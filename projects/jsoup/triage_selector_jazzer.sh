#!/usr/bin/env bash
set -euo pipefail

# Use Jazzer to reproduce selector crashes from raw crash-* inputs and capture full logs.

JAZZER=${JAZZER:-"../jazzer/jazzer"}
CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar:harnesses/src"
TARGET="org.jsoup.fuzz.JsoupSelectorFuzzer"
OUT_DIR=${OUT_DIR:-"findings/selector"}
LOG_DIR="$OUT_DIR/logs"
WORK_OUT=${WORK_OUT:-"out/selector_triage"}
DISABLED_HOOKS=${DISABLED_HOOKS:-"RegexInjection,Regex"}
SKIP_REGEX=${SKIP_REGEX:-true}

usage() {
  echo "Usage: $0 [crash-* timeout-* ...]" >&2
  echo "If no args, tries artifacts_selector/crash-* and timeout-*" >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage; exit 0
fi

if [[ ! -x "$JAZZER" ]]; then
  echo "[triage_jazzer] ERROR: Jazzer not found at $JAZZER" >&2
  exit 1
fi
if [[ ! -f jsoup.jar ]]; then
  echo "[triage_jazzer] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi

mkdir -p "$OUT_DIR" "$LOG_DIR" "$WORK_OUT"

# Ensure fuzzer class is compiled for the JVM/Jazzer
javac -cp .:jsoup.jar:../jazzer/jazzer_standalone.jar harnesses/src/org/jsoup/fuzz/JsoupSelectorFuzzer.java

inputs=("$@")
if [[ ${#inputs[@]} -eq 0 ]]; then
  shopt -s nullglob
  inputs=(artifacts_selector/Crash_*.java artifacts_selector/crash-* artifacts_selector/timeout-*)
  shopt -u nullglob
fi

if [[ ${#inputs[@]} -eq 0 ]]; then
  echo "[triage_jazzer] No crash inputs found." >&2
  exit 1
fi

summary_lines=()

process_java() {
  local f="$1"
  local base id
  base=$(basename "$f")
  id="${base%.java}"
  echo "[triage_jazzer] (java) Reproducing: $base"
  # Compile and run Crash_*.java
  javac -d "$WORK_OUT" -cp "$CP" "$f"
  set +e
  java -cp "$CP:$WORK_OUT:$(dirname "$f")" \
    -Dselector.triage=true \
    -Dselector.triage.dir="$OUT_DIR" \
    -Dselector.triage.id="$id" \
    "$id" 2>&1 | tee "$LOG_DIR/$id.java.txt"
  local status=$?
  set -e
    if [[ -f "$OUT_DIR/$id.result.txt" ]]; then
      local status_line label exc msg matches
      status_line=$(sed -n 's/^status: //p' "$OUT_DIR/$id.result.txt" | head -n1)
      matches=$(sed -n 's/^matches: //p' "$OUT_DIR/$id.result.txt" | head -n1)
      exc=$(sed -n 's/^exception: //p' "$OUT_DIR/$id.result.txt" | head -n1)
      msg=$(sed -n 's/^message: //p' "$OUT_DIR/$id.result.txt" | head -n1)
      label="ok"
      if [[ "$status_line" == "error" ]]; then
        if echo "$exc" | grep -Eq 'Selector\$SelectorParseException$' || { [[ "$exc" == "java.lang.IllegalArgumentException" ]] && echo "$msg" | grep -Eqi 'parse|selector|Could not parse'; }; then
          label="parse_error"
        elif echo "$exc" | grep -Eq 'FuzzerSecurityIssueLow' && echo "$msg" | grep -Eqi 'Regular Expression Injection|Regex'; then
          label="regex_injection"
        elif echo "$exc" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
          label="resource_exhaustion"
        else
          label="engine_exception"
        fi
      fi
      echo "[triage_jazzer] $id -> status=$status_line label=$label matches=${matches:-} exc=${exc:-}"
      summary_lines+=("$id,$status_line,$label,${exc:-},${matches:-}")
  else
    echo "[triage_jazzer] $id -> no triage files; see $LOG_DIR/$id.java.txt"
    summary_lines+=("$id,unknown,no_output,,")
  fi
}

process_raw() {
  local f="$1"
  local base id
  base=$(basename "$f")
  id="$base"
  echo "[triage_jazzer] (jazzer) Reproducing: $base"
  local tmpdir
  tmpdir=$(mktemp -d)
  cp "$f" "$tmpdir/input"
  set +e
  timeout --preserve-status 60s \
    "$JAZZER" \
    --cp="$CP" \
    --target_class="$TARGET" \
    --reproducer_path="$OUT_DIR" \
    --keep_going=0 \
    --print_final_stats=1 \
    --use_value_profile=1 \
    -runs=1 \
    -dict=selector.dict \
    ${DISABLED_HOOKS:+--disabled_hooks=$DISABLED_HOOKS} \
    --jvm_args="-Dselector.triage=true -Dselector.triage.dir=$OUT_DIR -Dselector.triage.id=$id -Dselector.skip.regex=$SKIP_REGEX" \
    "$tmpdir" 2>&1 | tee "$LOG_DIR/$id.jazzer.txt"
  local status=$?
  set -e
  if [[ -f "$OUT_DIR/$id.result.txt" ]]; then
    local status_line label exc msg matches
    status_line=$(sed -n 's/^status: //p' "$OUT_DIR/$id.result.txt" | head -n1)
    matches=$(sed -n 's/^matches: //p' "$OUT_DIR/$id.result.txt" | head -n1)
    exc=$(sed -n 's/^exception: //p' "$OUT_DIR/$id.result.txt" | head -n1)
    msg=$(sed -n 's/^message: //p' "$OUT_DIR/$id.result.txt" | head -n1)
    label="ok"
    if [[ "$status_line" == "error" ]]; then
      if echo "$exc" | grep -Eq 'Selector\$SelectorParseException$' || { [[ "$exc" == "java.lang.IllegalArgumentException" ]] && echo "$msg" | grep -Eqi 'parse|selector|Could not parse'; }; then
        label="parse_error"
      elif echo "$exc" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
        label="resource_exhaustion"
      else
        label="engine_exception"
      fi
    fi
    echo "[triage_jazzer] $id -> status=$status_line label=$label matches=${matches:-} exc=${exc:-}"
    summary_lines+=("$id,$status_line,$label,${exc:-},${matches:-}")
  else
    # Fallback parsing from jazzer log
    local exc_line exc_class exc_msg label status_line
    exc_line=$(grep -m1 -E '(^|\s)([A-Za-z0-9_.]+\.)+[A-Za-z0-9$]+(Exception|Error)(:|$)' "$LOG_DIR/$id.jazzer.txt" || true)
    if [[ -n "$exc_line" ]]; then
      exc_class=$(echo "$exc_line" | awk '{print $1}')
      exc_msg=$(echo "$exc_line" | cut -d: -f2- | sed 's/^ //')
      status_line="error"
      if echo "$exc_class" | grep -Eq 'Selector\$SelectorParseException$' || { echo "$exc_class" | grep -q 'IllegalArgumentException' && echo "$exc_msg" | grep -Eqi 'parse|selector|Could not parse'; }; then
        label="parse_error"
      elif echo "$exc_class" | grep -Eq 'FuzzerSecurityIssueLow' && echo "$exc_msg" | grep -Eqi 'Regular Expression Injection|Regex'; then
        label="regex_injection"
      elif echo "$exc_class" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
        label="resource_exhaustion"
      else
        label="engine_exception"
      fi
      echo -e "status: $status_line\nexception: $exc_class\nmessage: $exc_msg" > "$OUT_DIR/$id.result.txt"
      echo "[triage_jazzer] $id -> status=$status_line label=$label (from logs)"
      summary_lines+=("$id,$status_line,$label,$exc_class,")
    else
      echo "[triage_jazzer] $id -> no triage files; see $LOG_DIR/$id.jazzer.txt"
      summary_lines+=("$id,unknown,no_output,,")
    fi
  fi
  rm -rf "$tmpdir"
}

for f in "${inputs[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "[triage_jazzer] Skip missing: $f" >&2
    continue
  fi
  case "$f" in
    *.java) process_java "$f" ;;
    *) process_raw "$f" ;;
  esac
done

echo "[triage_jazzer] Logs in $LOG_DIR; triage outputs in $OUT_DIR"

# Write quick summary
summary_csv="$OUT_DIR/triage_quick_summary.csv"
echo "id,status,label,exception,matches" > "$summary_csv"
for line in "${summary_lines[@]}"; do echo "$line" >> "$summary_csv"; done
echo "[triage_jazzer] Quick summary: $summary_csv"
