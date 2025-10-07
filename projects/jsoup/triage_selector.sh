#!/usr/bin/env bash
set -euo pipefail

# Triage jsoup selector fuzzer artifacts by compiling + running Jazzer's Crash_*.java reproducers
# and capturing the decoded HTML, selector, and result summary from the harness.

JAZZER_CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar:harnesses/src"
OUT_DIR=${OUT_DIR:-"findings/selector"}
WORK_OUT="out/selector_triage"

usage() {
  echo "Usage: $0 [Crash_*.java ...]" >&2
  echo "If no args given, triages all Crash_*.java in artifacts_selector/." >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage; exit 0
fi

mkdir -p "$OUT_DIR" "$WORK_OUT"

# Ensure harness is compiled
javac -cp .:jsoup.jar:../jazzer/jazzer_standalone.jar harnesses/src/org/jsoup/fuzz/JsoupSelectorFuzzer.java

inputs=("$@")
if [[ ${#inputs[@]} -eq 0 ]]; then
  if compgen -G "artifacts_selector/Crash_*.java" > /dev/null; then
    mapfile -t inputs < <(ls artifacts_selector/Crash_*.java)
  else
    echo "[triage_selector] No inputs provided and no artifacts_selector/Crash_*.java found." >&2
    exit 1
  fi
fi

for f in "${inputs[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "[triage_selector] Skip missing: $f" >&2
    continue
  fi
  base=$(basename "$f")
  name="${base%.java}"
  echo "[triage_selector] Triage $base -> $OUT_DIR/$name.*"

  # Compile the Crash_*.java
  javac -d "$WORK_OUT" -cp "$JAZZER_CP" "$f"

  # Run it with triage flags so the harness writes decoded inputs + summary
  set +e
  java -cp "$JAZZER_CP:$WORK_OUT:$(dirname "$f")" \
    -Dselector.triage=true \
    -Dselector.triage.dir="$OUT_DIR" \
    -Dselector.triage.id="$name" \
    "$name" 2>&1 | tee "$OUT_DIR/$name.java.txt"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    echo "[triage_selector] Runner exited with status $status (this may be expected for real crashes)." >&2
  fi

  if [[ -f "$OUT_DIR/$name.result.txt" ]]; then
    echo "[triage_selector] Wrote: $OUT_DIR/$name.html.txt, $OUT_DIR/$name.selector.txt, $OUT_DIR/$name.result.txt"
  else
    # Fallback: parse exception from java stdout and emit a minimal result for labeling
    log_file="$OUT_DIR/$name.java.txt"
    if [[ -s "$log_file" ]]; then
      exc_line=$(grep -m1 -E '(^|\s)([A-Za-z0-9_.]+\.)+[A-Za-z0-9$]+(Exception|Error)(:|$)' "$log_file" || true)
      if [[ -n "$exc_line" ]]; then
        exc_class=$(echo "$exc_line" | awk '{print $1}')
        exc_msg=$(echo "$exc_line" | cut -d: -f2- | sed 's/^ //')
        status_line="error"
        # Labeling heuristics (align with jazzer triage)
        if echo "$exc_class" | grep -Eq 'Selector\$SelectorParseException$' || { echo "$exc_class" | grep -q 'IllegalArgumentException' && echo "$exc_msg" | grep -Eqi 'parse|selector|Could not parse'; }; then
          label="parse_error"
        elif echo "$exc_class" | grep -Eq 'FuzzerSecurityIssueLow' && echo "$exc_msg" | grep -Eqi 'Regular Expression Injection|Regex'; then
          label="regex_injection"
        elif echo "$exc_class" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
          label="resource_exhaustion"
        else
          label="engine_exception"
        fi
        {
          echo "status: $status_line"
          echo "exception: $exc_class"
          [[ -n "$exc_msg" ]] && echo "message: $exc_msg"
        } > "$OUT_DIR/$name.result.txt"
        echo "[triage_selector] $name -> status=$status_line label=$label (from logs)"
      else
        echo "[triage_selector] No triage output found for $name and no exception detected in logs." >&2
      fi
    else
      echo "[triage_selector] No triage output found for $name (empty logs)." >&2
    fi
  fi
done

# Build summary files from all results in OUT_DIR
summary_csv="$OUT_DIR/triage_summary.csv"
summary_ndjson="$OUT_DIR/triage_summary.ndjson"
echo "id,status,label,exception_class,exception_message,matches,html_len,selector_len,duration_ms" > "$summary_csv"
> "$summary_ndjson"

for res in "$OUT_DIR"/Crash_*.result.txt "$OUT_DIR"/Selector_*.result.txt; do
  [[ -f "$res" ]] || continue
  id=$(basename "$res")
  id=${id%.result.txt}

  status=$(sed -n 's/^status: //p' "$res" | head -n1)
  matches=$(sed -n 's/^matches: //p' "$res" | head -n1)
  exc=$(sed -n 's/^exception: //p' "$res" | head -n1)
  msg=$(sed -n 's/^message: //p' "$res" | head -n1)
  dur=$(sed -n 's/^duration_ms: //p' "$res" | head -n1)

  html_len=""; selector_len=""; jdur=""
  if [[ -f "$OUT_DIR/$id.html.txt" ]]; then html_len=$(wc -c < "$OUT_DIR/$id.html.txt" | tr -d ' '); fi
  if [[ -f "$OUT_DIR/$id.selector.txt" ]]; then selector_len=$(wc -c < "$OUT_DIR/$id.selector.txt" | tr -d ' '); fi
  if [[ -z "$dur" && -f "$OUT_DIR/$id.result.json" ]]; then
    # try to pull duration from json
    dur=$(grep -o '"duration_ms"\s*:\s*[0-9]\+' "$OUT_DIR/$id.result.json" | head -n1 | sed 's/[^0-9]//g') || true
  fi

  # labeling
  label="ok"
  if [[ "$status" == "error" ]]; then
    if echo "$exc" | grep -Eq 'Selector\$SelectorParseException$' || \
       { [[ "$exc" == "java.lang.IllegalArgumentException" ]] && echo "$msg" | grep -Eqi 'parse|selector|Could not parse'; }; then
      label="parse_error"
    elif echo "$exc" | grep -Eq 'FuzzerSecurityIssueLow' && echo "$msg" | grep -Eqi 'Regular Expression Injection|Regex'; then
      label="regex_injection"
    elif echo "$exc" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
      label="resource_exhaustion"
    else
      label="engine_exception"
    fi
  fi

  # CSV line (quote and escape message)
  esc_msg=${msg//"/""}
  echo "$id,$status,$label,$exc,\"$esc_msg\",${matches:-},${html_len:-},${selector_len:-},${dur:-}" >> "$summary_csv"

  # NDJSON line
  esc_json_msg=$(printf '%s' "$msg" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g')
  echo "{\"id\":\"$id\",\"status\":\"$status\",\"label\":\"$label\",\"exception_class\":\"$exc\",\"exception_message\":\"$esc_json_msg\",\"matches\":${matches:-0},\"html_len\":${html_len:-0},\"selector_len\":${selector_len:-0},\"duration_ms\":${dur:-0}}" >> "$summary_ndjson"
done

echo "[triage_selector] Summary written to: $summary_csv and $summary_ndjson"
