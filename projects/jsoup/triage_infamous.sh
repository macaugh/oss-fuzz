#!/usr/bin/env bash
set -euo pipefail

# Triage infamousfuzz DocumentManipulationFuzzer crash reproducers (Crash_*.java)

JAZZER_CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
OUT_DIR=${OUT_DIR:-"findings/infamous"}
WORK_OUT=${WORK_OUT:-"out/infamous_triage"}

SRC_CANDIDATES=(
  "infamousfuzz/DocumentManipulationFuzzer.java"
  "DocumentManipulationFuzzer.java"
)

usage() {
  echo "Usage: $0 [Crash_*.java ...]" >&2
  echo "If no args, triages all artifacts_infamous/Crash_*.java" >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage; exit 0
fi

if [[ ! -f jsoup.jar ]]; then
  echo "[triage_infamous] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi

mkdir -p "$OUT_DIR" "$WORK_OUT"

# Locate and compile the fuzzer source if present (not strictly required if class already compiled)
FUZZ_SRC=""
for c in "${SRC_CANDIDATES[@]}"; do
  if [[ -f "$c" ]]; then FUZZ_SRC="$c"; break; fi
done

TARGET_CLASS="DocumentManipulationFuzzer"
if [[ -n "$FUZZ_SRC" ]]; then
  # Extract package (if any) to determine target FQCN and compile destination
  PKG=$(sed -n 's/^package\s\+\([^;][^;]*\);.*/\1/p' "$FUZZ_SRC" | head -n1 | tr -d '\r' | tr -d '\n' | sed 's/[[:space:]]//g')
  if [[ -n "$PKG" ]]; then TARGET_CLASS="$PKG.$TARGET_CLASS"; fi
  echo "[triage_infamous] Compiling fuzzer: $FUZZ_SRC (target $TARGET_CLASS)"
  javac -d "$WORK_OUT" -cp "$JAZZER_CP" "$FUZZ_SRC"
else
  echo "[triage_infamous] WARN: Could not find fuzzer source, assuming class is already on classpath: $TARGET_CLASS" >&2
fi

inputs=("$@")
if [[ ${#inputs[@]} -eq 0 ]]; then
  shopt -s nullglob
  inputs=(artifacts_infamous/Crash_*.java)
  shopt -u nullglob
fi

if [[ ${#inputs[@]} -eq 0 ]]; then
  echo "[triage_infamous] No Crash_*.java inputs found." >&2
  exit 1
fi

summary_lines=()

for f in "${inputs[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "[triage_infamous] Skip missing: $f" >&2
    continue
  fi
  base=$(basename "$f")
  name="${base%.java}"
  echo "[triage_infamous] Triage $base -> $OUT_DIR/$name.*"

  # Compile the Crash_*.java
  javac -d "$WORK_OUT" -cp "$JAZZER_CP:$WORK_OUT" "$f"

  # Run it
  set +e
  java -cp "$JAZZER_CP:$WORK_OUT:$(dirname "$f")" "$name" 2>&1 | tee "$OUT_DIR/$name.java.txt"
  status=$?
  set -e

  # Parse output for exception summary
  exc_line=$(grep -m1 -E '(^|\s)([A-Za-z0-9_.]+\.)+[A-Za-z0-9$]+(Exception|Error)(:|$)' "$OUT_DIR/$name.java.txt" || true)
  if [[ -n "$exc_line" ]]; then
    exc_class=$(echo "$exc_line" | awk '{print $1}')
    exc_msg=$(echo "$exc_line" | cut -d: -f2- | sed 's/^ //')
    status_line="error"
  else
    exc_class=""
    exc_msg=""
    status_line=$([[ $status -eq 0 ]] && echo ok || echo error)
  fi

  # Write a minimal result.txt to harmonize with other triage flows
  {
    echo "status: $status_line"
    [[ -n "$exc_class" ]] && echo "exception: $exc_class"
    [[ -n "$exc_msg" ]] && echo "message: $exc_msg"
  } > "$OUT_DIR/$name.result.txt"

  # Label
  label="ok"
  if [[ "$status_line" == "error" ]]; then
    if echo "$exc_class" | grep -Eq 'OutOfMemoryError|StackOverflowError|Timeout'; then
      label="resource_exhaustion"
    elif echo "$exc_class" | grep -Eq 'FuzzerSecurityIssueLow' && echo "$exc_msg" | grep -Eqi 'Regular Expression Injection|Regex'; then
      label="regex_injection"
    elif echo "$exc_class" | grep -q 'IllegalArgumentException'; then
      label="illegal_argument"
    else
      label="exception"
    fi
  fi
  echo "[triage_infamous] $name -> status=$status_line label=$label exc=${exc_class:-}"
  summary_lines+=("$name,$status_line,$label,${exc_class:-}")
done

# Summary CSV
summary_csv="$OUT_DIR/triage_quick_summary.csv"
echo "id,status,label,exception" > "$summary_csv"
for line in "${summary_lines[@]}"; do echo "$line" >> "$summary_csv"; done
echo "[triage_infamous] Summary: $summary_csv"

