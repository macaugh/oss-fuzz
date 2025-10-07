#!/usr/bin/env bash
set -euo pipefail

# Compile and run a single Crash_*.java reproducer for DocumentManipulationFuzzer
# Usage: ./run_infamous_repro.sh artifacts_infamous/Crash_xxx.java

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path/to/Crash_*.java>" >&2
  exit 2
fi

CRASH_FILE="$1"
if [[ ! -f "$CRASH_FILE" ]]; then
  echo "[run_infamous_repro] Missing crash file: $CRASH_FILE" >&2
  exit 1
fi

if [[ ! -f jsoup.jar ]]; then
  echo "[run_infamous_repro] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi

CP_BASE=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
OUT_DIR=${OUT_DIR:-"out/infamous_repro"}

mkdir -p "$OUT_DIR"

# Try to find the fuzzer source for compilation
FUZZ_SRC=""
for cand in \
  infamousfuzz/DocumentManipulationFuzzer.java \
  DocumentManipulationFuzzer.java; do
  if [[ -f "$cand" ]]; then FUZZ_SRC="$cand"; break; fi
done

if [[ -n "$FUZZ_SRC" ]]; then
  echo "[run_infamous_repro] Compiling fuzzer: $FUZZ_SRC"
  javac -d "$OUT_DIR" -cp "$CP_BASE" "$FUZZ_SRC"
else
  echo "[run_infamous_repro] WARN: Fuzzer source not found; assuming class is available or not needed." >&2
fi

BASE=$(basename "$CRASH_FILE")
MAIN_CLASS="${BASE%.java}"

echo "[run_infamous_repro] Compiling reproducer: $BASE"
javac -d "$OUT_DIR" -cp "$CP_BASE:$OUT_DIR" "$CRASH_FILE"

echo "[run_infamous_repro] Running: $MAIN_CLASS"
set +e
java -cp "$CP_BASE:$OUT_DIR:$(dirname "$CRASH_FILE")" "$MAIN_CLASS"
status=$?
set -e

echo "[run_infamous_repro] Exit status: $status"
exit $status

