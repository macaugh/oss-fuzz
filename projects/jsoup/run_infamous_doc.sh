#!/usr/bin/env bash
set -euo pipefail

# Compile and run the infamousfuzz/DocumentManipulationFuzzer with Jazzer.
#
# Env vars (override as needed):
#   JAZZER             Path to jazzer binary (default ../jazzer/jazzer)
#   JVM_STACK_KB       Thread stack size in KB (default 256)
#   MAX_RUN_TIME       Seconds per fuzz run (default 1800)
#   PER_TEST_TIMEOUT_S Per-input timeout in seconds (default 3)
#   DISABLED_HOOKS     Jazzer sanitizer hooks to disable (default RegexInjection,Regex)
#   ARTIFACTS          Output directory for reproducers (default artifacts_infamous)
#   CORPUS_DIR         Corpus directory (default infamous_corpus)
#   LOG                Log file (default infamous_fuzz.log)

JAZZER=${JAZZER:-"../jazzer/jazzer"}
CP_BASE=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
SRC_DIR="infamousfuzz"
SRC_FILE="$SRC_DIR/DocumentManipulationFuzzer.java"
ARTIFACTS=${ARTIFACTS:-"artifacts_infamous"}
CORPUS_DIR=${CORPUS_DIR:-"infamous_corpus"}
LOG=${LOG:-"infamous_fuzz.log"}
DISABLED_HOOKS=${DISABLED_HOOKS:-"RegexInjection,Regex"}
CLASS_OUT=${CLASS_OUT:-"out/infamous_doc"}

# Timings / JVM
MAX_RUN_TIME=${MAX_RUN_TIME:-86400}
PER_TEST_TIMEOUT_S=${PER_TEST_TIMEOUT_S:-3}
JVM_STACK_KB=${JVM_STACK_KB:-256}

echo "[run_infamous_doc] Preparing…"

# Checks
if [[ ! -x "$JAZZER" ]]; then
  echo "[run_infamous_doc] ERROR: Jazzer not found at $JAZZER" >&2
  echo "[run_infamous_doc] Expect a local checkout at ../jazzer with 'jazzer' and 'jazzer_standalone.jar'" >&2
  exit 1
fi
if [[ ! -f jsoup.jar ]]; then
  echo "[run_infamous_doc] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi
if [[ ! -f "$SRC_FILE" ]]; then
  echo "[run_infamous_doc] ERROR: Source not found: $SRC_FILE" >&2
  exit 1
fi

mkdir -p "$ARTIFACTS" "$CORPUS_DIR" "$CLASS_OUT"

# Optional dictionary
DICT_FILE=${DICT_FILE:-"infamous_html.dict"}
DICT_ARG=()
if [[ -f "$DICT_FILE" ]]; then
  DICT_ARG=("-dict=$DICT_FILE")
  echo "[run_infamous_doc] Using dictionary: $DICT_FILE"
fi

# Detect package and target class
CLASS_NAME=$(basename "$SRC_FILE" .java)
PKG=$(sed -n 's/^package\s\+\([^;][^;]*\);.*/\1/p' "$SRC_FILE" | head -n1 | tr -d '\r' | tr -d '\n' | sed 's/[[:space:]]//g')
if [[ -z "${TARGET:-}" ]]; then
  if [[ -n "$PKG" ]]; then
    TARGET="$PKG.$CLASS_NAME"
  else
    TARGET="$CLASS_NAME"
  fi
fi

# Compile the fuzzer into CLASS_OUT to match package structure
javac -d "$CLASS_OUT" -cp .:jsoup.jar:../jazzer/jazzer_standalone.jar "$SRC_FILE"

echo "[run_infamous_doc] Target: $TARGET"
echo "[run_infamous_doc] Disabled hooks: $DISABLED_HOOKS"
echo "[run_infamous_doc] JVM thread stack size: ${JVM_STACK_KB}k; per-test timeout: ${PER_TEST_TIMEOUT_S}s"
echo "[run_infamous_doc] Starting Jazzer (max ${MAX_RUN_TIME}s)" | tee -a "$LOG"

# One bounded fuzz run; re-run manually if desired.
timeout --preserve-status "${MAX_RUN_TIME}s" \
  "$JAZZER" \
  --cp="$CP_BASE:$CLASS_OUT" \
  --target_class="$TARGET" \
  --reproducer_path="$ARTIFACTS" \
  --disabled_hooks="$DISABLED_HOOKS" \
  -keep_going=1 \
  --jvm_args="-Xss${JVM_STACK_KB}k" \
  -timeout=${PER_TEST_TIMEOUT_S} \
  "${DICT_ARG[@]}" \
  "$CORPUS_DIR" 2>&1 | tee -a "$LOG" || true

echo "[run_infamous_doc] Done. Artifacts (if any): $ARTIFACTS"
