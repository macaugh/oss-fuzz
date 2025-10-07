#!/usr/bin/env bash
set -euo pipefail

# Runner for jsoup CSS selector fuzzer
# - Compiles: org.jsoup.fuzz.JsoupSelectorFuzzer
# - Uses corpus: ./selector_corpus (expects HTML + selector per file)
# - Uses dict: ./selector.dict (required)

JAZZER=${JAZZER:-"../jazzer/jazzer"}
CP_BASE=".:jsoup.jar:../jazzer/jazzer_standalone.jar:harnesses/src"
TARGET="org.jsoup.fuzz.JsoupSelectorFuzzer"
CORPUS_DIR="selector_corpus"
DICT_FILE="selector.dict"
ARTIFACTS=${ARTIFACTS:-"artifacts_selector"}
LOG=${LOG:-"selector_fuzz.log"}
DISABLED_HOOKS=${DISABLED_HOOKS:-"RegexInjection,Regex"}

# Timings (env-overridable)
MAX_RUN_TIME=${MAX_RUN_TIME:-3600}   # seconds per run (default 1h)
SLEEP_BETWEEN=${SLEEP_BETWEEN:-5}    # seconds between runs

echo "[run_selector] Preparing…"

# Checks
if [[ ! -x "$JAZZER" ]]; then
  echo "[run_selector] ERROR: Jazzer not found or not executable at: $JAZZER" >&2
  echo "[run_selector] Expecting a local checkout at ../jazzer with 'jazzer' and 'jazzer_standalone.jar'" >&2
  exit 1
fi
if [[ ! -f jsoup.jar ]]; then
  echo "[run_selector] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi

if [[ ! -f "$DICT_FILE" ]]; then
  echo "[run_selector] ERROR: dictionary not found: $DICT_FILE" >&2
  exit 1
fi

mkdir -p "$ARTIFACTS" "$CORPUS_DIR"

# Compile the fuzzer (classes output next to sources)
javac -cp .:jsoup.jar:../jazzer/jazzer_standalone.jar harnesses/src/org/jsoup/fuzz/JsoupSelectorFuzzer.java

echo "[run_selector] Using dictionary: $DICT_FILE"

echo "[run_selector] Starting Jazzer with target $TARGET and corpus $CORPUS_DIR (timeout ${MAX_RUN_TIME}s)" | tee -a "$LOG"
echo "[run_selector] Disabled hooks: $DISABLED_HOOKS" | tee -a "$LOG"
JVM_STACK_KB=${JVM_STACK_KB:-256}
PER_TEST_TIMEOUT_S=${PER_TEST_TIMEOUT_S:-3}
SKIP_REGEX=${SKIP_REGEX:-true}
echo "[run_selector] JVM thread stack size: ${JVM_STACK_KB}k; per-test timeout: ${PER_TEST_TIMEOUT_S}s" | tee -a "$LOG"
 
# Track crash artifacts to detect new crashes per run
count_crash_artifacts() {
  local c1 c2
  c1=$(find "$ARTIFACTS" -maxdepth 1 -type f -name 'Crash_*.java' | wc -l | tr -d ' ')
  c2=$(find "$ARTIFACTS" -maxdepth 1 -type f -name 'crash-*' | wc -l | tr -d ' ')
  echo $((c1 + c2))
}

prompt_continue_on_crash() {
  while true; do
    read -r -p "[run_selector] Crash detected. Start another run? [y/n] " ans
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

prev_crash_total=$(count_crash_artifacts)

while true; do
  timeout --preserve-status "${MAX_RUN_TIME}s" \
    "$JAZZER" \
    --cp="$CP_BASE" \
    --target_class="$TARGET" \
    --reproducer_path="$ARTIFACTS" \
    --disabled_hooks="$DISABLED_HOOKS" \
    -keep_going=1 \
    --jvm_args="-Xss${JVM_STACK_KB}k -Dselector.skip.regex=${SKIP_REGEX}" \
    -timeout=${PER_TEST_TIMEOUT_S} \
    -dict="$DICT_FILE" \
    "$CORPUS_DIR" 2>&1 | tee -a "$LOG" || true
  
  # Detect new crash artifacts from this run
  new_crash_total=$(count_crash_artifacts)
  if [[ "$new_crash_total" -gt "$prev_crash_total" ]]; then
    echo "[run_selector] Crash artifacts increased: $prev_crash_total -> $new_crash_total" | tee -a "$LOG"
    if prompt_continue_on_crash; then
      echo "[run_selector] Continuing after crash…" | tee -a "$LOG"
    else
      echo "[run_selector] Stopping on user request after crash." | tee -a "$LOG"
      exit 0
    fi
  else
    echo "[run_selector] Run finished or timed out; sleeping ${SLEEP_BETWEEN}s" | tee -a "$LOG"
    sleep "$SLEEP_BETWEEN"
  fi
  prev_crash_total="$new_crash_total"
done
