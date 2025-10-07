#!/usr/bin/env bash
set -euo pipefail

# Stream parser fuzz runner (no networking)
# - Target: harnesses.StreamParseFuzzer
# - Corpus: stream_corpus (create and drop a few seeds if you have them)
# - Artifacts: artifacts_stream (reproducers)

JAZZER="../jazzer/jazzer"
CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
TARGET="harnesses.StreamParseFuzzer"
CORPUS_DIR="stream_corpus"
ARTIFACTS="artifacts_stream"
LOG="stream_fuzz.log"

# Optional dictionary (reuses the HTML/XML/SVG tokens)
DICT_FILE="connect_html.dict"
DICT_ARG=()
if [[ -f "$DICT_FILE" ]]; then
  DICT_ARG=("-dict=$DICT_FILE")
fi

# Timings (env-overridable)
MAX_RUN_TIME=${MAX_RUN_TIME:-3600}   # seconds per run (default 1h)
SLEEP_BETWEEN=${SLEEP_BETWEEN:-5}    # seconds between runs

mkdir -p "$ARTIFACTS" "$CORPUS_DIR"

# Compile the fuzzer
javac -cp .:jsoup.jar harnesses/StreamParseFuzzer.java

echo "[run_stream] Starting Jazzer with target $TARGET and corpus $CORPUS_DIR (timeout ${MAX_RUN_TIME}s)" | tee -a "$LOG"
while true; do
  timeout --preserve-status "${MAX_RUN_TIME}s" \
    "$JAZZER" \
    --cp="$CP" \
    --target_class="$TARGET" \
    --reproducer_path="$ARTIFACTS" \
    "${DICT_ARG[@]}" \
    "$CORPUS_DIR" 2>&1 | tee -a "$LOG" || true

  echo "[run_stream] Run finished or timed out; sleeping ${SLEEP_BETWEEN}s" | tee -a "$LOG"
  sleep "$SLEEP_BETWEEN"
done

