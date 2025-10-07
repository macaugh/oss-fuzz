#!/usr/bin/env bash
# run_forever_limited.sh
set -euo pipefail

echo "[run.sh] Starting fuzz loop..."

JAZZER="../jazzer/jazzer"
JAR_CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
# Target the GHSA regression fuzzer with crafted Unicode/encoded corpus
TARGET="CleanerGhsaGp7fRwcx9369Fuzzer"
REPRO_PATH="./artifacts"
CORPUS="ghsa_corpus"
FINDINGS="./findings"
LOG="jazzer_loop.log"
DICT_ARG="" # set to "-dict=relative_links.dict" if you have a dictionary

# how long to run each Jazzer invocation (seconds). Keep runs finite to limit runaway artifacts.
MAX_RUN_TIME=$((60*60))   # 1 hour runs
SLEEP_BETWEEN=5           # seconds to sleep between restarts

mkdir -p "$REPRO_PATH"
mkdir -p "$CORPUS"
mkdir -p "$FINDINGS"

# Basic sanity checks
if [ ! -x "$JAZZER" ]; then
  echo "[run.sh] ERROR: Jazzer not found or not executable at: $JAZZER" >&2
  echo "[run.sh] Expecting a local checkout at ../jazzer with 'jazzer' and 'jazzer_standalone.jar'" >&2
  exit 1
fi

if [ ! -f jsoup.jar ]; then
  echo "[run.sh] ERROR: jsoup.jar missing in repo root." >&2
  exit 1
fi

while true; do
  echo "$(date -Iseconds) Starting jazzer run (max ${MAX_RUN_TIME}s) target=$TARGET corpus=$CORPUS" | tee -a "$LOG"
  # run jazzer for a bounded time then kill if it exceeds
  timeout --preserve-status "${MAX_RUN_TIME}s" \
    "$JAZZER" --cp="$JAR_CP" --target_class="$TARGET" --reproducer_path="$REPRO_PATH" $DICT_ARG "$CORPUS" 2>&1 | tee -a "$LOG" || true

  # Move any crash artifacts into findings for later triage
  for f in "$REPRO_PATH"/Crash_*.java Crash_*.java "$REPRO_PATH"/crash-* crash-* "$REPRO_PATH"/timeout-* timeout-*; do
    [ -e "$f" ] || continue
    echo "[run.sh] Moving artifact $(basename "$f") -> $FINDINGS/" | tee -a "$LOG"
    mv -f "$f" "$FINDINGS"/
  done

  echo "$(date -Iseconds) Jazzer finished or timed out; sleeping ${SLEEP_BETWEEN}s" | tee -a "$LOG"
  sleep "$SLEEP_BETWEEN"
done
