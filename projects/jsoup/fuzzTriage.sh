#!/usr/bin/env bash
set -euo pipefail

# Configuration
HARNESS="CleanerWideNetRelativeLinksFuzzerNoCrash"
CORPUS_DIR="relative_corpus"
ARTIFACTS="./artifacts"
FINDINGS="./findings"
JSOUP_JAR="./jsoup.jar"

mkdir -p "$ARTIFACTS" "$FINDINGS"

while true; do
  echo "[*] Starting Jazzer fuzzing run..."
  ../jazzer/jazzer \
    --cp=.:"$JSOUP_JAR":../jazzer/jazzer_standalone.jar \
    --target_class=$HARNESS \
    --reproducer_path="$ARTIFACTS" \
    "$CORPUS_DIR" 2>&1 | tee fuzz_out.log

  # Process crashes
  for CRASH in "$ARTIFACTS"/Crash_*.java; do
    [ -e "$CRASH" ] || continue
    echo "[*] Found crash: $CRASH"

    # Extract base64
    B64=$(grep -oP 'Base64:\s*\K[^\s]+' "$CRASH" || true)
    if [ -z "$B64" ]; then
      echo "[!] No base64 found in $CRASH"
      continue
    fi

    ID=$(basename "$CRASH" .java)
    RAW_FILE="$FINDINGS/${ID}.raw"
    CLEAN_FILE="$FINDINGS/${ID}.clean.txt"
    DOM_FILE="$FINDINGS/${ID}.dom.txt"

    echo "$B64" | base64 -d > "$RAW_FILE" || continue

    # Run ShowClean and DomCheck
    java -cp .:"$JSOUP_JAR" ShowClean "$RAW_FILE" > "$CLEAN_FILE" 2>/dev/null || true
    java -cp .:"$JSOUP_JAR" DomCheck "$RAW_FILE" > "$DOM_FILE" 2>/dev/null || true

    # Quick heuristics
    if grep -qi "TAG:script" "$DOM_FILE"; then
      echo "[ALERT] Script survived — $ID"
    fi
    if grep -Eiq '\bon[a-z]+=' "$DOM_FILE"; then
      echo "[ALERT] Event handler survived — $ID"
    fi
    if grep -Eiq 'href.*javascript:' "$DOM_FILE"; then
      echo "[ALERT] Dangerous href survived — $ID"
    fi

    echo "[*] Saved triage: $RAW_FILE, $CLEAN_FILE, $DOM_FILE"
  done

  echo "[*] Restarting fuzzing loop in 5s..."
  sleep 5
done
