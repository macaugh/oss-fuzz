#!/usr/bin/env bash
set -euo pipefail

# triage_min.sh - minimal triage helper
# Usage:
#   ./triage_min.sh "<BASE64_STRING>"
#   ./triage_min.sh -f /path/to/file.b64

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 \"<base64>\"  OR  $0 -f file.b64"
  exit 1
fi

TMP="/tmp/payload_triage_$$"
RAW="$TMP/payload.raw"
B64="$TMP/payload.b64"
mkdir -p "$TMP"

if [ "$1" = "-f" ]; then
  if [ -z "${2:-}" ]; then echo "Missing file"; exit 1; fi
  cp "$2" "$B64"
else
  printf '%s' "$1" > "$B64"
fi

# decode
if ! command -v base64 >/dev/null 2>&1; then
  echo "base64 command not found"
  exit 1
fi
base64 -d "$B64" > "$RAW" || { echo "base64 decode failed"; exit 1; }

echo "Decoded -> $RAW"
echo
echo "=== TEXT PREVIEW (first 300 chars) ==="
head -c 300 "$RAW" | sed -n '1,200p' || true
echo
echo
echo "=== HEX PREVIEW (first 96 bytes) ==="
xxd -g1 -l96 "$RAW" || true
echo
echo "----------------------------------------"
echo

# Run your existing tools
if [ -f "./ShowClean.class" ] || [ -d "./classes" ]; then
  echo "Running ShowClean..."
  java -cp .:jsoup.jar ShowClean "$RAW" || true
else
  echo "ShowClean.class not found in current dir - skipping ShowClean"
fi

echo
if [ -f "./DomCheck.class" ] || [ -d "./classes" ]; then
  echo "Running DomCheck..."
  java -cp .:jsoup.jar DomCheck "$RAW" || true
else
  echo "DomCheck.class not found in current dir - skipping DomCheck"
fi

echo
echo "Done. Temp files under $TMP (preserved). Remove them when finished."
