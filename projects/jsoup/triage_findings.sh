#!/usr/bin/env bash
set -euo pipefail

# Triage Crash_*.java and crash-* artifacts in ./findings
# - Extract raw payloads
# - Produce cleaned HTML (.clean.txt) and DOM dump (.dom.txt)
# - Run headless browser triage to detect executable effects

FINDINGS_DIR="./findings"
RESULTS_DIR="$FINDINGS_DIR/results"
ARTIFACTS_DIR="$FINDINGS_DIR" # inputs live here
JSOUP_JAR="./jsoup.jar"

compile_tools() {
  javac -cp .:"$JSOUP_JAR" ShowCleanOnly.java >/dev/null 2>&1 || true
  javac -cp .:"$JSOUP_JAR" harnesses/DomCheck.java >/dev/null 2>&1 || true
}

extract_b64_from_java() {
  # Echoes base64 string if found; empty otherwise
  local f="$1"
  # Pattern 1: explicit "Base64: <...>"
  local b64
  b64=$(grep -oP 'Base64:\s*\K[^\s]+' "$f" || true)
  if [ -n "${b64:-}" ]; then
    echo "$b64"
    return 0
  fi
  # Pattern 2: base64Bytes = String.join("", "<...>"); possibly across lines
  b64=$(node -e "const fs=require('fs');const s=fs.readFileSync(process.argv[1],'utf8');const m=s.match(/base64Bytes\\s*=\\s*String\\.join\\(\"\",\\s*\"([^\"]+)\"\\);/s); if(m) console.log(m[1]);" "$f" 2>/dev/null || true)
  echo "$b64"
}

process_java_crash() {
  local f="$1"
  local id
  id=$(basename "$f" .java)
  local raw="$FINDINGS_DIR/${id}.raw"
  local clean="$FINDINGS_DIR/${id}.clean.txt"
  local dom="$FINDINGS_DIR/${id}.dom.txt"

  local b64
  b64=$(extract_b64_from_java "$f")
  if [ -z "${b64:-}" ]; then
    echo "[triage] WARN: No base64 found in $f" >&2
    return 0
  fi
  echo "$b64" | base64 -d > "$raw" || { echo "[triage] ERROR: base64 decode failed for $f" >&2; return 0; }

  java -cp .:harnesses:"$JSOUP_JAR" ShowCleanOnly "$raw" > "$clean" 2>/dev/null || true
  java -cp .:harnesses:"$JSOUP_JAR" DomCheck "$raw" > "$dom" 2>/dev/null || true

  mkdir -p "$RESULTS_DIR"
  node test_finding.js "$clean" "$RESULTS_DIR/${id}.json" || true
}

process_raw_crash() {
  local f="$1"
  local base
  base=$(basename "$f")
  local id=${base}
  local raw="$FINDINGS_DIR/${id}.raw"
  local clean="$FINDINGS_DIR/${id}.clean.txt"
  local dom="$FINDINGS_DIR/${id}.dom.txt"

  # Ensure extension .raw copy for uniformity
  cp -f "$f" "$raw"

  java -cp .:harnesses:"$JSOUP_JAR" ShowCleanOnly "$raw" > "$clean" 2>/dev/null || true
  java -cp .:harnesses:"$JSOUP_JAR" DomCheck "$raw" > "$dom" 2>/dev/null || true

  mkdir -p "$RESULTS_DIR"
  node test_finding.js "$clean" "$RESULTS_DIR/${id}.json" || true
}

main() {
  mkdir -p "$RESULTS_DIR"
  compile_tools

  shopt -s nullglob
  local any=0
  for f in "$ARTIFACTS_DIR"/Crash_*.java; do
    [ -e "$f" ] || continue
    any=1
    echo "[triage] Processing Java crash: $(basename "$f")"
    process_java_crash "$f"
  done

  for f in "$ARTIFACTS_DIR"/crash-* "$ARTIFACTS_DIR"/timeout-*; do
    [ -e "$f" ] || continue
    any=1
    echo "[triage] Processing raw crash: $(basename "$f")"
    process_raw_crash "$f"
  done

  if [ "$any" -eq 0 ]; then
    echo "[triage] No crash artifacts found in $FINDINGS_DIR"
  else
    echo "[triage] Done. See cleaned HTML and DOM under $FINDINGS_DIR and results under $RESULTS_DIR"
  fi
}

main "$@"
