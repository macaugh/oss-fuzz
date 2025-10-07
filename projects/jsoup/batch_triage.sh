#!/usr/bin/env bash
set -euo pipefail

FINDINGS_DIR="./findings"
RESULTS_DIR="$FINDINGS_DIR/results"
mkdir -p "$RESULTS_DIR"

echo "Starting batch triage over: $FINDINGS_DIR/*.clean.txt"
count_total=0
count_hits=0

for f in "$FINDINGS_DIR"/*.clean.txt; do
  [ -e "$f" ] || continue
  count_total=$((count_total+1))
  id=$(basename "$f" .clean.txt)
  out="$RESULTS_DIR/${id}.json"

  echo "----"
  echo "Testing: $f"
  # call node triage
  node test_finding.js "$f" "$out"

  if [ -f "$out" ]; then
    echo "=> HIT saved: $out"
    count_hits=$((count_hits+1))
  else
    echo "=> Not validated (no output JSON)"
  fi
done

echo "----"
echo "Batch done. Total tested: $count_total   Hits: $count_hits"
echo "Saved hits (if any) in: $RESULTS_DIR"
