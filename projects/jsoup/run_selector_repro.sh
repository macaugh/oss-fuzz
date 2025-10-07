#!/usr/bin/env bash
set -euo pipefail

# Reproduce a selector run with given HTML and selector files.
# Usage: ./run_selector_repro.sh selector_corpus/seed1.txt <optional-id>
#        or: ./run_selector_repro.sh <html_file> <selector_file> <optional-id>

OUT_DIR=${OUT_DIR:-"findings/selector"}

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <html_file> <selector_file> [ID]" >&2
  echo "   or: $0 selector_corpus/<seed>.txt [ID] (two-line file: html then selector)" >&2
  exit 2
fi

html_file=""
selector_file=""
id="${3:-}"

if [[ $# -ge 2 ]]; then
  html_file="$1"
  selector_file="$2"
  id="${3:-}"
else
  # one file mode: split into temp files
  in_file="$1"
  if [[ ! -f "$in_file" ]]; then echo "[repro] Missing file: $in_file" >&2; exit 1; fi
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  # First line(s) until last line: HTML; last line: selector
  # We assume the last line is selector, rest is HTML
  total=$(wc -l < "$in_file" | tr -d ' ')
  if [[ "$total" -lt 2 ]]; then echo "[repro] Need at least 2 lines in single-file mode" >&2; exit 2; fi
  head -n $((total-1)) "$in_file" > "$tmpdir/html.txt"
  tail -n 1 "$in_file" > "$tmpdir/selector.txt"
  html_file="$tmpdir/html.txt"
  selector_file="$tmpdir/selector.txt"
fi

mkdir -p "$OUT_DIR"

# Compile
javac -cp .:jsoup.jar harnesses/RunSelectorRepro.java

# Run
java -cp .:jsoup.jar harnesses.RunSelectorRepro "$html_file" "$selector_file" "${id:-}"

echo "[repro] Outputs (if any): $OUT_DIR/*.{html.txt,selector.txt,result.txt}"

