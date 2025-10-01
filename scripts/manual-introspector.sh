#!/bin/bash
# Manual introspector runner - generates coverage report on demand

set -e

PROJECT=${1:-jsoup}
OUTPUT_DIR="introspector-reports"

echo "Running introspector analysis for $PROJECT..."
echo "This will take 10-30 minutes depending on project size."
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run introspector with all corpora
python3 infra/helper.py introspector "$PROJECT"

# The introspector output is typically in build/out/<project>/introspector-report/
REPORT_DIR="build/out/$PROJECT/introspector-report"

if [ -d "$REPORT_DIR" ]; then
    # Copy to output directory with timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DEST="$OUTPUT_DIR/report-$TIMESTAMP"

    cp -r "$REPORT_DIR" "$DEST"

    echo ""
    echo "========================================="
    echo "Introspector report generated!"
    echo "========================================="
    echo "Location: $DEST"
    echo ""

    # Look for HTML report
    if [ -f "$DEST/fuzz_report.html" ]; then
        echo "View HTML report: file://$(pwd)/$DEST/fuzz_report.html"
    fi

    # Display summary if available
    if [ -f "$DEST/summary.txt" ]; then
        echo ""
        echo "Summary:"
        cat "$DEST/summary.txt"
    fi
else
    echo "Error: Introspector report not found at $REPORT_DIR"
    exit 1
fi
