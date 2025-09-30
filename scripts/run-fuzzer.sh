#!/bin/bash
# Continuous fuzzer runner with crash detection and corpus management

set -u

FUZZER_NAME=${FUZZER_NAME:-$1}
MAX_TIME_PER_RUN=${MAX_TIME_PER_RUN:-3600}
DATA_DIR="/fuzzing-data"
CORPUS_DIR="$DATA_DIR/corpus"
CRASHES_DIR="$DATA_DIR/crashes"
LOGS_DIR="$DATA_DIR/logs"

# Create directories
mkdir -p "$CORPUS_DIR" "$CRASHES_DIR" "$LOGS_DIR"

echo "========================================="
echo "Starting fuzzer: $FUZZER_NAME"
echo "Max time per run: ${MAX_TIME_PER_RUN}s"
echo "Data directory: $DATA_DIR"
echo "========================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Function to minimize corpus periodically
minimize_corpus() {
    local corpus_size_before=$(find "$CORPUS_DIR" -type f | wc -l)
    log "Minimizing corpus (current size: $corpus_size_before files)..."

    # Create temp directory for minimized corpus
    local temp_corpus="/tmp/corpus_minimized_$$"
    mkdir -p "$temp_corpus"

    # Run fuzzer with -merge flag to minimize corpus
    timeout 300 /out/$FUZZER_NAME -merge=1 "$temp_corpus" "$CORPUS_DIR" \
        2>&1 | grep -E "(MERGE|READ|RELOAD)" || true

    # Replace corpus if minimization succeeded
    if [ -d "$temp_corpus" ] && [ "$(ls -A $temp_corpus)" ]; then
        local corpus_size_after=$(find "$temp_corpus" -type f | wc -l)
        log "Corpus minimized: $corpus_size_before -> $corpus_size_after files"
        rm -rf "$CORPUS_DIR"
        mv "$temp_corpus" "$CORPUS_DIR"
    else
        log "Corpus minimization failed or no files produced"
        rm -rf "$temp_corpus"
    fi
}

# Counter for runs
RUN_COUNT=0

# Main fuzzing loop
while true; do
    RUN_COUNT=$((RUN_COUNT + 1))
    log "Starting fuzzing run #$RUN_COUNT"

    # Prepare arguments
    FUZZER_ARGS=(
        "-max_total_time=$MAX_TIME_PER_RUN"
        "-print_final_stats=1"
        "-print_corpus_stats=1"
        "-detect_leaks=0"
        "-rss_limit_mb=1536"
        "-timeout=25"
        "$CORPUS_DIR"
    )

    # Run fuzzer
    log "Executing: /out/$FUZZER_NAME ${FUZZER_ARGS[*]}"

    /out/$FUZZER_NAME "${FUZZER_ARGS[@]}" \
        2>&1 | tee -a "$LOGS_DIR/${FUZZER_NAME}_$(date +%Y%m%d).log" | \
        grep -E "(NEW|pulse|SUMMARY|crash|timeout)" || true

    EXIT_CODE=${PIPESTATUS[0]}
    log "Fuzzer exited with code: $EXIT_CODE"

    # Check for crashes (libFuzzer creates crash-* files in current dir)
    if ls crash-* oom-* timeout-* 2>/dev/null | head -1; then
        log "Crash artifacts found! Moving to $CRASHES_DIR"
        mv crash-* oom-* timeout-* "$CRASHES_DIR/" 2>/dev/null || true
    fi

    # Minimize corpus every 10 runs
    if [ $((RUN_COUNT % 10)) -eq 0 ]; then
        minimize_corpus
    fi

    # Get corpus stats
    CORPUS_SIZE=$(find "$CORPUS_DIR" -type f | wc -l)
    CRASH_COUNT=$(find "$CRASHES_DIR" -type f | wc -l)
    log "Stats: Corpus=$CORPUS_SIZE files, Crashes=$CRASH_COUNT"

    # Small delay between runs
    log "Waiting 10 seconds before next run..."
    sleep 10
done
