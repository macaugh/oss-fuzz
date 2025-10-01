#!/bin/bash
# Display fuzzing statistics

echo "========================================="
echo "Fuzzing Statistics"
echo "========================================="
echo ""

# Container status
echo "Container Status:"
if command -v docker-compose &> /dev/null; then
    docker-compose ps
else
    docker compose ps
fi

echo ""
echo "========================================="
echo "Corpus and Crash Statistics:"
echo "========================================="

for dir in fuzzing-data/*/; do
    if [ -d "$dir" ]; then
        fuzzer_name=$(basename "$dir")
        corpus_count=$(find "$dir/corpus" -type f 2>/dev/null | wc -l)
        crash_count=$(find "$dir/crashes" -type f 2>/dev/null | wc -l)
        corpus_size=$(du -sh "$dir/corpus" 2>/dev/null | cut -f1)

        echo ""
        echo "$fuzzer_name:"
        echo "  Corpus: $corpus_count files ($corpus_size)"
        echo "  Crashes: $crash_count"

        # Show recent log entries
        latest_log=$(ls -t "$dir/logs"/*.log 2>/dev/null | head -1)
        if [ -n "$latest_log" ]; then
            echo "  Last activity:"
            tail -3 "$latest_log" 2>/dev/null | sed 's/^/    /'
        fi
    fi
done

echo ""
echo "========================================="
echo ""
echo "View detailed logs: ./logs-fuzzing.sh <service-name>"
echo "Stop fuzzing: ./stop-fuzzing.sh"
echo ""
