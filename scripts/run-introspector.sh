#!/bin/bash
# Daily introspector runner with Discord notifications

set -u

PROJECT_NAME=${PROJECT_NAME:-jsoup}
REPORT_DIR=${REPORT_DIR:-/reports}
DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL:-}

# Create report directory
mkdir -p "$REPORT_DIR"

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Function to send Discord summary
send_discord_report() {
    local report_file=$1

    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        log "Discord webhook not configured, skipping notification"
        return
    fi

    # Extract key metrics from report
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Parse coverage data if available
    local coverage_summary="Report generated. Check $REPORT_DIR for details."

    if [ -f "$report_file" ]; then
        # Try to extract some basic stats
        coverage_summary=$(head -50 "$report_file" || echo "See full report")
    fi

    # Send to Discord
    local message=$(cat <<EOF
{
  "embeds": [{
    "title": "📊 Daily Introspector Report: $PROJECT_NAME",
    "color": 3447003,
    "fields": [
      {
        "name": "Project",
        "value": "\`$PROJECT_NAME\`",
        "inline": true
      },
      {
        "name": "Timestamp",
        "value": "$timestamp",
        "inline": true
      },
      {
        "name": "Report Location",
        "value": "\`$REPORT_DIR/introspector-report-$(date +%Y%m%d).txt\`",
        "inline": false
      },
      {
        "name": "Summary",
        "value": "\`\`\`\n${coverage_summary:0:500}\n\`\`\`",
        "inline": false
      }
    ],
    "footer": {
      "text": "OSS-Fuzz Introspector"
    }
  }]
}
EOF
)

    curl -H "Content-Type: application/json" \
         -d "$message" \
         "$DISCORD_WEBHOOK_URL" 2>&1 | grep -v "^$" || true
}

log "Starting introspector run for $PROJECT_NAME"

# Run introspector analysis
# Note: This requires the helper.py script from the OSS-Fuzz repo
REPORT_FILE="$REPORT_DIR/introspector-report-$(date +%Y%m%d).txt"

log "Running: python3 /src/oss-fuzz/infra/helper.py introspector $PROJECT_NAME"

# Run introspector (will take some time)
python3 /src/oss-fuzz/infra/helper.py introspector "$PROJECT_NAME" \
    2>&1 | tee "$REPORT_FILE"

EXIT_CODE=${PIPESTATUS[0]}

if [ $EXIT_CODE -eq 0 ]; then
    log "Introspector completed successfully"
    send_discord_report "$REPORT_FILE"
else
    log "Introspector failed with exit code: $EXIT_CODE"
    # Send error notification
    if [ -n "$DISCORD_WEBHOOK_URL" ]; then
        curl -H "Content-Type: application/json" \
             -d "{\"content\": \"⚠️ Introspector run failed for $PROJECT_NAME (exit code: $EXIT_CODE)\"}" \
             "$DISCORD_WEBHOOK_URL" 2>&1 | grep -v "^$" || true
    fi
fi

# Clean up old reports (keep last 30 days)
find "$REPORT_DIR" -name "introspector-report-*.txt" -mtime +30 -delete 2>/dev/null || true

log "Introspector run complete"
