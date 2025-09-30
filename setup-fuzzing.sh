#!/bin/bash
# Setup script for OSS-Fuzz continuous fuzzing on VPS

set -e

echo "========================================="
echo "OSS-Fuzz Docker Compose Setup"
echo "========================================="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Error: Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Discord webhook is configured
if [ -z "${DISCORD_WEBHOOK_URL:-}" ]; then
    echo ""
    echo "Warning: DISCORD_WEBHOOK_URL environment variable is not set."
    echo "To enable Discord notifications, create a .env file with:"
    echo "  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
    echo ""
    read -p "Continue without Discord notifications? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build the jsoup fuzzer image
echo ""
echo "Step 1: Building jsoup fuzzer image..."
echo "This may take 10-15 minutes on first run..."
python3 infra/helper.py build_image jsoup

echo ""
echo "Step 2: Building fuzzers..."
python3 infra/helper.py build_fuzzers jsoup

echo ""
echo "Step 3: Checking build..."
python3 infra/helper.py check_build jsoup

echo ""
echo "Step 4: Setting up directories..."
mkdir -p fuzzing-data/{jsoup-1,jsoup-2,jsoup-3}/{corpus,crashes,logs}

# Find available fuzzers
echo ""
echo "Step 5: Detecting available fuzzers..."
FUZZERS=$(docker run --rm gcr.io/oss-fuzz/jsoup ls /out/ | grep -v "\.jar$" | grep -v "\.zip$" | grep -v "\.dict$" | grep -v "\.options$" || true)
echo "Available fuzzers:"
echo "$FUZZERS" | head -10

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Edit docker-compose.yml to configure which fuzzers to run"
echo "2. Set DISCORD_WEBHOOK_URL in .env file (optional)"
echo "3. Start fuzzing with: ./start-fuzzing.sh"
echo ""
echo "Available commands:"
echo "  ./start-fuzzing.sh     - Start all fuzzers"
echo "  ./stop-fuzzing.sh      - Stop all fuzzers"
echo "  ./logs-fuzzing.sh      - View logs"
echo "  ./stats-fuzzing.sh     - View statistics"
echo ""
