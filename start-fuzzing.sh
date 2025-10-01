#!/bin/bash
# Start fuzzing with Docker Compose

set -e

echo "Starting OSS-Fuzz continuous fuzzing..."

# Check for .env file
if [ -f .env ]; then
    echo "Loading environment from .env file..."
    export $(grep -v '^#' .env | xargs)
fi

# Start services
if command -v docker-compose &> /dev/null; then
    docker-compose up -d
else
    docker compose up -d
fi

echo ""
echo "Fuzzing started successfully!"
echo ""
echo "View logs with: ./logs-fuzzing.sh"
echo "View stats with: ./stats-fuzzing.sh"
echo "Stop fuzzing with: ./stop-fuzzing.sh"
echo ""
