#!/bin/bash
# Stop all fuzzing containers

set -e

echo "Stopping fuzzing containers..."

if command -v docker-compose &> /dev/null; then
    docker-compose down
else
    docker compose down
fi

echo "All fuzzing containers stopped."
