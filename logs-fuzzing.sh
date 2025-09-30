#!/bin/bash
# View fuzzing logs

SERVICE=${1:-}

if [ -z "$SERVICE" ]; then
    echo "Available services:"
    if command -v docker-compose &> /dev/null; then
        docker-compose ps --services
    else
        docker compose ps --services
    fi
    echo ""
    echo "Usage: $0 <service-name>"
    echo "Example: $0 fuzzer-jsoup-1"
    echo ""
    echo "Or follow all logs:"
    if command -v docker-compose &> /dev/null; then
        docker-compose logs -f
    else
        docker compose logs -f
    fi
else
    if command -v docker-compose &> /dev/null; then
        docker-compose logs -f "$SERVICE"
    else
        docker compose logs -f "$SERVICE"
    fi
fi
