#!/bin/bash

PORT=${1:-8080}

echo "SIMPLE MONITORING SERVER TESTS"
echo "==============================="
echo "Port: $PORT"

# Check if server is running
if ! nc -z 127.0.0.1 $PORT 2>/dev/null; then
    echo "ERROR: Server not running on port $PORT"
    echo "Start server with: ./socks5v -L 127.0.0.1 -P $PORT -u admin:admin"
    exit 1
fi

echo "Server detected on port $PORT"
echo ""

echo ""
echo "1. Fragmented test..."
python3 monitoring_fragmented.py $PORT

echo ""
echo "2. Combined messages test..."
python3 monitoring_combined.py $PORT

echo ""
echo "Tests completed"
