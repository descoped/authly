#!/bin/bash
set -e

echo "🔄 Starting compliance tester..."

# Ensure data directory exists
mkdir -p /usr/share/nginx/html/data
chmod 755 /usr/share/nginx/html/data

# Run bootstrap in background with timeout
timeout 30 /bootstrap.sh &
BOOTSTRAP_PID=$!

# Wait for bootstrap or timeout
wait $BOOTSTRAP_PID 2>/dev/null || true

# Start nginx regardless
echo "🚀 Starting nginx..."
exec nginx -g "daemon off;"