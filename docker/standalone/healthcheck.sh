#!/bin/sh
# Health check script for Authly standalone container

set -e

# Check PostgreSQL
pg_isready -h localhost -U authly -d authly -q || exit 1

# Check Redis
redis-cli -h localhost ping > /dev/null 2>&1 || exit 1

# Check Authly API
curl -f http://localhost:8000/health > /dev/null 2>&1 || exit 1

echo "All services healthy"
exit 0