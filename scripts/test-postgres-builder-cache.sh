#!/bin/bash
# Test script for postgres-builder caching

set -e

echo "Testing postgres-builder caching mechanism..."
echo ""

# Define the postgres-builder tag
PG_VERSION="17.2"
PG_TAG="postgres-builder-${PG_VERSION}-alpine3.22"
REGISTRY="ghcr.io/descoped"

echo "1. Building postgres-builder stage locally..."
docker build -f Dockerfile.standalone \
  --target postgres-builder-build \
  -t ${REGISTRY}/authly-postgres-builder:${PG_TAG} \
  .

echo ""
echo "2. Testing build with cached postgres-builder..."
docker build -f Dockerfile.standalone \
  --build-arg POSTGRES_BUILDER_IMAGE=${REGISTRY}/authly-postgres-builder:${PG_TAG} \
  -t authly-standalone:cached-test \
  .

echo ""
echo "3. Verifying the cached build works..."
docker run --rm authly-standalone:cached-test sh -c "
  postgres --version && 
  ls -la /opt/postgresql/bin/ && 
  du -sh /opt/postgresql/
"

echo ""
echo "✅ Postgres-builder caching test completed successfully!"