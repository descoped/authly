#!/bin/bash
cd "$(dirname "$0")/.."
docker-compose -f docker/docker-compose.yml up -d
echo "Conformance suite starting..."
echo "Access the web UI at: https://localhost:8443"
echo "Logs: docker-compose -f docker/docker-compose.yml logs -f conformance-suite"
