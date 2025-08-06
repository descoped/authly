#!/bin/bash
cd "$(dirname "$0")/.."
docker-compose -f docker/docker-compose.yml down
echo "Conformance suite stopped"
