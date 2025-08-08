#!/bin/sh
# Master configuration script for Authly standalone container
# Runs all setup scripts in the correct order
set -e

echo "=== Starting Authly standalone configuration ==="

# Run configuration scripts in order
/tmp/setup-scripts/setup-postgres.sh
/tmp/setup-scripts/setup-python.sh
/tmp/setup-scripts/setup-s6-services.sh
/tmp/setup-scripts/setup-wrappers.sh
/tmp/setup-scripts/setup-environment.sh

echo "=== Configuration complete ==="