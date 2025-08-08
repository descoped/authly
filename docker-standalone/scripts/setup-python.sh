#!/bin/sh
# Setup Python 3.13 runtime
set -e

echo "Setting up Python 3.13..."

# Create symlinks for python and python3
ln -s /usr/local/bin/python3.13 /usr/local/bin/python3
ln -s /usr/local/bin/python3 /usr/local/bin/python

# Update library cache for Python shared libraries
ldconfig /usr/local/lib 2>/dev/null || true

echo "✅ Python 3.13 configured"