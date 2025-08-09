#!/bin/sh
# Install additional debugging and profiling tools
set -e

echo "Installing Python debugging tools..."

# Install Python profiling tools via pip
pip install --no-cache-dir \
    py-spy \
    memory_profiler \
    line_profiler \
    flamegraph \
    pyinstrument \
    ipython \
    ipdb \
    2>/dev/null || true

# Install system performance tools if not already present
which perf >/dev/null 2>&1 || apk add --no-cache perf 2>/dev/null || true
which gdb >/dev/null 2>&1 || apk add --no-cache gdb 2>/dev/null || true

echo "✅ Debug tools installed"