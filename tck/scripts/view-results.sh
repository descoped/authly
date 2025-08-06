#!/bin/bash
cd "$(dirname "$0")/.."
latest_results=$(ls -t results/*/summary.md 2>/dev/null | head -1)
if [ -n "$latest_results" ]; then
    cat "$latest_results"
else
    echo "No test results found. Run tests first with ./scripts/run-conformance.sh"
fi
