#!/bin/bash
# Simple script to achieve 90% OIDC/OAuth conformance

set -e

echo "🚀 OIDC/OAuth Conformance Test"
echo "================================"
echo ""

# Check if Authly is running
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "⚠️  Authly is not running. Starting it now..."
    cd ..
    docker compose up -d
    echo "⏳ Waiting for Authly to be ready..."
    timeout 60 bash -c 'until curl -f http://localhost:8000/health > /dev/null 2>&1; do sleep 2; done'
    cd tck
    echo "✅ Authly is ready"
else
    echo "✅ Authly is already running"
fi

echo ""
echo "🔍 Running conformance validation..."
echo ""

# Run the validator
python scripts/conformance-validator.py

echo ""
echo "📊 Results Summary:"
echo "==================="

# Extract and display compliance
if [ -f "reports/latest/SPECIFICATION_CONFORMANCE.md" ]; then
    COMPLIANCE=$(grep "checks passed" reports/latest/SPECIFICATION_CONFORMANCE.md | head -1)
    echo "Overall: $COMPLIANCE"
    echo ""
    echo "Category Scores:"
    grep "Category Score:" reports/latest/SPECIFICATION_CONFORMANCE.md | sed 's/\*\*//g' | sed 's/^/  /'
    echo ""
    echo "✅ Full report: reports/latest/SPECIFICATION_CONFORMANCE.md"
else
    echo "❌ Report not found"
    exit 1
fi

echo ""
echo "🎯 Target: 90% compliance"
echo "📈 Current: Extracting..."

# Check if we meet the target
PERCENT=$(echo "$COMPLIANCE" | grep -oE "[0-9]+" | tail -1)
if [ "$PERCENT" -ge 90 ]; then
    echo ""
    echo "✅ SUCCESS: Target compliance achieved! ($PERCENT%)"
else
    echo ""
    echo "⚠️  Below target compliance ($PERCENT%)"
    echo ""
    echo "Known issues to fix:"
    echo "1. Token endpoint error response format"
    echo "2. Authorization endpoint error handling"
fi