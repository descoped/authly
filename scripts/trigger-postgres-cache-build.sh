#!/bin/bash

# Trigger the PostgreSQL cache build workflow
# This uses native ARM runners for optimal performance

set -e

echo "🚀 Triggering PostgreSQL cache build workflow..."
echo ""
echo "This workflow builds PostgreSQL using native runners:"
echo "  - AMD64: ubuntu-latest (native x86-64)"
echo "  - ARM64: ubuntu-24.04-arm64 (native ARM - no QEMU!)"
echo ""
echo "Benefits:"
echo "  ✅ 5-10x faster ARM64 builds"
echo "  ✅ No QEMU emulation overhead"
echo "  ✅ Cached for release workflow"
echo ""

# Default values
PG_VERSION="${1:-17.2}"
ALPINE_VERSION="${2:-3.22}"

echo "PostgreSQL version: $PG_VERSION"
echo "Alpine version: $ALPINE_VERSION"
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed."
    echo "   Install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub CLI."
    echo "   Run: gh auth login"
    exit 1
fi

# Trigger the workflow
echo "Triggering workflow..."
gh workflow run build-postgres-cache.yml \
    -f pg_version="$PG_VERSION" \
    -f alpine_version="$ALPINE_VERSION"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Workflow triggered successfully!"
    echo ""
    echo "Monitor progress at:"
    echo "https://github.com/descoped/authly/actions/workflows/build-postgres-cache.yml"
    echo ""
    echo "Once complete, the release workflow will automatically use the cached image."
else
    echo ""
    echo "❌ Failed to trigger workflow"
    exit 1
fi