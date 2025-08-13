#!/bin/bash
# Setup script for OIDC conformance testing using pre-built Docker image
# Uses ghcr.io/descoped/oidc-conformance-suite:latest instead of building locally

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Setting up OIDC Conformance Testing (Pre-built Image)"
echo "========================================================"
echo ""

# Configuration
CONFORMANCE_IMAGE="ghcr.io/descoped/oidc-conformance-suite:latest"

echo "🐳 Using pre-built conformance suite image..."
echo "Image: $CONFORMANCE_IMAGE"
echo ""

# Check if pre-built image is available
if docker manifest inspect "$CONFORMANCE_IMAGE" > /dev/null 2>&1; then
    echo "✅ Pre-built image available"
else
    echo "📦 Pulling pre-built image..."
    if docker pull "$CONFORMANCE_IMAGE"; then
        echo "✅ Successfully pulled pre-built image"
    else
        echo "❌ Failed to pull pre-built image. Check your internet connection."
        exit 1
    fi
fi

# Remove conformance-suite folder if it exists (no longer needed)
if [ -d "conformance-suite" ]; then
    echo "🧹 Removing local conformance-suite folder (no longer needed)..."
    read -p "Remove conformance-suite/ folder? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf conformance-suite
        echo "✅ Removed conformance-suite folder"
    else
        echo "⚠️  Keeping conformance-suite folder (consider removing manually)"
    fi
fi

# Create results directory
mkdir -p results

# Install Python dependencies
echo ""
echo "📦 Checking Python dependencies..."
if python3 -c "import requests" 2>/dev/null; then
    echo "✅ Python dependencies installed"
else
    echo "Installing Python dependencies..."
    pip3 install requests urllib3
    echo "✅ Dependencies installed"
fi

echo ""
echo "======================================"
echo "✅ Setup Complete (Pre-built Image)!"
echo "======================================"
echo ""
echo "Configuration:"
echo "  • Image: $CONFORMANCE_IMAGE"
echo "  • Docker Compose: docker-compose-tck.yml"
echo "  • No local build required!"
echo ""
echo "Next steps:"
echo "1. Start services:  docker compose -f docker-compose-tck.yml up -d"
echo "2. Run tests:       make validate"
echo "3. View results:    make report"
echo ""
echo "Benefits:"
echo "  • No Java/Maven build required"
echo "  • Faster startup time"
echo "  • Consistent environment"
echo ""