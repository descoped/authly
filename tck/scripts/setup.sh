#!/bin/bash
# TCK Environment Setup
# Unified setup script for OIDC/OAuth conformance testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "🚀 TCK Environment Setup"
echo "========================"
echo ""

# Configuration
CONFORMANCE_IMAGE="ghcr.io/descoped/oidc-conformance-suite:latest"
TCK_IMAGE="authly-tck:latest"

echo "📋 Setup Summary:"
echo "  • Project: $(basename "$PROJECT_DIR")"
echo "  • Conformance Image: $CONFORMANCE_IMAGE"  
echo "  • TCK Image: $TCK_IMAGE"
echo ""

# 1. Create required directories
echo "📁 Creating directories..."
mkdir -p reports/latest config/test-plans
echo "✅ Directories created"
echo ""

# 2. Check Docker availability
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "❌ Docker daemon not running. Please start Docker."
    exit 1
fi

echo "🐳 Docker ready"
echo ""

# 3. Pull conformance suite image if needed
echo "📦 Checking conformance suite image..."
if docker manifest inspect "$CONFORMANCE_IMAGE" > /dev/null 2>&1; then
    echo "✅ Pre-built conformance image available"
else
    echo "📥 Pulling conformance suite image..."
    if docker pull "$CONFORMANCE_IMAGE"; then
        echo "✅ Successfully pulled conformance image"
    else
        echo "⚠️  Failed to pull conformance image (will build if needed)"
    fi
fi
echo ""

# 4. Build TCK container
echo "🔨 Building TCK validation container..."
if docker build -f Dockerfile.tck -t "$TCK_IMAGE" .; then
    echo "✅ TCK container built successfully"
else
    echo "❌ Failed to build TCK container"
    exit 1
fi
echo ""

# 5. Verify setup
echo "🔍 Verifying setup..."

# Check if main compose file exists
if [[ -f "docker-compose.yml" ]]; then
    echo "✅ Docker compose configuration found"
else
    echo "⚠️  Docker compose configuration missing"
fi

# Check if Makefile exists
if [[ -f "Makefile" ]]; then
    echo "✅ Makefile found"
else
    echo "⚠️  Makefile missing"
fi

# Check Python modules
if [[ -f "src/validator.py" ]] && [[ -f "src/client.py" ]] && [[ -f "src/utils.py" ]]; then
    echo "✅ Python modules found"
else
    echo "⚠️  Some Python modules missing"
fi

echo ""
echo "🎯 Setup Complete!"
echo ""
echo "Quick Start:"
echo "  make validate       # Run OIDC conformance validation"
echo "  make show-reports   # List generated reports"
echo "  make help          # Show all available commands"
echo ""
echo "For detailed information, see README.md"