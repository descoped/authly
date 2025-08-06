#!/bin/bash
# Setup script for OIDC conformance testing
# This script properly handles external dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Setting up OIDC Conformance Testing"
echo "======================================"
echo ""

# Check if conformance suite is already cloned
if [ -d "conformance-suite/.git" ]; then
    echo "✅ Conformance suite already cloned"
    
    # Check for local modifications
    cd conformance-suite
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "⚠️  Warning: Local modifications detected in conformance-suite/"
        echo "   These will be lost if you continue."
        read -p "   Reset to upstream? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git reset --hard origin/master
            git clean -fd
            echo "✅ Reset to upstream"
        else
            echo "❌ Aborted. Please handle modifications manually."
            exit 1
        fi
    fi
    cd ..
else
    echo "📦 Cloning conformance suite..."
    git clone https://gitlab.com/openid/conformance-suite.git conformance-suite
    echo "✅ Cloned successfully"
fi

# Build conformance suite JAR
echo ""
echo "🔨 Building conformance suite..."

if [ -f "conformance-suite/target/fapi-test-suite.jar" ]; then
    echo "✅ JAR already built"
else
    echo "Building JAR (this may take a few minutes)..."
    
    # Option 1: Build with Docker (recommended)
    if command -v docker &> /dev/null; then
        cd conformance-suite
        docker run --rm \
            -v "$PWD":/usr/src/mymaven \
            -v "$HOME/.m2":/root/.m2 \
            -w /usr/src/mymaven \
            maven:3-eclipse-temurin-17 \
            mvn -B clean package -DskipTests=true
        cd ..
    # Option 2: Build with local Maven
    elif command -v mvn &> /dev/null; then
        cd conformance-suite
        mvn clean package -B -DskipTests=true
        cd ..
    else
        echo "❌ Neither Docker nor Maven found. Please install one of them."
        exit 1
    fi
    
    echo "✅ JAR built successfully"
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
echo "✅ Setup Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Start services:  make start"
echo "2. Run tests:       make test"
echo "3. View results:    make report"
echo ""
echo "For more commands:  make help"
echo ""