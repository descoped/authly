#!/bin/bash
# Test script to verify Full Conformance Suite setup

set -e

echo "🧪 Testing Full Conformance Suite Setup"
echo "======================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Change to TCK directory
cd "$(dirname "$0")/.."

echo ""
echo "1. Checking configuration files..."
configs=(
    "config/conformance-basic.json"
    "config/conformance-pkce.json"
    "config/conformance-security.json"
    "config/test-profiles.yml"
)

for config in "${configs[@]}"; do
    if [ -f "$config" ]; then
        echo -e "  ✅ $config"
    else
        echo -e "  ❌ Missing: $config"
        exit 1
    fi
done

echo ""
echo "2. Checking Python modules..."
modules=(
    "src/conformance_suite.py"
    "src/validator.py"
    "src/test_plans.py"
    "src/actionable_items.py"
)

for module in "${modules[@]}"; do
    if [ -f "$module" ]; then
        echo -e "  ✅ $module"
    else
        echo -e "  ❌ Missing: $module"
        exit 1
    fi
done

echo ""
echo "3. Checking Docker setup..."
if [ -f "Dockerfile.tck" ]; then
    echo -e "  ✅ Dockerfile.tck exists"
else
    echo -e "  ❌ Missing Dockerfile.tck"
    exit 1
fi

if [ -f "docker-compose.yml" ]; then
    echo -e "  ✅ docker-compose.yml exists"
    # Check for profiles
    if grep -q "full-suite" docker-compose.yml; then
        echo -e "  ✅ full-suite profile configured"
    else
        echo -e "  ⚠️  full-suite profile not found"
    fi
else
    echo -e "  ❌ Missing docker-compose.yml"
    exit 1
fi

echo ""
echo "4. Checking report directories..."
dirs=(
    "reports/latest"
    "reports/conformance-suite"
    "reports/test-plans"
)

for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "  ✅ $dir exists"
    else
        echo -e "  ⚠️  Creating $dir"
        mkdir -p "$dir"
    fi
done

echo ""
echo "5. Building TCK container..."
if docker compose build validator; then
    echo -e "  ✅ TCK container builds successfully"
else
    echo -e "  ❌ Failed to build TCK container"
    exit 1
fi

echo ""
echo "6. Testing Python imports..."
docker compose run --rm validator python -c "
import sys
sys.path.insert(0, '/tck/src')
try:
    import conformance_suite
    import validator
    import test_plans
    import actionable_items
    print('  ✅ All Python modules import successfully')
except ImportError as e:
    print(f'  ❌ Import error: {e}')
    sys.exit(1)
"

echo ""
echo -e "${GREEN}✅ Full Conformance Suite setup is complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Start Authly: docker compose up -d (in main project)"
echo "  2. Start suite: make suite-start"
echo "  3. Run tests: make suite-test"
echo ""
echo "Available commands:"
echo "  make suite-test         # Run basic OIDC certification"
echo "  make suite-test-pkce    # Run PKCE certification"
echo "  make suite-test-security # Run security tests"
echo "  make suite-test-all     # Run all test profiles"
echo "  make suite-status       # Check suite status"
echo "  make suite-stop         # Stop suite"