#!/bin/bash

# Automated OIDC Conformance Testing Script
# Runs conformance tests and generates reports

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TCK_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$TCK_DIR")"

echo "🚀 Automated OIDC Conformance Testing"
echo "======================================"
echo ""

# Check if services are running
check_service() {
    local service=$1
    if docker ps | grep -q "$service"; then
        echo "✅ $service is running"
        return 0
    else
        echo "❌ $service is not running"
        return 1
    fi
}

echo "📋 Checking services..."
services_ok=true

if ! check_service "authly"; then
    services_ok=false
fi

if ! check_service "tck-mongodb"; then
    services_ok=false
fi

if ! check_service "tck-server"; then
    services_ok=false
fi

if ! check_service "tck-httpd"; then
    services_ok=false
fi

if [ "$services_ok" = false ]; then
    echo ""
    echo "⚠️  Some services are not running."
    echo "Starting all services..."
    echo ""
    
    # Start services
    "$PROJECT_ROOT/scripts/start-with-tck.sh"
    
    # Wait for services to be ready
    echo ""
    echo "⏳ Waiting for services to be ready..."
    sleep 10
fi

# Create results directory
RESULTS_DIR="$TCK_DIR/results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo ""
echo "📁 Results will be saved to: $RESULTS_DIR"
echo ""

# Run Python test runner
echo "🧪 Running conformance tests..."
echo ""

cd "$TCK_DIR"

# Check if Python dependencies are installed
if ! python3 -c "import requests" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    pip3 install requests urllib3
fi

# Run the test suite
python3 scripts/run-conformance-tests.py 2>&1 | tee "$RESULTS_DIR/test_output.log"

# Check exit code
TEST_EXIT_CODE=${PIPESTATUS[0]}

# Copy the latest report to results directory
if [ -f "$TCK_DIR/results/conformance_report_"*.md ]; then
    latest_report=$(ls -t "$TCK_DIR/results/conformance_report_"*.md | head -1)
    cp "$latest_report" "$RESULTS_DIR/conformance_report.md"
fi

echo ""
echo "======================================"
echo "📊 Test Execution Complete"
echo "======================================"
echo ""

# Print summary
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed. Check the report for details."
fi

echo ""
echo "📄 Reports saved to: $RESULTS_DIR"
echo ""
echo "View the report:"
echo "  cat $RESULTS_DIR/conformance_report.md"
echo ""

# Generate HTML report if pandoc is available
if command -v pandoc &> /dev/null; then
    echo "📝 Generating HTML report..."
    pandoc "$RESULTS_DIR/conformance_report.md" \
        -o "$RESULTS_DIR/conformance_report.html" \
        --standalone \
        --metadata title="OIDC Conformance Report" \
        --css="https://cdn.jsdelivr.net/npm/github-markdown-css@5.2.0/github-markdown.min.css" \
        2>/dev/null || true
    
    if [ -f "$RESULTS_DIR/conformance_report.html" ]; then
        echo "📄 HTML report generated: $RESULTS_DIR/conformance_report.html"
    fi
fi

exit $TEST_EXIT_CODE