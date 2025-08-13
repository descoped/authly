#!/bin/bash
# Run all conformance test configurations

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 Running All Conformance Test Configurations${NC}"
echo "=============================================="

# Create results directory
mkdir -p reports/all-conformance

# Run each conformance configuration
configs=(
    "config/conformance-basic.json"
    "config/conformance-pkce.json"
    "config/conformance-security.json"
)

total_passed=0
total_failed=0
total_tests=0

for config in "${configs[@]}"; do
    config_name=$(basename "$config" .json)
    echo ""
    echo -e "${YELLOW}Running $config_name...${NC}"
    
    # Run the test
    if python src/test_plans.py "$config" > "reports/all-conformance/${config_name}.log" 2>&1; then
        echo -e "${GREEN}✅ $config_name completed${NC}"
    else
        echo -e "${YELLOW}⚠️ $config_name had some failures${NC}"
    fi
    
    # Extract stats from the log
    if [ -f "reports/test-plans/${config_name}_report.md" ]; then
        passed=$(grep "Passed:" "reports/test-plans/${config_name}_report.md" | grep -oE "[0-9]+" | head -1)
        failed=$(grep "Failed:" "reports/test-plans/${config_name}_report.md" | grep -oE "[0-9]+" | tail -1)
        tests=$(grep "Total Tests:" "reports/test-plans/${config_name}_report.md" | grep -oE "[0-9]+")
        
        total_passed=$((total_passed + passed))
        total_failed=$((total_failed + failed))
        total_tests=$((total_tests + tests))
        
        echo "  Tests: $tests, Passed: $passed, Failed: $failed"
    fi
done

echo ""
echo -e "${GREEN}=============================================="
echo "📊 Consolidated Results"
echo "=============================================="
echo "Total Tests Run: $total_tests"
echo "Total Passed: $total_passed ✅"
echo "Total Failed: $total_failed ❌"
if [ $total_tests -gt 0 ]; then
    pass_rate=$((total_passed * 100 / total_tests))
    echo "Overall Pass Rate: ${pass_rate}%"
fi
echo -e "${NC}"

# Generate consolidated report
cat > reports/all-conformance/CONSOLIDATED_REPORT.md << EOF
# Consolidated Conformance Test Report

## Summary
- **Total Test Configurations**: ${#configs[@]}
- **Total Tests Run**: $total_tests
- **Total Passed**: $total_passed ✅
- **Total Failed**: $total_failed ❌
- **Overall Pass Rate**: ${pass_rate}%

## Configuration Results

EOF

for config in "${configs[@]}"; do
    config_name=$(basename "$config" .json)
    if [ -f "reports/test-plans/${config_name}_report.md" ]; then
        echo "### $config_name" >> reports/all-conformance/CONSOLIDATED_REPORT.md
        grep -A 20 "## Summary" "reports/test-plans/${config_name}_report.md" >> reports/all-conformance/CONSOLIDATED_REPORT.md
        echo "" >> reports/all-conformance/CONSOLIDATED_REPORT.md
    fi
done

echo "📄 Consolidated report saved to: reports/all-conformance/CONSOLIDATED_REPORT.md"