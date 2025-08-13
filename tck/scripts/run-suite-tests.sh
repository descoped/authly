#!/bin/bash
# Run OIDC Conformance Suite tests against Authly
# This script bridges the gap between our lightweight validator and full certification

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
SUITE_URL="https://localhost:8443"
AUTHLY_URL="${AUTHLY_BASE_URL:-http://localhost:8000}"
REPORTS_DIR="reports/suite-tests"

echo -e "${GREEN}🚀 OIDC Conformance Suite Test Runner${NC}"
echo "=================================="
echo "Suite URL: $SUITE_URL"
echo "Authly URL: $AUTHLY_URL"
echo ""

# Function to check if services are running
check_services() {
    echo -e "${YELLOW}Checking services...${NC}"
    
    # Check Authly
    if curl -sf "$AUTHLY_URL/health" > /dev/null; then
        echo -e "  ✅ Authly is running"
    else
        echo -e "  ❌ Authly is not accessible at $AUTHLY_URL"
        echo -e "     Start with: docker compose up -d"
        exit 1
    fi
    
    # Check Conformance Suite
    if curl -skf "$SUITE_URL/api/runner/available" > /dev/null 2>&1; then
        echo -e "  ✅ Conformance suite is running"
    else
        echo -e "  ⚠️  Conformance suite not running, starting it..."
        cd "$(dirname "$0")/.."
        docker compose --profile github-ci up -d
        echo -e "  ⏳ Waiting for suite to start (30 seconds)..."
        sleep 30
    fi
}

# Function to create test configuration
create_test_config() {
    local test_type=$1
    local config_file="config/suite-$test_type.json"
    
    echo -e "${YELLOW}Creating test configuration: $test_type${NC}"
    
    cat > "$config_file" << EOF
{
    "alias": "authly-$test_type-$(date +%s)",
    "description": "Authly $test_type Testing",
    "server": {
        "discoveryUrl": "$AUTHLY_URL/.well-known/openid-configuration"
    },
    "client": {
        "client_id": "conformance-test",
        "client_secret": "test-secret",
        "redirect_uri": "$SUITE_URL/test/a/authly/callback",
        "scope": "openid profile email"
    },
    "test_plan": "$test_type",
    "variant": {
        "client_auth_type": "client_secret_basic",
        "response_type": "code",
        "response_mode": "query"
    }
}
EOF
    
    echo "  Created: $config_file"
}

# Function to run test via API
run_suite_test() {
    local test_type=$1
    local config_file="config/suite-$test_type.json"
    
    echo -e "${GREEN}Running $test_type tests...${NC}"
    
    # Create test plan via API
    local plan_response=$(curl -sk -X POST \
        -H "Content-Type: application/json" \
        -d @"$config_file" \
        "$SUITE_URL/api/plan")
    
    local plan_id=$(echo "$plan_response" | jq -r '.id // empty')
    
    if [ -z "$plan_id" ]; then
        echo -e "${RED}Failed to create test plan${NC}"
        echo "Response: $plan_response"
        return 1
    fi
    
    echo "  Test plan ID: $plan_id"
    echo "  View in browser: $SUITE_URL/plan-detail.html?plan=$plan_id"
    
    # Get test modules for this plan
    local modules=$(get_test_modules "$test_type")
    
    # Run each module
    local passed=0
    local failed=0
    local total=0
    
    for module in $modules; do
        echo -n "  Testing $module... "
        
        # Start test
        local test_response=$(curl -sk -X POST \
            "$SUITE_URL/api/plan/$plan_id/test/$module/start")
        
        local test_id=$(echo "$test_response" | jq -r '.id // empty')
        
        if [ -z "$test_id" ]; then
            echo -e "${RED}SKIPPED${NC} (not applicable)"
            continue
        fi
        
        # Wait for completion
        local status=""
        local attempts=0
        while [ "$status" != "FINISHED" ] && [ "$status" != "FAILED" ] && [ "$attempts" -lt 30 ]; do
            sleep 1
            local result=$(curl -sk "$SUITE_URL/api/plan/$plan_id/test/$test_id")
            status=$(echo "$result" | jq -r '.status // empty')
            attempts=$((attempts + 1))
        done
        
        # Check result
        if [ "$status" == "FINISHED" ]; then
            echo -e "${GREEN}✅ PASSED${NC}"
            passed=$((passed + 1))
        else
            echo -e "${RED}❌ FAILED${NC}"
            failed=$((failed + 1))
            # Get error details
            local error=$(echo "$result" | jq -r '.error // .message // "Unknown error"')
            echo "     Error: $error"
        fi
        
        total=$((total + 1))
    done
    
    # Generate report
    generate_report "$test_type" "$plan_id" "$passed" "$failed" "$total"
}

# Function to get test modules
get_test_modules() {
    local test_type=$1
    
    case "$test_type" in
        "oidcc-basic-certification-test-plan")
            echo "oidcc-server oidcc-discovery-issuer oidcc-userinfo-get oidcc-scope-profile oidcc-scope-email"
            ;;
        "oidcc-pkce-test-plan")
            echo "oidcc-ensure-pkce-required oidcc-ensure-pkce-code-verifier-required oidcc-ensure-pkce-code-challenge-method-s256"
            ;;
        *)
            echo "oidcc-server"
            ;;
    esac
}

# Function to generate report
generate_report() {
    local test_type=$1
    local plan_id=$2
    local passed=$3
    local failed=$4
    local total=$5
    
    mkdir -p "$REPORTS_DIR"
    local report_file="$REPORTS_DIR/suite-$test_type-$(date +%Y%m%d-%H%M%S).md"
    
    local pass_rate=0
    if [ "$total" -gt 0 ]; then
        pass_rate=$((passed * 100 / total))
    fi
    
    cat > "$report_file" << EOF
# Conformance Suite Test Report

## Test Information
- **Test Plan**: $test_type
- **Plan ID**: $plan_id
- **Timestamp**: $(date '+%Y-%m-%d %H:%M:%S')
- **Authly URL**: $AUTHLY_URL
- **Suite URL**: $SUITE_URL

## Results Summary
- **Total Tests**: $total
- **Passed**: $passed ✅
- **Failed**: $failed ❌
- **Pass Rate**: ${pass_rate}%

## View Detailed Results
[Open in Conformance Suite UI]($SUITE_URL/plan-detail.html?plan=$plan_id)

## Next Steps
EOF
    
    if [ "$failed" -gt 0 ]; then
        cat >> "$report_file" << EOF

### Failed Tests Need Attention
1. Review the detailed error messages in the UI
2. Check \`reports/latest/ACTIONABLE_ITEMS.md\` for fixes
3. Run \`make validate\` to see lightweight validator results
4. Fix issues and re-run this test
EOF
    else
        cat >> "$report_file" << EOF

### 🎉 All Tests Passed!
Consider running more comprehensive test plans:
- \`oidcc-advanced-test-plan\` - Advanced features
- \`oidcc-security-test-plan\` - Security scenarios
- \`oidcc-interop-test-plan\` - Interoperability tests
EOF
    fi
    
    echo ""
    echo -e "${GREEN}📄 Report saved: $report_file${NC}"
    
    # Display summary
    echo ""
    echo "=================================="
    echo -e "${GREEN}Test Results Summary${NC}"
    echo "=================================="
    echo "Test Plan: $test_type"
    echo "Pass Rate: ${pass_rate}%"
    
    if [ "$pass_rate" -ge 90 ]; then
        echo -e "${GREEN}✅ PASSED - Meets 90% threshold${NC}"
        return 0
    else
        echo -e "${RED}❌ FAILED - Below 90% threshold${NC}"
        return 1
    fi
}

# Main execution
main() {
    cd "$(dirname "$0")/.."
    
    # Check services
    check_services
    
    # Parse arguments
    local test_type="${1:-oidcc-basic-certification-test-plan}"
    
    echo ""
    echo -e "${GREEN}Starting Conformance Suite Testing${NC}"
    echo "=================================="
    
    # Create configuration
    create_test_config "$test_type"
    
    # Run tests
    run_suite_test "$test_type"
    
    local exit_code=$?
    
    echo ""
    echo -e "${GREEN}Testing Complete${NC}"
    
    exit $exit_code
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi