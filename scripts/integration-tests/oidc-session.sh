#!/bin/bash
# OIDC Session Management Integration Test
# Tests OpenID Connect Session Management 1.0 endpoints
#
# NOTE: Session Management is not yet fully implemented in Authly
# Per tck/tck_todo.md, Session Management and Front-Channel Logout are pending tasks
# This test is disabled by default in run-full-stack-test.sh
# Enable with: RUN_OIDC_SESSION_TESTS=true when implementation is complete

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/user-auth.sh"

# Test results tracking
SESSION_TESTS_PASSED=0
SESSION_TESTS_FAILED=0

# Function to test session check endpoint
test_session_check() {
    log_info "Testing OIDC session check endpoint"
    
    # Test without authentication (should fail or return inactive)
    local response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check")
    local status="${response: -3}"
    
    if [[ "$status" == "401" ]]; then
        log_success "✓ Session check requires authentication (expected)"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
    elif [[ "$status" == "200" ]]; then
        local body="${response%???}"
        local session_state=$(extract_json_field "$body" "session_state")
        if [[ "$session_state" == "inactive" || "$session_state" == "none" ]]; then
            log_success "✓ Session check returned inactive (no session)"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_warning "Session check returned unexpected state: $session_state"
        fi
    else
        log_error "Session check returned unexpected status: $status"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
    fi
    
    # Test with valid authentication
    if load_user_token && is_user_token_valid; then
        log_info "Testing session check with valid token"
        response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check" "Bearer $USER_ACCESS_TOKEN")
        
        if check_http_status "$response" "200"; then
            local body="${response%???}"
            local session_state=$(extract_json_field "$body" "session_state")
            local sid=$(extract_json_field "$body" "sid")
            
            if [[ "$session_state" == "active" ]]; then
                log_success "✓ Session check returned active state"
                SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
            else
                log_error "Session check returned unexpected state: $session_state"
                SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
            fi
            
            if [[ -n "$sid" && "$sid" != "null" ]]; then
                log_success "✓ Session ID present: ${sid:0:20}..."
                SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
            else
                log_warning "Session ID not present in response"
            fi
        else
            log_error "Session check with valid token failed"
            SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
        fi
    else
        log_info "Performing user login for session testing"
        user_login "$TEST_USERNAME" "$TEST_PASSWORD" "openid profile" || {
            log_error "Failed to authenticate for session testing"
            SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
            return 1
        }
        
        # Retry session check with new token
        response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check" "Bearer $USER_ACCESS_TOKEN")
        if check_http_status "$response" "200"; then
            log_success "✓ Session check successful after login"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_error "Session check failed after login"
            SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
        fi
    fi
    
    return 0
}

# Function to test session iframe endpoint
test_session_iframe() {
    log_info "Testing OIDC session management iframe endpoint"
    
    local response=$(get_request "$AUTHLY_BASE_URL/oidc/session/iframe")
    
    if check_http_status "$response" "200"; then
        local body="${response%???}"
        
        # Check if response contains HTML/JavaScript for session monitoring
        if echo "$body" | grep -q "postMessage\|sessionStorage\|checkSession" 2>/dev/null; then
            log_success "✓ Session iframe contains session monitoring code"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_warning "Session iframe may not contain expected monitoring code"
        fi
        
        # Check Content-Type header
        local content_type=$(echo "$response" | grep -i "content-type:" | head -1 || echo "")
        if echo "$content_type" | grep -q "text/html"; then
            log_success "✓ Session iframe returns HTML content"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_warning "Session iframe Content-Type: $content_type"
        fi
    else
        log_error "Session iframe endpoint returned status: ${response: -3}"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
    fi
    
    return 0
}

# Function to test RP-initiated logout
test_rp_logout() {
    log_info "Testing OIDC RP-Initiated Logout endpoint"
    
    # Get a valid ID token first (if available)
    local id_token_hint=""
    if [[ -n "${USER_ID_TOKEN:-}" && "$USER_ID_TOKEN" != "null" ]]; then
        id_token_hint="$USER_ID_TOKEN"
        log_info "Using ID token hint for logout"
    fi
    
    # Test logout endpoint without parameters
    local response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/oidc/logout" 2>/dev/null || echo "000")
    local status="${response: -3}"
    
    if [[ "$status" == "200" || "$status" == "302" ]]; then
        log_success "✓ Logout endpoint accessible"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
    else
        log_warning "Logout endpoint returned status: $status"
    fi
    
    # Test logout with parameters
    local logout_params="post_logout_redirect_uri=https://example.com/logout&state=test123"
    if [[ -n "$id_token_hint" ]]; then
        logout_params="$logout_params&id_token_hint=$id_token_hint"
    fi
    
    response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/oidc/logout?$logout_params" 2>/dev/null || echo "000")
    status="${response: -3}"
    
    if [[ "$status" == "302" ]]; then
        log_success "✓ Logout endpoint redirects as expected"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        
        # Check redirect location
        local location=$(echo "$response" | grep -i "location:" | head -1 || echo "")
        if echo "$location" | grep -q "example.com/logout"; then
            log_success "✓ Logout redirects to specified URI"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        fi
    elif [[ "$status" == "200" ]]; then
        log_info "Logout endpoint returned 200 (may show confirmation page)"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
    else
        log_error "Logout endpoint with parameters returned unexpected status: $status"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
    fi
    
    return 0
}

# Function to test front-channel logout
test_frontchannel_logout() {
    log_info "Testing OIDC Front-Channel Logout endpoint"
    
    local response=$(get_request "$AUTHLY_BASE_URL/oidc/frontchannel/logout")
    local status="${response: -3}"
    
    if [[ "$status" == "200" || "$status" == "400" ]]; then
        log_success "✓ Front-channel logout endpoint accessible"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        
        # Test with session ID parameter
        response=$(get_request "$AUTHLY_BASE_URL/oidc/frontchannel/logout?sid=test-session-id")
        status="${response: -3}"
        
        if [[ "$status" == "200" || "$status" == "400" ]]; then
            log_success "✓ Front-channel logout handles session ID parameter"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_warning "Front-channel logout with sid returned: $status"
        fi
    else
        log_error "Front-channel logout endpoint returned unexpected status: $status"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
    fi
    
    return 0
}

# Function to test session state changes
test_session_lifecycle() {
    log_info "Testing OIDC session lifecycle"
    
    # Start fresh - logout any existing session
    user_logout >/dev/null 2>&1 || true
    
    # 1. Check session before login (should be inactive)
    log_info "Step 1: Check session before login"
    local response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check")
    local status="${response: -3}"
    
    if [[ "$status" == "401" || "$status" == "200" ]]; then
        if [[ "$status" == "200" ]]; then
            local body="${response%???}"
            local session_state=$(extract_json_field "$body" "session_state")
            if [[ "$session_state" == "inactive" || "$session_state" == "none" ]]; then
                log_success "✓ No active session before login"
                SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
            fi
        else
            log_success "✓ Session check requires authentication"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        fi
    fi
    
    # 2. Login and create session
    log_info "Step 2: Create session via login"
    if ! user_login "$TEST_USERNAME" "$TEST_PASSWORD" "openid profile"; then
        log_error "Failed to create session via login"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
        return 1
    fi
    
    # 3. Check session after login (should be active)
    log_info "Step 3: Check session after login"
    response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check" "Bearer $USER_ACCESS_TOKEN")
    
    if check_http_status "$response" "200"; then
        local body="${response%???}"
        local session_state=$(extract_json_field "$body" "session_state")
        
        if [[ "$session_state" == "active" ]]; then
            log_success "✓ Session active after login"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_error "Session not active after login: $session_state"
            SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
        fi
    else
        log_error "Failed to check session after login"
        SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
    fi
    
    # 4. Logout and check session
    log_info "Step 4: Logout and verify session termination"
    
    # Perform logout
    if [[ -n "${USER_ID_TOKEN:-}" && "$USER_ID_TOKEN" != "null" ]]; then
        response=$(curl -s -w "\n%{http_code}" \
            "$AUTHLY_BASE_URL/oidc/logout?id_token_hint=$USER_ID_TOKEN" 2>/dev/null || echo "000")
    else
        response=$(curl -s -w "\n%{http_code}" \
            "$AUTHLY_BASE_URL/oidc/logout" 2>/dev/null || echo "000")
    fi
    
    status="${response: -3}"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
        log_success "✓ Logout completed"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
    fi
    
    # Try to use the old token (should fail)
    response=$(get_request "$AUTHLY_BASE_URL/oidc/session/check" "Bearer $USER_ACCESS_TOKEN")
    status="${response: -3}"
    
    if [[ "$status" == "401" ]]; then
        log_success "✓ Session terminated after logout"
        SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
    elif [[ "$status" == "200" ]]; then
        local body="${response%???}"
        local session_state=$(extract_json_field "$body" "session_state")
        if [[ "$session_state" == "inactive" || "$session_state" == "terminated" ]]; then
            log_success "✓ Session marked as inactive after logout"
            SESSION_TESTS_PASSED=$((SESSION_TESTS_PASSED + 1))
        else
            log_error "Session still active after logout: $session_state"
            SESSION_TESTS_FAILED=$((SESSION_TESTS_FAILED + 1))
        fi
    else
        log_warning "Unexpected session status after logout: $status"
    fi
    
    return 0
}

# Main test function
run_oidc_session_test() {
    log_info "=== OIDC Session Management Integration Test ==="
    
    # Validate configuration
    validate_config || return 1
    
    # Check if services are ready
    wait_for_service "$HEALTH_ENDPOINT" || return 1
    
    # Run session management tests
    test_session_check || log_warning "Session check test failed"
    test_session_iframe || log_warning "Session iframe test failed"
    test_rp_logout || log_warning "RP-initiated logout test failed"
    test_frontchannel_logout || log_warning "Front-channel logout test failed"
    test_session_lifecycle || log_warning "Session lifecycle test failed"
    
    # Report results
    log_info "=== OIDC Session Test Results ==="
    log_success "Passed: $SESSION_TESTS_PASSED"
    log_error "Failed: $SESSION_TESTS_FAILED"
    
    if [[ $SESSION_TESTS_FAILED -eq 0 ]]; then
        log_success "=== OIDC Session Test Completed Successfully ==="
        return 0
    else
        log_error "=== OIDC Session Test Failed ==="
        return 1
    fi
}

# Cleanup function
cleanup_oidc_session() {
    log_info "Cleaning up OIDC session test"
    user_logout >/dev/null 2>&1 || true
}

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_oidc_session
    
    # Run the test
    run_oidc_session_test
    exit $?
fi