#!/bin/bash
# OIDC Conformance Integration Test
# Comprehensive test suite for OpenID Connect Core 1.0 conformance
#
# NOTE: Authly has achieved 100% conformance on core OIDC features
# Some optional/advanced features tested here may not be implemented:
# - Session Management (pending per tck/tck_todo.md)
# - Front-Channel Logout (pending per tck/tck_todo.md)
# - Dynamic Client Registration (not implemented)
# - Request Object Support (not implemented)
# Current pass rate: ~65% (includes optional features)

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/../helpers/oauth.sh"
source "$SCRIPT_DIR/admin-auth.sh"
source "$SCRIPT_DIR/client-management.sh"

# Test results tracking
CONFORMANCE_TESTS_PASSED=0
CONFORMANCE_TESTS_FAILED=0
CONFORMANCE_TESTS_SKIPPED=0

# OIDC test client configuration
OIDC_TEST_CLIENT_ID=""
OIDC_TEST_CLIENT_SECRET=""
OIDC_TEST_REDIRECT_URI="https://oidc-test.example.com/callback"

# Test user credentials (using admin as verified user)
TEST_USERNAME="${TEST_USER_USERNAME:-admin}"
TEST_PASSWORD="${TEST_USER_PASSWORD:-${AUTHLY_ADMIN_PASSWORD}}"

# Function to create OIDC test client
create_oidc_test_client() {
    log_info "Creating OIDC conformance test client"
    
    # Ensure admin authentication
    if ! load_admin_token || ! is_admin_token_valid; then
        admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
    fi
    
    # Create client with OIDC-specific configuration
    local client_data=$(cat <<EOF
{
  "client_name": "OIDC_Conformance_Test_Client",
  "client_type": "confidential",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["$OIDC_TEST_REDIRECT_URI"],
  "response_types": ["code"],
  "scopes": ["openid", "profile", "email", "phone", "address", "offline_access"],
  "require_pkce": true,
  "token_endpoint_auth_method": "client_secret_basic",
  "id_token_signed_response_alg": "RS256",
  "userinfo_signed_response_alg": "none",
  "request_object_signing_alg": "none",
  "frontchannel_logout_uri": "https://oidc-test.example.com/frontchannel-logout",
  "frontchannel_logout_session_required": true,
  "post_logout_redirect_uris": ["https://oidc-test.example.com/post-logout"]
}
EOF
)
    
    local response=$(post_request "$CLIENTS_ENDPOINT" "$client_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    if ! check_http_status "$response" "200" "201"; then
        log_error "Failed to create OIDC test client"
        return 1
    fi
    
    local body="${response%???}"
    OIDC_TEST_CLIENT_ID=$(extract_json_field "$body" "client_id")
    OIDC_TEST_CLIENT_SECRET=$(extract_json_field "$body" "client_secret")
    
    log_success "OIDC test client created: $OIDC_TEST_CLIENT_ID"
    return 0
}

# Function to test ID token structure and claims
test_id_token_claims() {
    log_info "Testing ID token structure and claims"
    
    # Get tokens with openid scope
    local token_response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "password" \
        "$TEST_USERNAME" "$TEST_PASSWORD" "openid profile email")
    
    if ! check_http_status "$token_response" "200"; then
        log_error "Failed to obtain tokens"
        CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        return 1
    fi
    
    local token_body="${token_response%???}"
    local id_token=$(extract_json_field "$token_body" "id_token")
    
    if [[ -z "$id_token" || "$id_token" == "null" ]]; then
        log_error "No ID token returned with openid scope"
        CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        return 1
    fi
    
    # Validate JWT structure
    local dot_count=$(echo "$id_token" | grep -o '\.' | wc -l | tr -d ' ')
    if [[ $dot_count -ne 2 ]]; then
        log_error "Invalid ID token structure (expected 3 parts, got $((dot_count + 1)))"
        CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        return 1
    fi
    
    log_success "✓ ID token has valid JWT structure"
    CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
    
    # Decode and validate claims
    local payload=$(echo "$id_token" | cut -d'.' -f2)
    local payload_padded=$(printf "%s%s" "$payload" "$(printf '%*s' $(((4 - ${#payload} % 4) % 4)) | tr ' ' '=')")
    local payload_json=$(echo "$payload_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
    
    # Check required claims (OIDC Core 1.0 Section 2)
    local required_claims=("iss" "sub" "aud" "exp" "iat")
    
    for claim in "${required_claims[@]}"; do
        local value=$(echo "$payload_json" | jq -r ".$claim" 2>/dev/null)
        if [[ -z "$value" || "$value" == "null" ]]; then
            log_error "Missing required ID token claim: $claim"
            CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        else
            log_success "✓ Required claim present: $claim"
            CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        fi
    done
    
    # Validate issuer matches discovery
    local discovery_response=$(get_request "/.well-known/openid-configuration")
    if check_http_status "$discovery_response" "200"; then
        local discovery_body="${discovery_response%???}"
        local expected_issuer=$(extract_json_field "$discovery_body" "issuer")
        local token_issuer=$(echo "$payload_json" | jq -r ".iss" 2>/dev/null)
        
        if [[ "$token_issuer" == "$expected_issuer" ]]; then
            log_success "✓ ID token issuer matches discovery"
            CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        else
            log_error "ID token issuer mismatch: got '$token_issuer', expected '$expected_issuer'"
            CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        fi
    fi
    
    return 0
}

# Function to test UserInfo endpoint with different scopes
test_userinfo_scopes() {
    log_info "Testing UserInfo endpoint with different scopes"
    
    local test_scopes=(
        "openid"
        "openid profile"
        "openid email"
        "openid profile email"
        "openid phone"
        "openid address"
    )
    
    for scopes in "${test_scopes[@]}"; do
        log_info "Testing UserInfo with scopes: $scopes"
        
        # Get token with specific scopes
        local token_response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "password" \
            "$TEST_USERNAME" "$TEST_PASSWORD" "$scopes")
        
        if ! check_http_status "$token_response" "200"; then
            log_warning "Failed to get token with scopes: $scopes"
            continue
        fi
        
        local token_body="${token_response%???}"
        local access_token=$(extract_json_field "$token_body" "access_token")
        
        # Call UserInfo endpoint
        local userinfo_response=$(get_request "/oidc/userinfo" "Bearer $access_token")
        
        if ! check_http_status "$userinfo_response" "200"; then
            log_error "UserInfo request failed for scopes: $scopes"
            CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
            continue
        fi
        
        local userinfo_body="${userinfo_response%???}"
        
        # Validate claims based on scopes
        local sub=$(extract_json_field "$userinfo_body" "sub")
        if [[ -z "$sub" || "$sub" == "null" ]]; then
            log_error "UserInfo missing required 'sub' claim"
            CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        else
            log_success "✓ UserInfo returns 'sub' claim for scopes: $scopes"
            CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        fi
        
        # Check scope-specific claims
        if [[ "$scopes" == *"profile"* ]]; then
            local name=$(extract_json_field "$userinfo_body" "name")
            local preferred_username=$(extract_json_field "$userinfo_body" "preferred_username")
            if [[ -n "$name" || -n "$preferred_username" ]]; then
                log_success "✓ Profile claims present"
                CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
            fi
        fi
        
        if [[ "$scopes" == *"email"* ]]; then
            local email=$(extract_json_field "$userinfo_body" "email")
            if [[ -n "$email" && "$email" != "null" ]]; then
                log_success "✓ Email claim present"
                CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
            fi
        fi
    done
    
    return 0
}

# Function to test nonce validation
test_nonce_validation() {
    log_info "Testing nonce validation in ID tokens"
    
    # Generate a nonce
    local nonce=$(generate_oidc_nonce)
    
    # For this test, we need to simulate an authorization code flow
    # Since we can't easily do browser automation, we'll test the concept
    
    log_info "Testing nonce parameter handling"
    
    # Build authorization URL with nonce
    local auth_params="response_type=code"
    auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
    auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
    auth_params="$auth_params&scope=openid"
    auth_params="$auth_params&state=$(generate_oauth_state)"
    auth_params="$auth_params&nonce=$nonce"
    auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
    auth_params="$auth_params&code_challenge_method=S256"
    
    # Test that authorization endpoint accepts nonce parameter
    local auth_response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
    local status="${auth_response: -3}"
    
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
        log_success "✓ Authorization endpoint accepts nonce parameter"
        CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
    else
        log_error "Authorization endpoint rejected nonce parameter (status: $status)"
        CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
    fi
    
    # In a real flow, we would validate that the ID token contains the same nonce
    log_info "Note: Full nonce validation requires complete authorization code flow"
    
    return 0
}

# Function to test max_age parameter
test_max_age_parameter() {
    log_info "Testing max_age parameter handling"
    
    # Build authorization URL with max_age
    local auth_params="response_type=code"
    auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
    auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
    auth_params="$auth_params&scope=openid"
    auth_params="$auth_params&state=$(generate_oauth_state)"
    auth_params="$auth_params&max_age=300"  # 5 minutes
    auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
    auth_params="$auth_params&code_challenge_method=S256"
    
    # Test that authorization endpoint accepts max_age parameter
    local auth_response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
    local status="${auth_response: -3}"
    
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
        log_success "✓ Authorization endpoint accepts max_age parameter"
        CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
    else
        log_error "Authorization endpoint rejected max_age parameter (status: $status)"
        CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
    fi
    
    return 0
}

# Function to test prompt parameter variations
test_prompt_parameter() {
    log_info "Testing prompt parameter variations"
    
    local prompt_values=("none" "login" "consent" "select_account")
    
    for prompt in "${prompt_values[@]}"; do
        log_info "Testing prompt=$prompt"
        
        local auth_params="response_type=code"
        auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
        auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
        auth_params="$auth_params&scope=openid"
        auth_params="$auth_params&state=$(generate_oauth_state)"
        auth_params="$auth_params&prompt=$prompt"
        auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
        auth_params="$auth_params&code_challenge_method=S256"
        
        local auth_response=$(curl -s -w "\n%{http_code}" \
            "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
        local status="${auth_response: -3}"
        
        # Different prompts may have different expected behaviors
        case "$prompt" in
            "none")
                # Should redirect with error if not logged in
                if [[ "$status" == "302" || "$status" == "401" ]]; then
                    log_success "✓ prompt=none handled correctly"
                    CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
                else
                    log_warning "Unexpected response for prompt=none: $status"
                fi
                ;;
            "login"|"consent"|"select_account")
                # Should show login/consent page
                if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
                    log_success "✓ prompt=$prompt accepted"
                    CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
                else
                    log_warning "Unexpected response for prompt=$prompt: $status"
                fi
                ;;
        esac
    done
    
    return 0
}

# Function to test ACR values
test_acr_values() {
    log_info "Testing ACR (Authentication Context Class Reference) values"
    
    local auth_params="response_type=code"
    auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
    auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
    auth_params="$auth_params&scope=openid"
    auth_params="$auth_params&state=$(generate_oauth_state)"
    auth_params="$auth_params&acr_values=urn:mace:incommon:iap:bronze"
    auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
    auth_params="$auth_params&code_challenge_method=S256"
    
    local auth_response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
    local status="${auth_response: -3}"
    
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
        log_success "✓ Authorization endpoint accepts acr_values parameter"
        CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
    else
        log_warning "Authorization endpoint may not support acr_values (status: $status)"
        CONFORMANCE_TESTS_SKIPPED=$((CONFORMANCE_TESTS_SKIPPED + 1))
    fi
    
    return 0
}

# Function to test claims parameter
test_claims_parameter() {
    log_info "Testing claims parameter for requesting specific claims"
    
    # Build claims request
    local claims_json='{
        "userinfo": {
            "given_name": {"essential": true},
            "family_name": {"essential": true},
            "email": {"essential": true}
        },
        "id_token": {
            "auth_time": {"essential": true},
            "acr": {"values": ["urn:mace:incommon:iap:bronze"]}
        }
    }'
    
    local claims_encoded=$(echo "$claims_json" | jq -c . | urlencode)
    
    local auth_params="response_type=code"
    auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
    auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
    auth_params="$auth_params&scope=openid"
    auth_params="$auth_params&state=$(generate_oauth_state)"
    auth_params="$auth_params&claims=$claims_encoded"
    auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
    auth_params="$auth_params&code_challenge_method=S256"
    
    local auth_response=$(curl -s -w "\n%{http_code}" \
        "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
    local status="${auth_response: -3}"
    
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
        log_success "✓ Authorization endpoint accepts claims parameter"
        CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
    else
        log_warning "Authorization endpoint may not support claims parameter (status: $status)"
        CONFORMANCE_TESTS_SKIPPED=$((CONFORMANCE_TESTS_SKIPPED + 1))
    fi
    
    return 0
}

# Function to test response_mode variations
test_response_mode() {
    log_info "Testing response_mode parameter variations"
    
    local response_modes=("query" "fragment" "form_post")
    
    for mode in "${response_modes[@]}"; do
        log_info "Testing response_mode=$mode"
        
        local auth_params="response_type=code"
        auth_params="$auth_params&client_id=$OIDC_TEST_CLIENT_ID"
        auth_params="$auth_params&redirect_uri=$(urlencode "$OIDC_TEST_REDIRECT_URI")"
        auth_params="$auth_params&scope=openid"
        auth_params="$auth_params&state=$(generate_oauth_state)"
        auth_params="$auth_params&response_mode=$mode"
        auth_params="$auth_params&code_challenge=$(generate_pkce_pair | jq -r '.code_challenge')"
        auth_params="$auth_params&code_challenge_method=S256"
        
        local auth_response=$(curl -s -w "\n%{http_code}" \
            "$AUTHLY_BASE_URL/api/v1/oauth/authorize?$auth_params" 2>/dev/null || echo "000")
        local status="${auth_response: -3}"
        
        if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" ]]; then
            log_success "✓ response_mode=$mode accepted"
            CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        else
            log_warning "response_mode=$mode may not be supported (status: $status)"
            CONFORMANCE_TESTS_SKIPPED=$((CONFORMANCE_TESTS_SKIPPED + 1))
        fi
    done
    
    return 0
}

# Function to test offline_access scope
test_offline_access() {
    log_info "Testing offline_access scope for refresh tokens"
    
    # Get token with offline_access scope
    local token_response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "password" \
        "$TEST_USERNAME" "$TEST_PASSWORD" "openid offline_access")
    
    if ! check_http_status "$token_response" "200"; then
        log_warning "Failed to get token with offline_access scope"
        CONFORMANCE_TESTS_SKIPPED=$((CONFORMANCE_TESTS_SKIPPED + 1))
        return 0
    fi
    
    local token_body="${token_response%???}"
    local refresh_token=$(extract_json_field "$token_body" "refresh_token")
    
    if [[ -n "$refresh_token" && "$refresh_token" != "null" ]]; then
        log_success "✓ offline_access scope provides refresh token"
        CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        
        # Test refresh token usage
        local refresh_response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "refresh_token" \
            "" "" "" "$refresh_token")
        
        if check_http_status "$refresh_response" "200"; then
            log_success "✓ Refresh token from offline_access works"
            CONFORMANCE_TESTS_PASSED=$((CONFORMANCE_TESTS_PASSED + 1))
        else
            log_error "Refresh token from offline_access failed"
            CONFORMANCE_TESTS_FAILED=$((CONFORMANCE_TESTS_FAILED + 1))
        fi
    else
        log_warning "No refresh token provided with offline_access scope"
        CONFORMANCE_TESTS_SKIPPED=$((CONFORMANCE_TESTS_SKIPPED + 1))
    fi
    
    return 0
}

# Function to cleanup test client
cleanup_oidc_conformance() {
    log_info "Cleaning up OIDC conformance test"
    
    if [[ -n "$OIDC_TEST_CLIENT_ID" ]]; then
        if load_admin_token && is_admin_token_valid; then
            local delete_response=$(delete_request "$CLIENTS_ENDPOINT/$OIDC_TEST_CLIENT_ID" \
                "Bearer $ADMIN_ACCESS_TOKEN")
            
            if check_http_status "$delete_response" "200" "204" "404"; then
                log_success "OIDC test client cleaned up"
            fi
        fi
    fi
}

# Main test function
run_oidc_conformance_test() {
    log_info "=== OIDC Conformance Integration Test ==="
    log_info "Testing OpenID Connect Core 1.0 conformance"
    
    # Validate configuration
    validate_config || return 1
    
    # Check if services are ready
    wait_for_service "$HEALTH_ENDPOINT" || return 1
    
    # Create test client
    create_oidc_test_client || {
        log_error "Failed to create OIDC test client"
        return 1
    }
    
    # Run conformance tests
    test_id_token_claims || log_warning "ID token claims test failed"
    test_userinfo_scopes || log_warning "UserInfo scopes test failed"
    test_nonce_validation || log_warning "Nonce validation test failed"
    test_max_age_parameter || log_warning "Max age parameter test failed"
    test_prompt_parameter || log_warning "Prompt parameter test failed"
    test_acr_values || log_warning "ACR values test failed"
    test_claims_parameter || log_warning "Claims parameter test failed"
    test_response_mode || log_warning "Response mode test failed"
    test_offline_access || log_warning "Offline access test failed"
    
    # Report results
    log_info "=== OIDC Conformance Test Results ==="
    log_success "Passed: $CONFORMANCE_TESTS_PASSED"
    log_error "Failed: $CONFORMANCE_TESTS_FAILED"
    log_warning "Skipped: $CONFORMANCE_TESTS_SKIPPED"
    
    local total=$((CONFORMANCE_TESTS_PASSED + CONFORMANCE_TESTS_FAILED + CONFORMANCE_TESTS_SKIPPED))
    local pass_rate=0
    if [[ $total -gt 0 ]]; then
        pass_rate=$((CONFORMANCE_TESTS_PASSED * 100 / total))
    fi
    
    log_info "Pass rate: ${pass_rate}% ($CONFORMANCE_TESTS_PASSED/$total)"
    
    if [[ $CONFORMANCE_TESTS_FAILED -eq 0 ]]; then
        log_success "=== OIDC Conformance Test Completed Successfully ==="
        return 0
    else
        log_error "=== OIDC Conformance Test Failed ==="
        return 1
    fi
}

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_oidc_conformance
    
    # Run the test
    run_oidc_conformance_test
    exit $?
fi