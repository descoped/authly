#!/bin/bash
# OIDC Discovery Integration Test
# Tests OpenID Connect Discovery 1.0 endpoints and metadata

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"

# Test results tracking
DISCOVERY_TESTS_PASSED=0
DISCOVERY_TESTS_FAILED=0

# Function to test OpenID Configuration endpoint
test_openid_configuration() {
    log_info "Testing OpenID Connect Discovery endpoint"
    
    local response=$(get_request "$AUTHLY_BASE_URL/.well-known/openid-configuration")
    
    if ! check_http_status "$response" "200"; then
        log_error "OpenID Configuration endpoint failed"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    local body="${response%???}"
    validate_json_response "$response"
    
    # Check required fields per OIDC Discovery 1.0 spec
    local required_fields=(
        "issuer"
        "authorization_endpoint"
        "token_endpoint"
        "userinfo_endpoint"
        "jwks_uri"
        "response_types_supported"
        "subject_types_supported"
        "id_token_signing_alg_values_supported"
    )
    
    log_info "Validating required OpenID Configuration fields"
    for field in "${required_fields[@]}"; do
        local value=$(extract_json_field "$body" "$field")
        if [[ -z "$value" || "$value" == "null" ]]; then
            log_error "Missing required field: $field"
            DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        else
            log_success "✓ $field: $value"
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        fi
    done
    
    # Check recommended fields
    local recommended_fields=(
        "scopes_supported"
        "claims_supported"
        "grant_types_supported"
        "response_modes_supported"
        "token_endpoint_auth_methods_supported"
        "code_challenge_methods_supported"
    )
    
    log_info "Checking recommended OpenID Configuration fields"
    for field in "${recommended_fields[@]}"; do
        local value=$(extract_json_field "$body" "$field")
        if [[ -z "$value" || "$value" == "null" ]]; then
            log_warning "Missing recommended field: $field"
        else
            log_success "✓ $field present"
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        fi
    done
    
    # Validate issuer matches expected format
    local issuer=$(extract_json_field "$body" "issuer")
    local expected_issuer="$AUTHLY_BASE_URL"
    if [[ "$issuer" != "$expected_issuer" ]]; then
        log_warning "Issuer mismatch: got '$issuer', expected '$expected_issuer'"
    else
        log_success "✓ Issuer matches expected value"
        DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
    fi
    
    return 0
}

# Function to test OAuth 2.0 Authorization Server Metadata
test_oauth_discovery() {
    log_info "Testing OAuth 2.0 Authorization Server Metadata endpoint"
    
    local response=$(get_request "$AUTHLY_BASE_URL/.well-known/oauth-authorization-server")
    
    if ! check_http_status "$response" "200"; then
        log_error "OAuth Authorization Server Metadata endpoint failed"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    local body="${response%???}"
    validate_json_response "$response"
    
    # Check required fields per RFC 8414
    local required_fields=(
        "issuer"
        "authorization_endpoint"
        "token_endpoint"
        "response_types_supported"
    )
    
    log_info "Validating required OAuth metadata fields"
    for field in "${required_fields[@]}"; do
        local value=$(extract_json_field "$body" "$field")
        if [[ -z "$value" || "$value" == "null" ]]; then
            log_error "Missing required field: $field"
            DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        else
            log_success "✓ $field: $value"
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        fi
    done
    
    return 0
}

# Function to test JWKS endpoint
test_jwks_endpoint() {
    log_info "Testing JSON Web Key Set (JWKS) endpoint"
    
    local response=$(get_request "$AUTHLY_BASE_URL/.well-known/jwks.json")
    
    if ! check_http_status "$response" "200"; then
        log_error "JWKS endpoint failed"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    local body="${response%???}"
    validate_json_response "$response"
    
    # Check for keys array
    local keys=$(echo "$body" | jq -r '.keys' 2>/dev/null)
    if [[ -z "$keys" || "$keys" == "null" ]]; then
        log_error "JWKS endpoint missing 'keys' array"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    # Count keys
    local key_count=$(echo "$body" | jq '.keys | length' 2>/dev/null || echo "0")
    log_info "JWKS contains $key_count key(s)"
    
    if [[ $key_count -eq 0 ]]; then
        log_error "JWKS endpoint returned no keys"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    # Validate each key
    for i in $(seq 0 $((key_count - 1))); do
        local key=$(echo "$body" | jq ".keys[$i]" 2>/dev/null)
        local kty=$(echo "$key" | jq -r '.kty' 2>/dev/null)
        local use=$(echo "$key" | jq -r '.use' 2>/dev/null)
        local kid=$(echo "$key" | jq -r '.kid' 2>/dev/null)
        
        log_info "Key $i: kty=$kty, use=$use, kid=$kid"
        
        # Validate required fields
        if [[ -z "$kty" || "$kty" == "null" ]]; then
            log_error "Key $i missing 'kty' field"
            DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        else
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        fi
        
        if [[ "$kty" == "RSA" ]]; then
            # Check RSA-specific fields
            local n=$(echo "$key" | jq -r '.n' 2>/dev/null)
            local e=$(echo "$key" | jq -r '.e' 2>/dev/null)
            
            if [[ -z "$n" || "$n" == "null" ]]; then
                log_error "RSA key $i missing 'n' field"
                DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
            else
                log_success "✓ RSA key has modulus"
                DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
            fi
            
            if [[ -z "$e" || "$e" == "null" ]]; then
                log_error "RSA key $i missing 'e' field"
                DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
            else
                log_success "✓ RSA key has exponent"
                DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
            fi
        fi
    done
    
    log_success "JWKS endpoint validation completed"
    return 0
}

# Function to test endpoint consistency
test_endpoint_consistency() {
    log_info "Testing endpoint consistency between discovery documents"
    
    # Get both discovery documents
    local oidc_response=$(get_request "$AUTHLY_BASE_URL/.well-known/openid-configuration")
    local oauth_response=$(get_request "$AUTHLY_BASE_URL/.well-known/oauth-authorization-server")
    
    if ! check_http_status "$oidc_response" "200" || ! check_http_status "$oauth_response" "200"; then
        log_error "Failed to fetch discovery documents for consistency check"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    local oidc_body="${oidc_response%???}"
    local oauth_body="${oauth_response%???}"
    
    # Compare common endpoints
    local endpoints=("issuer" "authorization_endpoint" "token_endpoint")
    
    for endpoint in "${endpoints[@]}"; do
        local oidc_value=$(extract_json_field "$oidc_body" "$endpoint")
        local oauth_value=$(extract_json_field "$oauth_body" "$endpoint")
        
        if [[ "$oidc_value" != "$oauth_value" ]]; then
            log_error "Endpoint mismatch for $endpoint:"
            log_error "  OIDC:  $oidc_value"
            log_error "  OAuth: $oauth_value"
            DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        else
            log_success "✓ $endpoint consistent across discovery documents"
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        fi
    done
    
    return 0
}

# Function to test CORS headers on discovery endpoints
test_discovery_cors() {
    log_info "Testing CORS headers on discovery endpoints"
    
    local endpoints=(
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/.well-known/jwks.json"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log_info "Testing CORS for $endpoint"
        
        # Make OPTIONS request to check CORS
        local response=$(curl -s -X OPTIONS \
            -H "Origin: https://example.com" \
            -H "Access-Control-Request-Method: GET" \
            -w "\n%{http_code}" \
            "$AUTHLY_BASE_URL$endpoint" 2>/dev/null || echo "000")
        
        local status="${response: -3}"
        
        if [[ "$status" == "200" || "$status" == "204" ]]; then
            log_success "✓ CORS preflight successful for $endpoint"
            DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
        else
            log_warning "CORS preflight returned $status for $endpoint (may be intentionally disabled)"
        fi
    done
    
    return 0
}

# Function to validate endpoint URLs in discovery
test_endpoint_urls() {
    log_info "Validating that discovered endpoints are accessible"
    
    local response=$(get_request "$AUTHLY_BASE_URL/.well-known/openid-configuration")
    if ! check_http_status "$response" "200"; then
        log_error "Failed to fetch OpenID Configuration"
        DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
        return 1
    fi
    
    local body="${response%???}"
    
    # Extract and test key endpoints
    local endpoints=(
        "authorization_endpoint"
        "token_endpoint"
        "userinfo_endpoint"
        "jwks_uri"
    )
    
    for endpoint_name in "${endpoints[@]}"; do
        local endpoint_url=$(extract_json_field "$body" "$endpoint_name")
        
        if [[ -z "$endpoint_url" || "$endpoint_url" == "null" ]]; then
            log_error "Missing endpoint URL for $endpoint_name"
            DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
            continue
        fi
        
        # Convert relative URLs to absolute
        if [[ "$endpoint_url" == /* ]]; then
            endpoint_url="$AUTHLY_BASE_URL$endpoint_url"
        fi
        
        # Test if endpoint is reachable
        # Use HEAD for most endpoints, but GET for JWKS
        if [[ "$endpoint_name" == "jwks_uri" ]]; then
            local test_response=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint_url" 2>/dev/null)
        else
            local test_response=$(curl -s -I -w "%{http_code}" "$endpoint_url" 2>/dev/null | tail -1)
        fi
        
        # Different endpoints have different expected responses
        case "$endpoint_name" in
            "authorization_endpoint")
                # Should return 400 or 302 without parameters
                if [[ "$test_response" == "400" || "$test_response" == "302" ]]; then
                    log_success "✓ $endpoint_name is accessible"
                    DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
                else
                    log_warning "$endpoint_name returned $test_response (expected 400 or 302)"
                fi
                ;;
            "token_endpoint")
                # Should return 405 for GET or 400/401 for POST without body
                if [[ "$test_response" == "405" || "$test_response" == "400" || "$test_response" == "401" ]]; then
                    log_success "✓ $endpoint_name is accessible"
                    DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
                else
                    log_warning "$endpoint_name returned $test_response"
                fi
                ;;
            "userinfo_endpoint")
                # Should return 401 without authorization
                if [[ "$test_response" == "401" ]]; then
                    log_success "✓ $endpoint_name requires authentication (expected)"
                    DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
                else
                    log_warning "$endpoint_name returned $test_response (expected 401)"
                fi
                ;;
            "jwks_uri")
                # Should return 200
                if [[ "$test_response" == "200" ]]; then
                    log_success "✓ $endpoint_name is accessible"
                    DISCOVERY_TESTS_PASSED=$((DISCOVERY_TESTS_PASSED + 1))
                else
                    log_error "$endpoint_name returned $test_response (expected 200)"
                    DISCOVERY_TESTS_FAILED=$((DISCOVERY_TESTS_FAILED + 1))
                fi
                ;;
        esac
    done
    
    return 0
}

# Main test function
run_oidc_discovery_test() {
    log_info "=== OIDC Discovery Integration Test ==="
    
    # Validate configuration
    validate_config || return 1
    
    # Check if services are ready
    wait_for_service "$HEALTH_ENDPOINT" || return 1
    
    # Run discovery tests
    test_openid_configuration || log_warning "OpenID Configuration test failed"
    test_oauth_discovery || log_warning "OAuth Discovery test failed"
    test_jwks_endpoint || log_warning "JWKS endpoint test failed"
    test_endpoint_consistency || log_warning "Endpoint consistency test failed"
    test_discovery_cors || log_warning "CORS test failed"
    test_endpoint_urls || log_warning "Endpoint URL validation failed"
    
    # Report results
    log_info "=== OIDC Discovery Test Results ==="
    log_success "Passed: $DISCOVERY_TESTS_PASSED"
    log_error "Failed: $DISCOVERY_TESTS_FAILED"
    
    if [[ $DISCOVERY_TESTS_FAILED -eq 0 ]]; then
        log_success "=== OIDC Discovery Test Completed Successfully ==="
        return 0
    else
        log_error "=== OIDC Discovery Test Failed ==="
        return 1
    fi
}

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_oidc_discovery_test
    exit $?
fi