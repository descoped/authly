#!/bin/bash
# User Authentication Integration Test
# Tests OAuth 2.1 password grant flow and OpenID Connect user authentication

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"

# Global variables for token storage
USER_ACCESS_TOKEN=""
USER_REFRESH_TOKEN=""
USER_ID_TOKEN=""
USER_TOKEN_FILE="/tmp/authly_user_token.json"

# Test user credentials (using admin as verified user)
TEST_USERNAME="${TEST_USER_USERNAME:-admin}"
TEST_PASSWORD="${TEST_USER_PASSWORD:-${AUTHLY_ADMIN_PASSWORD}}"
TEST_SCOPES="${TEST_USER_SCOPES:-openid profile email}"

# Function to authenticate user via password grant
user_login() {
    local username="${1:-$TEST_USERNAME}"
    local password="${2:-$TEST_PASSWORD}"
    local scopes="${3:-$TEST_SCOPES}"
    
    log_info "Attempting user login for: $username"
    
    # Make authentication request using OAuth token request helper
    local response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "password" "$username" "$password" "$scopes")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "User login failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    # Extract token information
    USER_ACCESS_TOKEN=$(extract_json_field "$body" "access_token")
    USER_REFRESH_TOKEN=$(extract_json_field "$body" "refresh_token")
    local token_type=$(extract_json_field "$body" "token_type")
    local expires_in=$(extract_json_field "$body" "expires_in")
    USER_ID_TOKEN=$(extract_json_field "$body" "id_token")
    local requires_password_change=$(extract_json_field "$body" "requires_password_change")
    
    # Validate token extraction
    if [[ -z "$USER_ACCESS_TOKEN" ]]; then
        log_error "Failed to extract access token from response"
        return 1
    fi
    
    # Save token to file for use by other scripts
    local requires_password_change_json="${requires_password_change:-null}"
    local id_token_json="${USER_ID_TOKEN:-null}"
    if [[ "$id_token_json" != "null" && -n "$id_token_json" ]]; then
        id_token_json="\"$USER_ID_TOKEN\""
    fi
    
    cat > "$USER_TOKEN_FILE" <<EOF
{
  "access_token": "$USER_ACCESS_TOKEN",
  "refresh_token": "$USER_REFRESH_TOKEN",
  "id_token": $id_token_json,
  "token_type": "$token_type",
  "expires_in": $expires_in,
  "acquired_at": "$(date +%s)",
  "requires_password_change": $requires_password_change_json,
  "username": "$username",
  "scopes": "$scopes"
}
EOF
    
    log_success "User login successful"
    log_info "Token type: $token_type"
    log_info "Expires in: ${expires_in}s"
    log_info "ID Token: $(if [[ -n "$USER_ID_TOKEN" ]]; then echo "Present"; else echo "Not present"; fi)"
    log_info "Password change required: $requires_password_change_json"
    
    return 0
}

# Function to refresh user access token
user_refresh_token() {
    log_info "Refreshing user access token"
    
    if [[ -z "$USER_REFRESH_TOKEN" ]]; then
        log_error "No refresh token available"
        return 1
    fi
    
    # Make refresh request using OAuth token request helper
    local response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "refresh_token" "" "" "" "$USER_REFRESH_TOKEN")
    
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Token refresh failed. Response: $body"
        return 1
    fi
    
    local body="${response%???}"
    USER_ACCESS_TOKEN=$(extract_json_field "$body" "access_token")
    
    # Update token file
    local temp_file=$(mktemp)
    jq ".access_token = \"$USER_ACCESS_TOKEN\" | .acquired_at = \"$(date +%s)\"" "$USER_TOKEN_FILE" > "$temp_file"
    mv "$temp_file" "$USER_TOKEN_FILE"
    
    log_success "User token refreshed successfully"
    return 0
}

# Function to validate user token by testing userinfo endpoint
validate_user_token() {
    log_info "Validating user token via UserInfo endpoint"
    
    if [[ -z "$USER_ACCESS_TOKEN" ]]; then
        log_error "No access token available for validation"
        return 1
    fi
    
    # Test UserInfo endpoint
    local response=$(get_request "$USERINFO_ENDPOINT" "Bearer $USER_ACCESS_TOKEN")
    
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "UserInfo request failed. Response: $body"
        return 1
    fi
    
    local body="${response%???}"
    validate_json_response "$response"
    
    # Extract user information
    local sub=$(extract_json_field "$body" "sub")
    local preferred_username=$(extract_json_field "$body" "preferred_username")
    local email=$(extract_json_field "$body" "email")
    local email_verified=$(extract_json_field "$body" "email_verified")
    
    log_success "User token validation successful"
    log_info "Subject (sub): $sub"
    log_info "Username: $preferred_username"
    log_info "Email: $email"
    log_info "Email verified: $email_verified"
    
    return 0
}

# Function to test ID token structure (basic validation)
validate_id_token() {
    if [[ -z "$USER_ID_TOKEN" || "$USER_ID_TOKEN" == "null" ]]; then
        log_warning "No ID token present to validate"
        return 0
    fi
    
    log_info "Validating ID token structure"
    
    # Basic JWT structure validation (3 parts separated by dots)
    local dot_count=$(echo "$USER_ID_TOKEN" | grep -o '\.' | wc -l)
    if [[ $dot_count -ne 2 ]]; then
        log_error "Invalid ID token structure - expected 3 parts separated by dots"
        return 1
    fi
    
    # Extract header and payload (decode base64url)
    local header=$(echo "$USER_ID_TOKEN" | cut -d'.' -f1)
    local payload=$(echo "$USER_ID_TOKEN" | cut -d'.' -f2)
    
    # Add padding if needed for base64 decoding
    local header_padded=$(printf "%s%s" "$header" "$(printf '%*s' $(((4 - ${#header} % 4) % 4)) | tr ' ' '=')")
    local payload_padded=$(printf "%s%s" "$payload" "$(printf '%*s' $(((4 - ${#payload} % 4) % 4)) | tr ' ' '=')")
    
    # Decode and validate JSON structure
    local header_json=$(echo "$header_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
    local payload_json=$(echo "$payload_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
    
    if ! echo "$header_json" | jq . >/dev/null 2>&1; then
        log_error "Invalid ID token header JSON"
        return 1
    fi
    
    if ! echo "$payload_json" | jq . >/dev/null 2>&1; then
        log_error "Invalid ID token payload JSON"
        return 1
    fi
    
    # Extract key claims
    local alg=$(echo "$header_json" | jq -r '.alg // "none"')
    local typ=$(echo "$header_json" | jq -r '.typ // "none"')
    local iss=$(echo "$payload_json" | jq -r '.iss // "none"')
    local aud=$(echo "$payload_json" | jq -r '.aud // "none"')
    local sub=$(echo "$payload_json" | jq -r '.sub // "none"')
    local exp=$(echo "$payload_json" | jq -r '.exp // "none"')
    
    log_success "ID token structure validation successful"
    log_info "Algorithm: $alg"
    log_info "Type: $typ"
    log_info "Issuer: $iss"
    log_info "Audience: $aud"
    log_info "Subject: $sub"
    log_info "Expires: $exp"
    
    return 0
}

# Function to revoke user tokens
user_logout() {
    log_info "Logging out user and revoking tokens"
    
    local revoked_count=0
    local failed_count=0
    
    # Revoke access token
    if [[ -n "$USER_ACCESS_TOKEN" ]]; then
        local revoke_data=$(cat <<EOF
{
  "token": "$USER_ACCESS_TOKEN",
  "token_type_hint": "access_token"
}
EOF
)
        
        local response=$(post_request "$AUTH_REVOKE_ENDPOINT" "$revoke_data")
        if check_http_status "$response" "200"; then
            log_success "Access token revoked successfully"
            revoked_count=$((revoked_count + 1))
        else
            log_error "Failed to revoke access token"
            failed_count=$((failed_count + 1))
        fi
    fi
    
    # Revoke refresh token
    if [[ -n "$USER_REFRESH_TOKEN" ]]; then
        local revoke_data=$(cat <<EOF
{
  "token": "$USER_REFRESH_TOKEN",
  "token_type_hint": "refresh_token"
}
EOF
)
        
        local response=$(post_request "$AUTH_REVOKE_ENDPOINT" "$revoke_data")
        if check_http_status "$response" "200"; then
            log_success "Refresh token revoked successfully"
            revoked_count=$((revoked_count + 1))
        else
            log_error "Failed to revoke refresh token"
            failed_count=$((failed_count + 1))
        fi
    fi
    
    # Clean up
    USER_ACCESS_TOKEN=""
    USER_REFRESH_TOKEN=""
    USER_ID_TOKEN=""
    rm -f "$USER_TOKEN_FILE"
    
    log_info "Token revocation completed:"
    log_info "  Revoked: $revoked_count"
    log_info "  Failed: $failed_count"
    
    if [[ $failed_count -eq 0 ]]; then
        log_success "User logout completed successfully"
        return 0
    else
        log_warning "User logout completed with some failures"
        return 1
    fi
}

# Function to load existing token from file
load_user_token() {
    if [[ -f "$USER_TOKEN_FILE" ]]; then
        log_info "Loading existing user token from file"
        
        USER_ACCESS_TOKEN=$(jq -r '.access_token' "$USER_TOKEN_FILE" 2>/dev/null || echo "")
        USER_REFRESH_TOKEN=$(jq -r '.refresh_token' "$USER_TOKEN_FILE" 2>/dev/null || echo "")
        USER_ID_TOKEN=$(jq -r '.id_token' "$USER_TOKEN_FILE" 2>/dev/null || echo "")
        
        if [[ -n "$USER_ACCESS_TOKEN" && "$USER_ACCESS_TOKEN" != "null" ]]; then
            log_success "User token loaded from file"
            return 0
        else
            log_warning "Invalid token file, removing it"
            rm -f "$USER_TOKEN_FILE"
        fi
    fi
    
    log_info "No valid user token file found"
    return 1
}

# Function to check if user token is valid
is_user_token_valid() {
    if [[ -z "$USER_ACCESS_TOKEN" ]]; then
        return 1
    fi
    
    # Quick validation by testing UserInfo endpoint
    local response=$(get_request "$USERINFO_ENDPOINT" "Bearer $USER_ACCESS_TOKEN")
    check_http_status "$response" "200"
}

# Function to test scope-specific claims
test_scope_claims() {
    log_info "Testing scope-specific claims in UserInfo response"
    
    if [[ -z "$USER_ACCESS_TOKEN" ]]; then
        log_error "No access token available for scope testing"
        return 1
    fi
    
    local response=$(get_request "$USERINFO_ENDPOINT" "Bearer $USER_ACCESS_TOKEN")
    
    if ! check_http_status "$response" "200"; then
        log_error "UserInfo request failed for scope testing"
        return 1
    fi
    
    local body="${response%???}"
    local scopes=(${TEST_SCOPES})
    
    log_info "Testing claims for scopes: ${scopes[*]}"
    
    for scope in "${scopes[@]}"; do
        case "$scope" in
            "openid")
                local sub=$(extract_json_field "$body" "sub")
                if [[ -n "$sub" ]]; then
                    log_success "✓ openid scope: 'sub' claim present"
                else
                    log_error "✗ openid scope: 'sub' claim missing"
                fi
                ;;
            "profile")
                local name=$(extract_json_field "$body" "name")
                local preferred_username=$(extract_json_field "$body" "preferred_username")
                if [[ -n "$name" || -n "$preferred_username" ]]; then
                    log_success "✓ profile scope: profile claims present"
                else
                    log_warning "? profile scope: profile claims may be empty"
                fi
                ;;
            "email")
                local email=$(extract_json_field "$body" "email")
                if [[ -n "$email" ]]; then
                    log_success "✓ email scope: 'email' claim present"
                else
                    log_warning "? email scope: 'email' claim missing or empty"
                fi
                ;;
            "phone")
                local phone_number=$(extract_json_field "$body" "phone_number")
                if [[ -n "$phone_number" ]]; then
                    log_success "✓ phone scope: 'phone_number' claim present"
                else
                    log_info "○ phone scope: 'phone_number' claim not present (may be empty)"
                fi
                ;;
            "address")
                local address=$(extract_json_field "$body" "address")
                if [[ -n "$address" ]]; then
                    log_success "✓ address scope: 'address' claim present"
                else
                    log_info "○ address scope: 'address' claim not present (may be empty)"
                fi
                ;;
        esac
    done
    
    log_success "Scope claims testing completed"
    return 0
}

# Function to cleanup user authentication test
cleanup_user_auth() {
    log_info "Cleaning up user authentication test"
    user_logout >/dev/null 2>&1 || true
}

# Main test function
run_user_auth_test() {
    log_info "=== User Authentication Integration Test ==="
    
    # Validate configuration
    validate_config || return 1
    
    # Check if services are ready
    wait_for_service "$HEALTH_ENDPOINT" || return 1
    
    # Skip Docker service checks if SKIP_DOCKER_CHECK is set
    if [[ "${SKIP_DOCKER_CHECK:-false}" != "true" ]]; then
        check_docker_services || return 1
    else
        log_info "Skipping Docker service checks (SKIP_DOCKER_CHECK=true)"
    fi
    
    # Test 1: User Login (Password Grant)
    log_info "Test 1: User authentication via password grant"
    user_login "$TEST_USERNAME" "$TEST_PASSWORD" "$TEST_SCOPES" || return 1
    
    # Test 2: Token Validation via UserInfo
    log_info "Test 2: Token validation via UserInfo endpoint"
    validate_user_token || return 1
    
    # Test 3: ID Token Validation (if present)
    log_info "Test 3: ID token structure validation"
    validate_id_token || return 1
    
    # Test 4: Scope-specific Claims Testing
    log_info "Test 4: Scope-specific claims testing"
    test_scope_claims || return 1
    
    # Test 5: Token Refresh
    log_info "Test 5: Token refresh functionality"
    if user_refresh_token; then
        log_success "Token refresh test passed"
        
        # Re-validate refreshed token
        log_info "Validating refreshed token"
        validate_user_token || return 1
    else
        log_warning "Token refresh test failed"
    fi
    
    log_success "=== User Authentication Test Completed Successfully ==="
    return 0
}

# Export functions for use by other scripts
export USER_TOKEN_FILE
export -f user_login user_refresh_token validate_user_token user_logout
export -f load_user_token is_user_token_valid validate_id_token test_scope_claims

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_user_auth
    
    # Run the test
    run_user_auth_test
    exit $?
fi