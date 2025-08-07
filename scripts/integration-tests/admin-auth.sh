#!/bin/bash
# Admin Authentication Integration Test
# Tests admin login and JWT token acquisition

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"

# Global variables for token storage
ADMIN_ACCESS_TOKEN=""
ADMIN_REFRESH_TOKEN=""
ADMIN_TOKEN_FILE="/tmp/authly_admin_token.json"

# Admin authentication function
admin_login() {
    local username="$1"
    local password="$2"
    local scopes="${3:-admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:users:write admin:system:read}"
    
    log_info "Attempting admin login for user: $username"
    
    # Make login request using OAuth token request helper
    local response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "password" "$username" "$password" "$scopes")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Admin login failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    # Extract tokens
    ADMIN_ACCESS_TOKEN=$(extract_json_field "$body" "access_token")
    ADMIN_REFRESH_TOKEN=$(extract_json_field "$body" "refresh_token")
    local token_type=$(extract_json_field "$body" "token_type")
    local expires_in=$(extract_json_field "$body" "expires_in")
    local requires_password_change=$(extract_json_field "$body" "requires_password_change")
    
    # Validate token extraction
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        log_error "Failed to extract access token from response"
        return 1
    fi
    
    # Save token to file for use by other scripts
    local requires_password_change_json="${requires_password_change:-false}"
    cat > "$ADMIN_TOKEN_FILE" <<EOF
{
  "access_token": "$ADMIN_ACCESS_TOKEN",
  "refresh_token": "$ADMIN_REFRESH_TOKEN",
  "token_type": "$token_type",
  "expires_in": $expires_in,
  "acquired_at": "$(date +%s)",
  "requires_password_change": $requires_password_change_json
}
EOF
    
    log_success "Admin login successful"
    log_info "Token type: $token_type"
    log_info "Expires in: ${expires_in}s"
    log_info "Password change required: $requires_password_change"
    
    # Warn if password change is required
    if [[ "$requires_password_change" == "true" ]]; then
        log_warning "Admin password change is required on first login"
        log_warning "This may affect subsequent admin operations"
    fi
    
    return 0
}

# Function to refresh admin token
admin_refresh_token() {
    log_info "Refreshing admin access token"
    
    if [[ -z "$ADMIN_REFRESH_TOKEN" ]]; then
        log_error "No refresh token available"
        return 1
    fi
    
    # Make refresh request using OAuth token request helper
    local response=$(oauth_token_request "$AUTH_TOKEN_ENDPOINT" "refresh_token" "" "" "" "$ADMIN_REFRESH_TOKEN")
    
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Token refresh failed. Response: $body"
        return 1
    fi
    
    local body="${response%???}"
    ADMIN_ACCESS_TOKEN=$(extract_json_field "$body" "access_token")
    
    # Update token file
    local temp_file=$(mktemp)
    jq ".access_token = \"$ADMIN_ACCESS_TOKEN\" | .acquired_at = \"$(date +%s)\"" "$ADMIN_TOKEN_FILE" > "$temp_file"
    mv "$temp_file" "$ADMIN_TOKEN_FILE"
    
    log_success "Admin token refreshed successfully"
    return 0
}

# Function to validate admin token by checking admin endpoints
validate_admin_token() {
    log_info "Validating admin token by testing admin endpoints"
    
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        log_error "No admin access token available"
        return 1
    fi
    
    # Test admin health endpoint (no auth required, but may be localhost-restricted)
    local health_response=$(get_request "$ADMIN_HEALTH_ENDPOINT")
    if check_http_status "$health_response" "200"; then
        log_info "Admin health endpoint accessible"
    elif check_http_status "$health_response" "403"; then
        log_info "Admin health endpoint restricted to localhost (expected in some configurations)"
    else
        log_error "Admin health endpoint failed with unexpected status"
        return 1
    fi
    
    # Test admin scopes endpoint (requires admin:scopes:read)
    local scopes_response=$(get_request "$SCOPES_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$scopes_response" "200"; then
        local body="${scopes_response%???}"
        log_error "Admin scopes endpoint failed. Response: $body"
        return 1
    fi
    
    # Test admin clients endpoint (requires admin:clients:read)
    local clients_response=$(get_request "$CLIENTS_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$clients_response" "200"; then
        local body="${clients_response%???}"
        log_error "Admin clients endpoint failed. Response: $body"
        return 1
    fi
    
    log_success "Admin token validation successful"
    return 0
}

# Function to logout admin
admin_logout() {
    log_info "Logging out admin user"
    
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        log_warning "No active admin session to logout"
        return 0
    fi
    
    # Revoke access token
    local revoke_data=$(cat <<EOF
{
  "token": "$ADMIN_ACCESS_TOKEN",
  "token_type_hint": "access_token"
}
EOF
)
    
    local response=$(post_request "$AUTH_REVOKE_ENDPOINT" "$revoke_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Note: Token revocation might return 200 even if token is already invalid
    if check_http_status "$response" "200"; then
        log_success "Admin access token revoked successfully"
    else
        log_warning "Token revocation returned unexpected status, but continuing"
    fi
    
    # Clean up
    ADMIN_ACCESS_TOKEN=""
    ADMIN_REFRESH_TOKEN=""
    rm -f "$ADMIN_TOKEN_FILE"
    
    log_success "Admin logout completed"
    return 0
}

# Function to load existing token from file
load_admin_token() {
    if [[ -f "$ADMIN_TOKEN_FILE" ]]; then
        log_info "Loading existing admin token from file"
        
        ADMIN_ACCESS_TOKEN=$(jq -r '.access_token' "$ADMIN_TOKEN_FILE" 2>/dev/null || echo "")
        ADMIN_REFRESH_TOKEN=$(jq -r '.refresh_token' "$ADMIN_TOKEN_FILE" 2>/dev/null || echo "")
        
        if [[ -n "$ADMIN_ACCESS_TOKEN" && "$ADMIN_ACCESS_TOKEN" != "null" ]]; then
            log_success "Admin token loaded from file"
            return 0
        else
            log_warning "Invalid token file, removing it"
            rm -f "$ADMIN_TOKEN_FILE"
        fi
    fi
    
    return 1
}

# Function to check if admin token is still valid
is_admin_token_valid() {
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        return 1
    fi
    
    # Quick validation by calling a simple admin endpoint
    local response=$(get_request "$ADMIN_HEALTH_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    return $?
}

# Main test function
run_admin_auth_test() {
    log_info "=== Admin Authentication Integration Test ==="
    
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
    
    # Try to load existing token
    if load_admin_token && is_admin_token_valid; then
        log_info "Using existing valid admin token"
    else
        # Perform fresh login
        admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
    fi
    
    # Validate the token works
    validate_admin_token || return 1
    
    # Test token refresh (optional)
    if [[ -n "$ADMIN_REFRESH_TOKEN" ]]; then
        log_info "Testing token refresh functionality"
        admin_refresh_token || log_warning "Token refresh failed, but continuing"
        validate_admin_token || return 1
    fi
    
    log_success "=== Admin Authentication Test Completed Successfully ==="
    return 0
}

# Cleanup function
cleanup_admin_auth() {
    log_info "Cleaning up admin authentication test"
    admin_logout
}

# Export functions for use by other scripts
export ADMIN_TOKEN_FILE
export -f admin_login admin_refresh_token validate_admin_token admin_logout
export -f load_admin_token is_admin_token_valid

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_admin_auth
    
    # Run the test
    run_admin_auth_test
    exit $?
fi