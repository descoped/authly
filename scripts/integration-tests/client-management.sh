#!/bin/bash
# Client Management Integration Test
# Tests creating, retrieving, and managing OAuth clients via Admin API

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/admin-auth.sh"

# Global variables for test data
TEST_CLIENTS=()
TEST_CLIENT_COUNT=0

# Function to generate test client data
generate_test_client_data() {
    local client_suffix="${1:-$(generate_random_string 6)}"
    local client_name="${TEST_CLIENT_PREFIX}_${client_suffix}"
    local redirect_uri="${2:-http://localhost:8080/callback}"
    local client_type="${3:-public}"
    
    # Set appropriate auth method based on client type
    local auth_method="none"
    if [[ "$client_type" == "confidential" ]]; then
        auth_method="client_secret_post"
    fi
    
    cat <<EOF
{
  "client_name": "$client_name",
  "client_type": "$client_type",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["$redirect_uri"],
  "scopes": ["openid", "profile", "email"],
  "require_pkce": true,
  "token_endpoint_auth_method": "$auth_method",
  "application_type": "web"
}
EOF
}

# Function to create a test client via Admin API
create_test_client() {
    local client_data="$1"
    local description="${2:-test client}"
    
    log_info "Creating $description via Admin API"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client creation"
            return 1
        fi
    fi
    
    # Create client via Admin API
    local response=$(post_request "$CLIENTS_ENDPOINT" "$client_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status (200 or 201 are both valid for creation)
    if ! check_http_status "$response" "200" "201"; then
        local body="${response%???}"
        log_error "Client creation failed. Response: $body"
        return 1
    fi
    
    # Parse response to get client information
    local body="${response%???}"
    validate_json_response "$response"
    
    local client_id=$(extract_json_field "$body" "client_id")
    local client_name=$(extract_json_field "$body" "client_name")
    local client_secret=$(extract_json_field "$body" "client_secret")
    local client_type=$(extract_json_field "$body" "client_type")
    local created_at=$(extract_json_field "$body" "created_at")
    
    if [[ -z "$client_id" ]]; then
        log_error "Failed to extract client_id from creation response"
        return 1
    fi
    
    # Store client info for cleanup
    TEST_CLIENTS+=("$client_id")
    TEST_CLIENT_COUNT=$((TEST_CLIENT_COUNT + 1))
    
    log_success "Client created successfully:"
    log_info "  Client ID: $client_id"
    log_info "  Client Name: $client_name"
    log_info "  Client Type: $client_type"
    log_info "  Created at: $created_at"
    
    # Handle client secret (may be null for public clients)
    if [[ -n "$client_secret" && "$client_secret" != "null" ]]; then
        log_info "  Client Secret: $(echo "$client_secret" | sed 's/./*/g')"
        log_warning "  Client secret shown only once - save it now!"
    else
        log_info "  Client Secret: None (public client)"
    fi
    
    # Return client_id for further operations
    echo "$client_id"
    return 0
}

# Function to retrieve client by ID via Admin API
get_client_by_id() {
    local client_id="$1"
    
    log_info "Retrieving client by ID: $client_id"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client retrieval"
            return 1
        fi
    fi
    
    # Get client via Admin API
    local response=$(get_request "$CLIENTS_ENDPOINT/$client_id" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Client retrieval failed. Response: $body"
        return 1
    fi
    
    # Parse and validate response
    local body="${response%???}"
    validate_json_response "$response"
    
    local client_name=$(extract_json_field "$body" "client_name")
    local client_type=$(extract_json_field "$body" "client_type")
    local redirect_uris=$(extract_json_field "$body" "redirect_uris")
    local grant_types=$(extract_json_field "$body" "grant_types")
    local scopes=$(extract_json_field "$body" "scopes")
    local is_active=$(extract_json_field "$body" "is_active")
    
    log_success "Client retrieved successfully:"
    log_info "  Client Name: $client_name"
    log_info "  Client Type: $client_type"
    log_info "  Active: $is_active"
    log_info "  Grant Types: $grant_types"
    log_info "  Scopes: $scopes"
    log_info "  Redirect URIs: $redirect_uris"
    
    return 0
}

# Function to list clients via Admin API with pagination
list_clients() {
    local limit="${1:-10}"
    local offset="${2:-0}"
    local include_inactive="${3:-false}"
    
    log_info "Listing clients (limit: $limit, offset: $offset, include_inactive: $include_inactive)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client listing"
            return 1
        fi
    fi
    
    # List clients via Admin API
    local url="${CLIENTS_ENDPOINT}?limit=${limit}&offset=${offset}&include_inactive=${include_inactive}"
    local response=$(get_request "$url" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Client listing failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    # Extract pagination info (adjust based on actual API response format)
    local total_count=$(extract_json_field "$body" "total" 2>/dev/null || echo "unknown")
    local returned_count=$(echo "$body" | jq -r '.clients | length' 2>/dev/null || echo "unknown")
    
    log_success "Clients listed successfully"
    log_info "  Total count: $total_count"
    log_info "  Returned: $returned_count"
    log_info "  Limit: $limit, Offset: $offset"
    
    return 0
}

# Function to update client information via Admin API
update_test_client() {
    local client_id="$1"
    local update_data="$2"
    local description="${3:-client update}"
    
    log_info "Updating client $client_id ($description)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client update"
            return 1
        fi
    fi
    
    # Update client via Admin API
    local response=$(put_request "$CLIENTS_ENDPOINT/$client_id" "$update_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Client update failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    log_success "Client updated successfully"
    return 0
}

# Function to regenerate client secret via Admin API
regenerate_client_secret() {
    local client_id="$1"
    local description="${2:-client secret regeneration}"
    
    log_info "Regenerating secret for client $client_id ($description)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for secret regeneration"
            return 1
        fi
    fi
    
    # Regenerate secret via Admin API
    local response=$(post_request "$CLIENTS_ENDPOINT/$client_id/regenerate-secret" "{}" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Secret regeneration failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    local new_secret=$(extract_json_field "$body" "client_secret")
    
    if [[ -n "$new_secret" && "$new_secret" != "null" ]]; then
        log_success "Client secret regenerated successfully"
        log_info "  New Secret: $(echo "$new_secret" | sed 's/./*/g')"
        log_warning "  New secret shown only once - save it now!"
    else
        log_success "Secret regeneration completed (no secret returned - may be public client)"
    fi
    
    return 0
}

# Function to delete/deactivate client via Admin API
delete_test_client() {
    local client_id="$1"
    local description="${2:-test client}"
    
    log_info "Deleting $description (ID: $client_id)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client deletion"
            return 1
        fi
    fi
    
    # Delete client via Admin API
    local response=$(delete_request "$CLIENTS_ENDPOINT/$client_id" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status (might be 200, 204, or 404 if already deleted)
    if check_http_status "$response" "200" || check_http_status "$response" "204"; then
        log_success "Client deleted successfully"
        return 0
    elif check_http_status "$response" "404"; then
        log_warning "Client not found (may have been already deleted)"
        return 0
    else
        local body="${response%???}"
        log_error "Client deletion failed. Response: $body"
        return 1
    fi
}

# Function to test client creation with various scenarios
test_client_creation_scenarios() {
    log_info "Testing client creation scenarios"
    
    # Test 1: Create a public client
    log_info "Test 1: Creating public client"
    local public_client_data=$(generate_test_client_data "public" "http://localhost:8080/callback" "public")
    local public_client_id=$(create_test_client "$public_client_data" "public test client")
    
    if [[ -z "$public_client_id" ]]; then
        log_error "Failed to create public client"
        return 1
    fi
    
    # Test 2: Create a confidential client
    log_info "Test 2: Creating confidential client"
    local confidential_client_data=$(generate_test_client_data "confidential" "https://app.example.com/callback" "confidential")
    local confidential_client_id=$(create_test_client "$confidential_client_data" "confidential test client")
    
    if [[ -z "$confidential_client_id" ]]; then
        log_error "Failed to create confidential client"
        return 1
    fi
    
    # Test 3: Retrieve the created clients
    log_info "Test 3: Retrieving created clients"
    get_client_by_id "$public_client_id" || return 1
    get_client_by_id "$confidential_client_id" || return 1
    
    # Test 4: Create client with multiple redirect URIs
    log_info "Test 4: Creating client with multiple redirect URIs"
    local multi_redirect_data=$(cat <<EOF
{
  "client_name": "${TEST_CLIENT_PREFIX}_multi_redirect",
  "client_type": "public",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": [
    "http://localhost:8080/callback",
    "http://localhost:3000/auth/callback",
    "https://app.example.com/oauth/callback"
  ],
  "scopes": ["openid", "profile", "email"],
  "require_pkce": true,
  "token_endpoint_auth_method": "none",
  "application_type": "web"
}
EOF
)
    local multi_redirect_id=$(create_test_client "$multi_redirect_data" "client with multiple redirect URIs")
    
    if [[ -z "$multi_redirect_id" ]]; then
        log_warning "Failed to create client with multiple redirect URIs"
    fi
    
    # Test 5: Try to create client with invalid data (should fail)
    log_info "Test 5: Testing invalid client creation (should fail)"
    local invalid_data='{"client_name": "", "client_type": "invalid"}'
    local invalid_response=$(post_request "$CLIENTS_ENDPOINT" "$invalid_data" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$invalid_response" "400" || check_http_status "$invalid_response" "422"; then
        log_success "Invalid client creation properly rejected"
    else
        log_warning "Invalid client creation should have been rejected"
    fi
    
    log_success "Client creation scenarios completed"
    return 0
}

# Function to test client management operations
test_client_management_operations() {
    log_info "Testing client management operations"
    
    # Create a client for management testing
    local mgmt_client_data=$(generate_test_client_data "mgmt" "http://localhost:8080/test" "confidential")
    local mgmt_client_id=$(create_test_client "$mgmt_client_data" "management test client")
    
    if [[ -z "$mgmt_client_id" ]]; then
        log_error "Failed to create client for management testing"
        return 1
    fi
    
    # Test client update
    log_info "Testing client update"
    local update_data='{"client_uri": "https://updated.example.com", "contacts": ["admin@updated.example.com"]}'
    if update_test_client "$mgmt_client_id" "$update_data" "client metadata update"; then
        log_success "Client update test passed"
    else
        log_warning "Client update test failed"
    fi
    
    # Test secret regeneration (only for confidential clients)
    log_info "Testing client secret regeneration"
    if regenerate_client_secret "$mgmt_client_id" "test secret regeneration"; then
        log_success "Secret regeneration test passed"
    else
        log_warning "Secret regeneration test failed"
    fi
    
    # Test client listing
    log_info "Testing client listing"
    if list_clients 5 0 false; then
        log_success "Client listing test passed"
    else
        log_warning "Client listing test failed"
    fi
    
    # Test listing with inactive clients
    log_info "Testing client listing with inactive clients"
    if list_clients 10 0 true; then
        log_success "Client listing with inactive test passed"
    else
        log_warning "Client listing with inactive test failed"
    fi
    
    log_success "Client management operations completed"
    return 0
}

# Function to clean up test clients
cleanup_test_clients() {
    log_info "Cleaning up test clients"
    
    if [[ ${#TEST_CLIENTS[@]} -eq 0 ]]; then
        log_info "No test clients to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    for client_id in "${TEST_CLIENTS[@]}"; do
        if delete_test_client "$client_id" "test client $client_id"; then
            cleaned_count=$((cleaned_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    done
    
    log_info "Client cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    log_info "  Total: ${#TEST_CLIENTS[@]}"
    
    # Reset arrays
    TEST_CLIENTS=()
    TEST_CLIENT_COUNT=0
    
    return 0
}

# Main test function
run_client_management_test() {
    log_info "=== Client Management Integration Test ==="
    
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
    
    # Ensure admin authentication is available
    if ! load_admin_token || ! is_admin_token_valid; then
        log_info "Admin token not available, performing admin login"
        admin_login "$ADMIN_USERNAME" "$ADMIN_PASSWORD" || return 1
    fi
    
    # Verify client management endpoints are available
    log_info "Checking if client management endpoints are available"
    local test_response=$(get_request "$CLIENTS_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$test_response" "200"; then
        local body="${test_response%???}"
        log_error "Client management endpoints not available. Response: $body"
        return 1
    fi
    log_success "Client management endpoints are available"
    
    # Run client creation scenarios
    test_client_creation_scenarios || return 1
    
    # Run client management operations
    test_client_management_operations || return 1
    
    log_success "=== Client Management Test Completed Successfully ==="
    return 0
}

# Cleanup function
cleanup_client_management() {
    log_info "Cleaning up client management test"
    cleanup_test_clients
}

# Export functions for use by other scripts
export -f create_test_client get_client_by_id list_clients update_test_client
export -f regenerate_client_secret delete_test_client cleanup_test_clients generate_test_client_data

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_client_management
    
    # Run the test
    run_client_management_test
    exit $?
fi