#!/bin/bash
# Scope Management Integration Test
# Tests creating, retrieving, and managing OAuth scopes via Admin API

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/admin-auth.sh"

# Global variables for test data
TEST_SCOPES=()
TEST_SCOPE_COUNT=0

# Function to generate test scope data
generate_test_scope_data() {
    local scope_suffix="${1:-$(generate_random_string 6)}"
    local scope_name="${TEST_SCOPE_PREFIX}:${scope_suffix}"
    local description="${2:-Test scope for integration testing}"
    local is_default="${3:-false}"
    
    cat <<EOF
{
  "scope_name": "$scope_name",
  "description": "$description",
  "is_default": $is_default,
  "is_active": true
}
EOF
}

# Function to create a test scope via Admin API
create_test_scope() {
    local scope_data="$1"
    local description="${2:-test scope}"
    
    log_info "Creating $description via Admin API"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope creation"
            return 1
        fi
    fi
    
    # Create scope via Admin API
    local response=$(post_request "$SCOPES_ENDPOINT" "$scope_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status (200 or 201 are both valid for creation)
    if ! check_http_status "$response" "200" "201"; then
        local body="${response%???}"
        log_error "Scope creation failed. Response: $body"
        return 1
    fi
    
    # Parse response to get scope information
    local body="${response%???}"
    validate_json_response "$response"
    
    local scope_name=$(extract_json_field "$body" "scope_name")
    local description_field=$(extract_json_field "$body" "description")
    local is_default=$(extract_json_field "$body" "is_default")
    local is_active=$(extract_json_field "$body" "is_active")
    local created_at=$(extract_json_field "$body" "created_at")
    
    if [[ -z "$scope_name" ]]; then
        log_error "Failed to extract scope_name from creation response"
        return 1
    fi
    
    # Store scope info for cleanup
    TEST_SCOPES+=("$scope_name")
    TEST_SCOPE_COUNT=$((TEST_SCOPE_COUNT + 1))
    
    log_success "Scope created successfully:"
    log_info "  Scope Name: $scope_name"
    log_info "  Description: $description_field"
    log_info "  Is Default: $is_default"
    log_info "  Is Active: $is_active"
    log_info "  Created at: $created_at"
    
    # Return scope_name for further operations
    echo "$scope_name"
    return 0
}

# Function to retrieve scope by name via Admin API
get_scope_by_name() {
    local scope_name="$1"
    
    log_info "Retrieving scope by name: $scope_name"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope retrieval"
            return 1
        fi
    fi
    
    # Get scope via Admin API
    local response=$(get_request "$SCOPES_ENDPOINT/$scope_name" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Scope retrieval failed. Response: $body"
        return 1
    fi
    
    # Parse and validate response
    local body="${response%???}"
    validate_json_response "$response"
    
    local description=$(extract_json_field "$body" "description")
    local is_default=$(extract_json_field "$body" "is_default")
    local is_active=$(extract_json_field "$body" "is_active")
    
    log_success "Scope retrieved successfully:"
    log_info "  Scope Name: $scope_name"
    log_info "  Description: $description"
    log_info "  Is Default: $is_default"
    log_info "  Is Active: $is_active"
    
    return 0
}

# Function to list scopes via Admin API with pagination
list_scopes() {
    local limit="${1:-10}"
    local offset="${2:-0}"
    local include_inactive="${3:-false}"
    local default_only="${4:-false}"
    
    log_info "Listing scopes (limit: $limit, offset: $offset, include_inactive: $include_inactive, default_only: $default_only)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope listing"
            return 1
        fi
    fi
    
    # List scopes via Admin API
    local url="${SCOPES_ENDPOINT}?limit=${limit}&offset=${offset}&include_inactive=${include_inactive}&default_only=${default_only}"
    local response=$(get_request "$url" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Scope listing failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    # Extract pagination info (adjust based on actual API response format)
    local total_count=$(extract_json_field "$body" "total" 2>/dev/null || echo "unknown")
    local returned_count=$(echo "$body" | jq -r '. | length' 2>/dev/null || echo "unknown")
    
    log_success "Scopes listed successfully"
    log_info "  Total count: $total_count"
    log_info "  Returned: $returned_count"
    log_info "  Limit: $limit, Offset: $offset"
    
    return 0
}

# Function to get default scopes via Admin API
get_default_scopes() {
    log_info "Retrieving default scopes"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for default scopes retrieval"
            return 1
        fi
    fi
    
    # Get default scopes via Admin API
    local response=$(get_request "$SCOPES_ENDPOINT/defaults" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Default scopes retrieval failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    local default_count=$(echo "$body" | jq -r '. | length' 2>/dev/null || echo "unknown")
    
    log_success "Default scopes retrieved successfully"
    log_info "  Default scopes count: $default_count"
    
    # Log some default scope names
    if [[ "$default_count" != "unknown" && "$default_count" -gt 0 ]]; then
        local scope_names=$(echo "$body" | jq -r '.[].scope_name' 2>/dev/null | head -5)
        log_info "  Sample scopes: $(echo "$scope_names" | tr '\n' ' ')"
    fi
    
    return 0
}

# Function to update scope information via Admin API
update_test_scope() {
    local scope_name="$1"
    local update_data="$2"
    local description="${3:-scope update}"
    
    log_info "Updating scope $scope_name ($description)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope update"
            return 1
        fi
    fi
    
    # Update scope via Admin API
    local response=$(put_request "$SCOPES_ENDPOINT/$scope_name" "$update_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "Scope update failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    log_success "Scope updated successfully"
    return 0
}

# Function to delete/deactivate scope via Admin API
delete_test_scope() {
    local scope_name="$1"
    local description="${2:-test scope}"
    
    log_info "Deleting $description (Name: $scope_name)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope deletion"
            return 1
        fi
    fi
    
    # Delete scope via Admin API
    local response=$(delete_request "$SCOPES_ENDPOINT/$scope_name" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status (might be 200, 204, or 404 if already deleted)
    if check_http_status "$response" "200" "204"; then
        log_success "Scope deleted successfully"
        return 0
    elif check_http_status "$response" "404"; then
        log_warning "Scope not found (may have been already deleted)"
        return 0
    else
        local body="${response%???}"
        log_error "Scope deletion failed. Response: $body"
        return 1
    fi
}

# Function to test scope creation with various scenarios
test_scope_creation_scenarios() {
    log_info "Testing scope creation scenarios"
    
    # Test 1: Create a basic scope
    log_info "Test 1: Creating basic scope"
    local basic_scope_data=$(generate_test_scope_data "" "Read access to resources" "false")
    local basic_scope_name=$(create_test_scope "$basic_scope_data" "basic test scope")
    
    if [[ -z "$basic_scope_name" ]]; then
        log_error "Failed to create basic scope"
        return 1
    fi
    
    # Test 2: Create a default scope
    log_info "Test 2: Creating default scope"
    local default_scope_data=$(generate_test_scope_data "" "Default scope for testing" "true")
    local default_scope_name=$(create_test_scope "$default_scope_data" "default test scope")
    
    if [[ -z "$default_scope_name" ]]; then
        log_warning "Failed to create default scope (may not be allowed)"
    fi
    
    # Test 3: Retrieve the created scopes
    log_info "Test 3: Retrieving created scopes"
    get_scope_by_name "$basic_scope_name" || return 1
    
    if [[ -n "$default_scope_name" ]]; then
        get_scope_by_name "$default_scope_name" || log_warning "Failed to retrieve default scope"
    fi
    
    # Test 4: Create scope with special characters
    log_info "Test 4: Creating scope with namespaced name"
    local namespaced_scope_data=$(generate_test_scope_data "" "Namespaced scope" "false")
    local namespaced_scope_name=$(create_test_scope "$namespaced_scope_data" "namespaced test scope")
    
    if [[ -z "$namespaced_scope_name" ]]; then
        log_warning "Failed to create namespaced scope (may not be supported)"
    fi
    
    # Test 5: Try to create duplicate scope (should fail)
    log_info "Test 5: Testing duplicate scope creation (should fail)"
    local duplicate_response=$(post_request "$SCOPES_ENDPOINT" "$basic_scope_data" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$duplicate_response" "400" "409"; then
        log_success "Duplicate scope creation properly rejected"
    else
        log_warning "Duplicate scope creation should have been rejected"
    fi
    
    log_success "Scope creation scenarios completed"
    return 0
}

# Function to test scope management operations
test_scope_management_operations() {
    log_info "Testing scope management operations"
    
    # Create a scope for management testing
    local mgmt_scope_data=$(generate_test_scope_data "" "Management test scope" "false")
    local mgmt_scope_name=$(create_test_scope "$mgmt_scope_data" "management test scope")
    
    if [[ -z "$mgmt_scope_name" ]]; then
        log_error "Failed to create scope for management testing"
        return 1
    fi
    
    # Test scope update
    log_info "Testing scope update"
    local update_data='{"description": "Updated scope description", "is_active": true}'
    if update_test_scope "$mgmt_scope_name" "$update_data" "description update"; then
        log_success "Scope update test passed"
    else
        log_warning "Scope update test failed"
    fi
    
    # Test scope listing
    log_info "Testing scope listing"
    if list_scopes 5 0 false false; then
        log_success "Scope listing test passed"
    else
        log_warning "Scope listing test failed"
    fi
    
    # Test default scopes retrieval
    log_info "Testing default scopes retrieval"
    if get_default_scopes; then
        log_success "Default scopes retrieval test passed"
    else
        log_warning "Default scopes retrieval test failed"
    fi
    
    # Test listing with default only filter
    log_info "Testing scope listing with default only filter"
    if list_scopes 10 0 false true; then
        log_success "Default-only scope listing test passed"
    else
        log_warning "Default-only scope listing test failed"
    fi
    
    log_success "Scope management operations completed"
    return 0
}

# Function to verify standard OIDC scopes exist
verify_standard_scopes() {
    log_info "Verifying standard OIDC scopes exist"
    
    local standard_scopes=("openid" "profile" "email" "address" "phone")
    local found_count=0
    local missing_scopes=()
    
    for scope in "${standard_scopes[@]}"; do
        if get_scope_by_name "$scope" >/dev/null 2>&1; then
            found_count=$((found_count + 1))
            log_info "  ✓ Standard scope '$scope' exists"
        else
            missing_scopes+=("$scope")
            log_warning "  ✗ Standard scope '$scope' missing"
        fi
    done
    
    log_info "Standard scope verification:"
    log_info "  Found: $found_count/${#standard_scopes[@]}"
    
    if [[ ${#missing_scopes[@]} -gt 0 ]]; then
        log_warning "  Missing: ${missing_scopes[*]}"
    fi
    
    return 0
}

# Function to clean up test scopes
cleanup_test_scopes() {
    log_info "Cleaning up test scopes"
    
    if [[ ${#TEST_SCOPES[@]} -eq 0 ]]; then
        log_info "No test scopes to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    for scope_name in "${TEST_SCOPES[@]}"; do
        if delete_test_scope "$scope_name" "test scope $scope_name"; then
            cleaned_count=$((cleaned_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    done
    
    log_info "Scope cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    log_info "  Total: ${#TEST_SCOPES[@]}"
    
    # Reset arrays
    TEST_SCOPES=()
    TEST_SCOPE_COUNT=0
    
    return 0
}

# Main test function
run_scope_management_test() {
    log_info "=== Scope Management Integration Test ==="
    
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
        admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
    fi
    
    # Verify scope management endpoints are available
    log_info "Checking if scope management endpoints are available"
    local test_response=$(get_request "$SCOPES_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$test_response" "200"; then
        local body="${test_response%???}"
        log_error "Scope management endpoints not available. Response: $body"
        return 1
    fi
    log_success "Scope management endpoints are available"
    
    # Verify standard OIDC scopes exist
    verify_standard_scopes || return 1
    
    # Run scope creation scenarios
    test_scope_creation_scenarios || return 1
    
    # Run scope management operations
    test_scope_management_operations || return 1
    
    log_success "=== Scope Management Test Completed Successfully ==="
    return 0
}

# Cleanup function
cleanup_scope_management() {
    log_info "Cleaning up scope management test"
    cleanup_test_scopes
}

# Export functions for use by other scripts
export -f create_test_scope get_scope_by_name list_scopes update_test_scope
export -f delete_test_scope cleanup_test_scopes generate_test_scope_data get_default_scopes

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_scope_management
    
    # Run the test
    run_scope_management_test
    exit $?
fi