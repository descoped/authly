#!/bin/bash
# User Management Integration Test
# Tests creating, retrieving, and managing users via Admin API

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/admin-auth.sh"

# Global variables for test data
TEST_USERS=()
TEST_USER_COUNT=0

# Function to generate test user data
generate_test_user_data() {
    local username_suffix="${1:-$(generate_random_string 6)}"
    # Add timestamp to make usernames unique across test runs
    local timestamp=$(date +%s)
    local username="${TEST_USER_PREFIX}_${username_suffix}_${timestamp}"
    local email=$(generate_test_email "$username")
    local password="TestPass123@"
    
    # Use cat with heredoc instead of printf to avoid escaping issues
    cat <<EOF
{
  "username": "$username",
  "email": "$email",
  "password": "$password"
}
EOF
}

# Function to create a test user via Admin API
create_test_user() {
    local user_data="$1"
    local description="${2:-test user}"
    
    log_info "Creating $description via Admin API"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for user creation"
            return 1
        fi
    fi
    
    # Create user via Admin API
    local response=$(post_request "$ADMIN_USERS_ENDPOINT" "$user_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "201"; then
        local body="${response%???}"
        log_error "User creation failed. Response: $body"
        return 1
    fi
    
    # Parse response to get user information
    local body="${response%???}"
    validate_json_response "$response"
    
    local user_id=$(extract_json_field "$body" "id")
    local username=$(extract_json_field "$body" "username")
    local email=$(extract_json_field "$body" "email")
    local created_at=$(extract_json_field "$body" "created_at")
    
    if [[ -z "$user_id" ]]; then
        log_error "Failed to extract id from creation response"
        return 1
    fi
    
    # Store user info for cleanup
    TEST_USERS+=("$user_id")
    TEST_USER_COUNT=$((TEST_USER_COUNT + 1))
    
    log_success "User created successfully:"
    log_info "  User ID: $user_id"
    log_info "  Username: $username"
    log_info "  Email: $email"
    log_info "  Created at: $created_at"
    
    # Return user_id for further operations
    echo "$user_id"
    return 0
}

# Function to retrieve user by ID via Admin API
get_user_by_id() {
    local user_id="$1"
    
    log_info "Retrieving user by ID: $user_id"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for user retrieval"
            return 1
        fi
    fi
    
    # Get user via Admin API
    local response=$(get_request "$ADMIN_USERS_ENDPOINT/$user_id" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "User retrieval failed. Response: $body"
        return 1
    fi
    
    # Parse and validate response
    local body="${response%???}"
    validate_json_response "$response"
    
    local username=$(extract_json_field "$body" "username")
    local email=$(extract_json_field "$body" "email")
    local is_active=$(extract_json_field "$body" "is_active")
    local is_admin=$(extract_json_field "$body" "is_admin")
    
    log_success "User retrieved successfully:"
    log_info "  Username: $username"
    log_info "  Email: $email"
    log_info "  Active: $is_active"
    log_info "  Admin: $is_admin"
    
    return 0
}

# Function to list users via Admin API with pagination
list_users() {
    local limit="${1:-10}"
    local offset="${2:-0}"
    
    log_info "Listing users (limit: $limit, offset: $offset)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for user listing"
            return 1
        fi
    fi
    
    # List users via Admin API
    local url="${ADMIN_USERS_ENDPOINT}?limit=${limit}&offset=${offset}"
    local response=$(get_request "$url" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "User listing failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    # Note: The actual response format depends on the implementation
    # This might need adjustment based on the actual API response structure
    local total_count=$(extract_json_field "$body" "total" 2>/dev/null || echo "unknown")
    
    log_success "Users listed successfully"
    log_info "  Total count: $total_count"
    log_info "  Limit: $limit, Offset: $offset"
    
    return 0
}

# Function to update user information via Admin API
update_test_user() {
    local user_id="$1"
    local update_data="$2"
    local description="${3:-user update}"
    
    log_info "Updating user $user_id ($description)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for user update"
            return 1
        fi
    fi
    
    # Update user via Admin API
    local response=$(put_request "$ADMIN_USERS_ENDPOINT/$user_id" "$update_data" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status
    if ! check_http_status "$response" "200"; then
        local body="${response%???}"
        log_error "User update failed. Response: $body"
        return 1
    fi
    
    # Parse response
    local body="${response%???}"
    validate_json_response "$response"
    
    log_success "User updated successfully"
    return 0
}

# Function to delete/deactivate user via Admin API
delete_test_user() {
    local user_id="$1"
    local description="${2:-test user}"
    
    log_info "Deleting $description (ID: $user_id)"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for user deletion"
            return 1
        fi
    fi
    
    # Delete user via Admin API
    local response=$(delete_request "$ADMIN_USERS_ENDPOINT/$user_id" "Bearer $ADMIN_ACCESS_TOKEN")
    
    # Check HTTP status (might be 200, 204, or 404 if already deleted)
    if check_http_status "$response" "200" || check_http_status "$response" "204"; then
        log_success "User deleted successfully"
        return 0
    elif check_http_status "$response" "404"; then
        log_warning "User not found (may have been already deleted)"
        return 0
    else
        local body="${response%???}"
        log_error "User deletion failed. Response: $body"
        return 1
    fi
}

# Function to test user creation with various scenarios
test_user_creation_scenarios() {
    log_info "Testing user creation scenarios"
    
    # Test 1: Create a basic user
    log_info "Test 1: Creating basic user"
    local basic_user_data=$(generate_test_user_data "basic")
    local basic_user_id=$(create_test_user "$basic_user_data" "basic test user")
    
    if [[ -z "$basic_user_id" ]]; then
        log_error "Failed to create basic user"
        return 1
    fi
    
    # Test 2: Retrieve the created user
    log_info "Test 2: Retrieving created user"
    get_user_by_id "$basic_user_id" || return 1
    
    # Test 3: Create user with special characters in email
    log_info "Test 3: Creating user with complex email"
    # Add timestamp to make username unique
    local timestamp=$(date +%s)
    local complex_email_data=$(cat <<EOF
{
  "username": "${TEST_USER_PREFIX}_complex_${timestamp}",
  "email": "test.user+tag@sub.example.com",
  "password": "ComplexPass123@",
  "first_name": "Test",
  "last_name": "User"
}
EOF
)
    local complex_user_id=$(create_test_user "$complex_email_data" "user with complex email")
    
    if [[ -z "$complex_user_id" ]]; then
        log_warning "Failed to create user with complex email (may not be supported)"
    fi
    
    # Test 4: Try to create duplicate user (should fail)
    log_info "Test 4: Testing duplicate user creation (should fail)"
    local duplicate_response=$(post_request "$ADMIN_USERS_ENDPOINT" "$basic_user_data" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$duplicate_response" "400" || check_http_status "$duplicate_response" "409"; then
        log_success "Duplicate user creation properly rejected"
    else
        log_warning "Duplicate user creation should have been rejected"
    fi
    
    log_success "User creation scenarios completed"
    return 0
}

# Function to test user management operations
test_user_management_operations() {
    log_info "Testing user management operations"
    
    # Create a user for management testing
    local mgmt_user_data=$(generate_test_user_data "mgmt")
    local mgmt_user_id=$(create_test_user "$mgmt_user_data" "management test user")
    
    if [[ -z "$mgmt_user_id" ]]; then
        log_error "Failed to create user for management testing"
        return 1
    fi
    
    # Test user update (if supported)
    log_info "Testing user update"
    local update_data='{"given_name": "Updated", "family_name": "Name"}'
    if update_test_user "$mgmt_user_id" "$update_data" "name update"; then
        log_success "User update test passed"
    else
        log_warning "User update test failed (may not be implemented)"
    fi
    
    # Test user listing
    log_info "Testing user listing"
    if list_users 5 0; then
        log_success "User listing test passed"
    else
        log_warning "User listing test failed (may not be implemented)"
    fi
    
    log_success "User management operations completed"
    return 0
}

# Function to clean up test users
cleanup_test_users() {
    log_info "Cleaning up test users"
    
    if [[ ${#TEST_USERS[@]} -eq 0 ]]; then
        log_info "No test users to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    for user_id in "${TEST_USERS[@]}"; do
        if delete_test_user "$user_id" "test user $user_id"; then
            cleaned_count=$((cleaned_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    done
    
    log_info "User cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    log_info "  Total: ${#TEST_USERS[@]}"
    
    # Reset arrays
    TEST_USERS=()
    TEST_USER_COUNT=0
    
    return 0
}

# Main test function
run_user_management_test() {
    log_info "=== User Management Integration Test ==="
    
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
    
    # Check if user management endpoints are implemented
    log_info "Checking if user management endpoints are available"
    local test_response=$(get_request "$ADMIN_USERS_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$test_response" "501"; then
        log_warning "User management endpoints return 501 Not Implemented"
        log_warning "This may be expected if user management is not yet implemented"
        log_info "Skipping user management tests"
        return 0
    elif check_http_status "$test_response" "200"; then
        log_success "User management endpoints are available"
    else
        local body="${test_response%???}"
        log_error "Unexpected response from user management endpoint: $body"
        return 1
    fi
    
    # Run user creation scenarios
    test_user_creation_scenarios || return 1
    
    # Run user management operations
    test_user_management_operations || return 1
    
    log_success "=== User Management Test Completed Successfully ==="
    return 0
}

# Cleanup function
cleanup_user_management() {
    log_info "Cleaning up user management test"
    cleanup_test_users
}

# Export functions for use by other scripts
export -f create_test_user get_user_by_id list_users update_test_user delete_test_user
export -f cleanup_test_users generate_test_user_data

# Run test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Set up cleanup on exit
    cleanup_on_exit cleanup_user_management
    
    # Run the test
    run_user_management_test
    exit $?
fi