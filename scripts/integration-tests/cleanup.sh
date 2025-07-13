#!/bin/bash
# Integration Test Cleanup Script
# Cleans up test data created during integration testing

set -euo pipefail

# Source helper functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../helpers/common.sh"
source "$SCRIPT_DIR/../helpers/config.sh"
source "$SCRIPT_DIR/admin-auth.sh"

# Import cleanup functions from other scripts
source "$SCRIPT_DIR/user-management.sh"
source "$SCRIPT_DIR/client-management.sh"
source "$SCRIPT_DIR/scope-management.sh"

# Function to clean up all test clients
cleanup_all_test_clients() {
    log_info "Cleaning up all test clients"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for client cleanup"
            return 1
        fi
    fi
    
    # Get list of all clients
    local response=$(get_request "$CLIENTS_ENDPOINT?limit=100" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$response" "200"; then
        log_error "Failed to retrieve client list for cleanup"
        return 1
    fi
    
    local body="${response%???}"
    local test_clients=$(echo "$body" | jq -r ".[] | select(.client_name | test(\"^${TEST_CLIENT_PREFIX}\")) | .client_id" 2>/dev/null || echo "")
    
    if [[ -z "$test_clients" ]]; then
        log_info "No test clients found to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    while IFS= read -r client_id; do
        if [[ -n "$client_id" ]]; then
            log_info "Deleting test client: $client_id"
            if delete_test_client "$client_id" "test client"; then
                cleaned_count=$((cleaned_count + 1))
            else
                failed_count=$((failed_count + 1))
            fi
        fi
    done <<< "$test_clients"
    
    log_info "Test clients cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    
    return 0
}

# Function to clean up all test scopes
cleanup_all_test_scopes() {
    log_info "Cleaning up all test scopes"
    
    # Ensure we have admin token
    if [[ -z "$ADMIN_ACCESS_TOKEN" ]]; then
        if ! load_admin_token || ! is_admin_token_valid; then
            log_error "No valid admin token available for scope cleanup"
            return 1
        fi
    fi
    
    # Get list of all scopes
    local response=$(get_request "$SCOPES_ENDPOINT?limit=100" "Bearer $ADMIN_ACCESS_TOKEN")
    if ! check_http_status "$response" "200"; then
        log_error "Failed to retrieve scope list for cleanup"
        return 1
    fi
    
    local body="${response%???}"
    local test_scopes=$(echo "$body" | jq -r ".[] | select(.scope_name | test(\"^${TEST_SCOPE_PREFIX}:\")) | .scope_name" 2>/dev/null || echo "")
    
    if [[ -z "$test_scopes" ]]; then
        log_info "No test scopes found to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    while IFS= read -r scope_name; do
        if [[ -n "$scope_name" ]]; then
            log_info "Deleting test scope: $scope_name"
            if delete_test_scope "$scope_name" "test scope"; then
                cleaned_count=$((cleaned_count + 1))
            else
                failed_count=$((failed_count + 1))
            fi
        fi
    done <<< "$test_scopes"
    
    log_info "Test scopes cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    
    return 0
}

# Function to clean up all test users (if user management is implemented)
cleanup_all_test_users() {
    log_info "Cleaning up all test users"
    
    # Check if user management endpoints are available
    local test_response=$(get_request "$ADMIN_USERS_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$test_response" "501"; then
        log_info "User management not implemented, skipping user cleanup"
        return 0
    elif ! check_http_status "$test_response" "200"; then
        log_error "Failed to access user management endpoints"
        return 1
    fi
    
    local body="${test_response%???}"
    local test_users=$(echo "$body" | jq -r ".[] | select(.username | test(\"^${TEST_USER_PREFIX}_\")) | .user_id" 2>/dev/null || echo "")
    
    if [[ -z "$test_users" ]]; then
        log_info "No test users found to clean up"
        return 0
    fi
    
    local cleaned_count=0
    local failed_count=0
    
    while IFS= read -r user_id; do
        if [[ -n "$user_id" ]]; then
            log_info "Deleting test user: $user_id"
            if delete_test_user "$user_id" "test user"; then
                cleaned_count=$((cleaned_count + 1))
            else
                failed_count=$((failed_count + 1))
            fi
        fi
    done <<< "$test_users"
    
    log_info "Test users cleanup completed:"
    log_info "  Cleaned: $cleaned_count"
    log_info "  Failed: $failed_count"
    
    return 0
}

# Function to clean up temporary files
cleanup_temp_files() {
    log_info "Cleaning up temporary files"
    
    local temp_files=(
        "/tmp/authly_admin_token.json"
        "/tmp/authly_test_*.json"
        "/tmp/authly_integration_*.log"
    )
    
    local cleaned_count=0
    
    for pattern in "${temp_files[@]}"; do
        # Use shell expansion to handle wildcards
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                rm -f "$file"
                cleaned_count=$((cleaned_count + 1))
                log_info "Removed temporary file: $file"
            fi
        done
    done
    
    if [[ $cleaned_count -eq 0 ]]; then
        log_info "No temporary files found to clean up"
    else
        log_info "Cleaned up $cleaned_count temporary files"
    fi
    
    return 0
}

# Function to perform comprehensive cleanup
comprehensive_cleanup() {
    log_info "Starting comprehensive cleanup of all test data"
    
    local cleanup_start_time=$(date +%s)
    local total_errors=0
    
    # Ensure we have admin authentication
    if ! load_admin_token || ! is_admin_token_valid; then
        log_info "Admin token not available, performing admin login for cleanup"
        if ! admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD"; then
            log_error "Failed to authenticate admin user for cleanup"
            return 1
        fi
    fi
    
    # Clean up test clients
    if ! cleanup_all_test_clients; then
        log_error "Test client cleanup failed"
        total_errors=$((total_errors + 1))
    fi
    
    # Clean up test scopes
    if ! cleanup_all_test_scopes; then
        log_error "Test scope cleanup failed"
        total_errors=$((total_errors + 1))
    fi
    
    # Clean up test users
    if ! cleanup_all_test_users; then
        log_error "Test user cleanup failed"
        total_errors=$((total_errors + 1))
    fi
    
    # Clean up temporary files
    if ! cleanup_temp_files; then
        log_error "Temporary file cleanup failed"
        total_errors=$((total_errors + 1))
    fi
    
    # Logout admin user
    admin_logout
    
    local cleanup_end_time=$(date +%s)
    local cleanup_duration=$((cleanup_end_time - cleanup_start_time))
    
    if [[ $total_errors -eq 0 ]]; then
        log_success "Comprehensive cleanup completed successfully in ${cleanup_duration}s"
        return 0
    else
        log_warning "Cleanup completed with $total_errors errors in ${cleanup_duration}s"
        return 1
    fi
}

# Function to show cleanup status
show_cleanup_status() {
    log_info "Integration Test Cleanup Status"
    
    # Check admin authentication
    if load_admin_token && is_admin_token_valid; then
        log_info "✓ Admin token available"
    else
        log_warning "✗ Admin token not available"
        return 0
    fi
    
    # Count test clients
    local client_response=$(get_request "$CLIENTS_ENDPOINT?limit=100" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$client_response" "200"; then
        local client_body="${client_response%???}"
        local test_client_count=$(echo "$client_body" | jq -r "[.[] | select(.client_name | test(\"^${TEST_CLIENT_PREFIX}\"))] | length" 2>/dev/null || echo "0")
        log_info "Test clients found: $test_client_count"
    else
        log_warning "Could not check test clients"
    fi
    
    # Count test scopes
    local scope_response=$(get_request "$SCOPES_ENDPOINT?limit=100" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$scope_response" "200"; then
        local scope_body="${scope_response%???}"
        local test_scope_count=$(echo "$scope_body" | jq -r "[.[] | select(.scope_name | test(\"^${TEST_SCOPE_PREFIX}:\"))] | length" 2>/dev/null || echo "0")
        log_info "Test scopes found: $test_scope_count"
    else
        log_warning "Could not check test scopes"
    fi
    
    # Check user management
    local user_response=$(get_request "$ADMIN_USERS_ENDPOINT" "Bearer $ADMIN_ACCESS_TOKEN")
    if check_http_status "$user_response" "501"; then
        log_info "User management: Not implemented"
    elif check_http_status "$user_response" "200"; then
        local user_body="${user_response%???}"
        local test_user_count=$(echo "$user_body" | jq -r "[.[] | select(.username | test(\"^${TEST_USER_PREFIX}_\"))] | length" 2>/dev/null || echo "0")
        log_info "Test users found: $test_user_count"
    else
        log_warning "Could not check test users"
    fi
    
    # Check temporary files
    local temp_file_count=0
    if [[ -f "/tmp/authly_admin_token.json" ]]; then
        temp_file_count=$((temp_file_count + 1))
    fi
    
    log_info "Temporary files found: $temp_file_count"
    
    return 0
}

# Function to force cleanup (ignore errors)
force_cleanup() {
    log_warning "Starting force cleanup (ignoring errors)"
    
    # Set error handling to continue on errors
    set +e
    
    comprehensive_cleanup
    
    # Reset error handling
    set -e
    
    log_info "Force cleanup completed"
    return 0
}

# Main cleanup function
run_cleanup() {
    local cleanup_type="${1:-comprehensive}"
    
    log_info "=== Integration Test Cleanup ==="
    log_info "Cleanup type: $cleanup_type"
    
    # Validate configuration
    validate_config || return 1
    
    case "$cleanup_type" in
        "status")
            show_cleanup_status
            ;;
        "clients")
            admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
            cleanup_all_test_clients
            admin_logout
            ;;
        "scopes")
            admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
            cleanup_all_test_scopes
            admin_logout
            ;;
        "users")
            admin_login "$ADMIN_USERNAME" "$AUTHLY_ADMIN_PASSWORD" || return 1
            cleanup_all_test_users
            admin_logout
            ;;
        "files")
            cleanup_temp_files
            ;;
        "force")
            force_cleanup
            ;;
        "comprehensive"|*)
            comprehensive_cleanup
            ;;
    esac
    
    log_success "=== Cleanup Completed ==="
    return 0
}

# Export functions for use by other scripts
export -f cleanup_all_test_clients cleanup_all_test_scopes cleanup_all_test_users
export -f cleanup_temp_files comprehensive_cleanup show_cleanup_status force_cleanup

# Run cleanup if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cleanup_type="${1:-comprehensive}"
    run_cleanup "$cleanup_type"
    exit $?
fi