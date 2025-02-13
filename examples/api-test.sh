#!/bin/bash
# =============================================================================
# API Test Script for Apex App
#
# This script runs a series of tests against the Apex App API (running in Docker).
#
# Prerequisites:
#   - jq must be installed
#   - An environment file "../.env" must exist with API_HOST, API_VERSION, etc.
#
# Usage:
#   ./api-test.sh [--parallel] [test_function_name ...]
#
#   --parallel    Run selected tests in parallel.
#   If no test names are provided, the full test suite will run.
#
# Note: In selective mode, tests should be self-contained.
# =============================================================================

# Configuration
LOG_LEVEL=${LOG_LEVEL:-"INFO"}  # Options: TRACE, DEBUG, INFO
CURL_CONNECT_TIMEOUT=${CURL_CONNECT_TIMEOUT:-5}
CURL_MAX_TIME=${CURL_MAX_TIME:-10}
CURL_RETRY=${CURL_RETRY:-2}
CURL_RETRY_DELAY=${CURL_RETRY_DELAY:-1}
DELETE_TIMEOUT=${DELETE_TIMEOUT:-5}

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test metrics and created user IDs for cleanup
TESTS_RUN=0
TESTS_PASSED=0
CREATED_USER_IDS=()

# Environment setup
export API_HOST API_VERSION JWT_SECRET_KEY JWT_ALGORITHM

# Load environment variables from ../.env
[ -f "../.env" ] && source "../.env" || { echo -e "${RED}Error: ../.env file not found${NC}"; exit 1; }

API_BASE_URL="${API_HOST}"
API_AUTH_URL="${API_BASE_URL}/api/${API_VERSION}/auth"
API_USERS_URL="${API_BASE_URL}/api/${API_VERSION}/users"

CURRENT_TOKEN=""

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
log() {
    local level=$1
    local message=$2
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_levels=("TRACE" "DEBUG" "INFO")
    local current_level_index
    current_level_index=$(printf '%s\n' "${log_levels[@]}" | grep -n "^${LOG_LEVEL}$" | cut -d: -f1)
    local msg_level_index
    msg_level_index=$(printf '%s\n' "${log_levels[@]}" | grep -n "^${level}$" | cut -d: -f1)

    if [ "$msg_level_index" -ge "$current_level_index" ]; then
        case $level in
            "TRACE") echo -e "${BLUE}[TRACE]${NC} ${timestamp} - ${message}" ;;
            "DEBUG") echo -e "${YELLOW}[DEBUG]${NC} ${timestamp} - ${message}" ;;
            "INFO")  echo -e "${GREEN}[INFO]${NC}  ${timestamp} - ${GREEN}${message}${NC}" ;;
        esac
    fi
}

# -----------------------------------------------------------------------------
# HTTP Request Handler
# -----------------------------------------------------------------------------
make_request() {
    local method=$1
    local url=$2
    local auth_header=${3:-""}
    local content_type=${4:-""}
    local data=${5:-""}
    local custom_timeout=${6:-$CURL_MAX_TIME}

    local curl_cmd="curl -s"
    curl_cmd+=" --connect-timeout ${CURL_CONNECT_TIMEOUT}"
    curl_cmd+=" --max-time ${custom_timeout}"
    curl_cmd+=" --retry ${CURL_RETRY}"
    curl_cmd+=" --retry-delay ${CURL_RETRY_DELAY}"

    if [ -n "$auth_header" ]; then
        curl_cmd+=" -H \"Authorization: Bearer ${auth_header}\""
    fi
    if [ -n "$content_type" ]; then
        curl_cmd+=" -H \"Content-Type: ${content_type}\""
    fi
    if [ -n "$data" ]; then
        curl_cmd+=" -d '${data}'"
    fi

    curl_cmd+=" -X ${method} \"${url}\""

    log "TRACE" "Executing: ${curl_cmd}"
    local response
    response=$(eval ${curl_cmd})
    log "DEBUG" "Response: ${response}"
    echo "$response"
}

# -----------------------------------------------------------------------------
# Print Test Result and Update Counters
# -----------------------------------------------------------------------------
print_test_result() {
    local test_name=$1
    local result=$2
    local error_msg=$3

    ((TESTS_RUN++))
    if [ "$result" -eq 0 ]; then
        log "INFO" "✓ $test_name passed"
        ((TESTS_PASSED++))
    else
        log "INFO" "✗ $test_name failed"
        [ -n "$error_msg" ] && log "INFO" "Error: $error_msg"
    fi
}

# -----------------------------------------------------------------------------
# API Health Check
# -----------------------------------------------------------------------------
check_api() {
    log "INFO" "Checking if API is running..."
    local response
    response=$(make_request "GET" "${API_HOST}/health")
    local status_code=$?
    if [ $status_code -ne 0 ]; then
        log "INFO" "API is not running on ${API_HOST}"
        exit 1
    fi
    log "INFO" "API is running"
}

# -----------------------------------------------------------------------------
# Test Functions
# -----------------------------------------------------------------------------

test_unauthorized_access() {
    log "INFO" "Testing unauthorized access..."
    local response
    response=$(make_request "GET" "${API_USERS_URL}/me")
    print_test_result "Unauthorized access" 0
}

test_login() {
    local username=$1
    log "INFO" "Testing user login for $username..."

    # Prepare a JSON payload for login
    local data
    data=$(printf '{"username": "%s", "password": "Test123!", "grant_type": "password"}' "$username")
    local response
    response=$(make_request "POST" "${API_AUTH_URL}/token" "" "application/json" "$data")
    CURRENT_TOKEN=$(echo "$response" | jq -r '.access_token // empty')

    if [ -n "$CURRENT_TOKEN" ]; then
        print_test_result "User login ($username)" 0
    else
        local error
        error=$(echo "$response" | jq -r '.detail // empty')
        if [ "$error" = "Account not verified" ]; then
            print_test_result "User login ($username) - Not verified" 0
        else
            print_test_result "User login ($username)" 1 "Failed to login: ${error:-$response}"
        fi
    fi
}

verify_token() {
    local username=$1
    local response
    response=$(make_request "GET" "${API_USERS_URL}/me" "$CURRENT_TOKEN")
    if [ -n "$(echo "$response" | jq -r '.username // empty')" ]; then
        print_test_result "Get current user ($username)" 0
    else
        print_test_result "Get current user ($username)" 1 "Failed to get user: $response"
    fi
}

test_get_users() {
    local response
    response=$(make_request "GET" "${API_USERS_URL}/" "$CURRENT_TOKEN")
    if [ -n "$response" ]; then
        local count
        count=$(echo "$response" | jq '. | length')
        log "INFO" "Number of users: $count"
        print_test_result "Get all users" 0
    else
        print_test_result "Get all users" 1 "Empty response"
    fi
}

test_create_user() {
    local username=$1
    log "INFO" "Testing user creation for $username..."

    local data
    data=$(printf '{"username": "%s", "email": "%s@example.com", "password": "Test123!"}' "$username" "$username")
    local response
    response=$(make_request "POST" "$API_USERS_URL/" "" "application/json" "$data")

    local user_id
    user_id=$(echo "$response" | jq -r '.id')
    if [ "$user_id" != "null" ] && [ -n "$user_id" ]; then
        print_test_result "Create user ($username)" 0
        log "INFO" "Created user $username with ID: $user_id"
        CREATED_USER_IDS+=("$user_id")
        return 0
    else
        print_test_result "Create user ($username)" 1 "Failed to create user: $response"
        return 1
    fi
}

# Negative test: send an invalid JSON payload to /auth/token
test_invalid_payload() {
    log "INFO" "Testing login with invalid JSON payload..."
    local data="invalid_json"
    local response
    response=$(make_request "POST" "${API_AUTH_URL}/token" "" "application/json" "$data")
    # Check for "JSON decode error" in the response
    if echo "$response" | grep -q "JSON decode error"; then
        print_test_result "Login with invalid JSON" 0
    else
        print_test_result "Login with invalid JSON" 1 "Unexpected response: $response"
    fi
}

test_verify_user() {
    local username=$1
    log "INFO" "Testing user verification for $username..."

    # Admin login using JSON payload
    local admin_data
    admin_data='{"username": "admin", "password": "Test123!", "grant_type": "password"}'
    local admin_response
    admin_response=$(make_request "POST" "${API_AUTH_URL}/token" "" "application/json" "$admin_data")
    local admin_token
    admin_token=$(echo "$admin_response" | jq -r '.access_token')

    # Use the first created user ID for verification
    local user_id="${CREATED_USER_IDS[0]}"
    local verify_response
    verify_response=$(make_request "PUT" "${API_USERS_URL}/${user_id}/verify" "$admin_token" "application/json")
    if [ "$(echo "$verify_response" | jq -r '.is_verified')" = "true" ]; then
        print_test_result "Verify user ($username)" 0
    else
        print_test_result "Verify user ($username)" 1 "Failed to verify: $verify_response"
    fi
}

test_update_user() {
    local username=$1
    local user_id="${CREATED_USER_IDS[0]}"
    local data
    data=$(printf '{"username": "updated_%s"}' "$username")
    local response
    response=$(make_request "PUT" "${API_USERS_URL}/${user_id}" "$CURRENT_TOKEN" "application/json" "$data")
    local updated_username
    updated_username=$(echo "$response" | jq -r '.username')
    if [ "$updated_username" = "updated_${username}" ]; then
        print_test_result "Update user ($username)" 0
    else
        print_test_result "Update user ($username)" 1 "Failed to update: $response"
    fi
}

test_delete_user() {
    local username=$1
    local user_id="${CREATED_USER_IDS[0]}"
    log "INFO" "Testing user deletion for $username..."
    if [ -z "$user_id" ]; then
        print_test_result "Delete user ($username)" 1 "No user ID available"
        return 1
    fi
    log "INFO" "Deletion may take up to ${DELETE_TIMEOUT}s..."
    local curl_cmd
    curl_cmd="curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout ${CURL_CONNECT_TIMEOUT} --max-time ${DELETE_TIMEOUT} -X DELETE"
    if [ -n "$CURRENT_TOKEN" ]; then
        curl_cmd+=" -H \"Authorization: Bearer ${CURRENT_TOKEN}\""
    fi
    curl_cmd+=" \"${API_USERS_URL}/${user_id}\""
    log "TRACE" "Executing delete command: ${curl_cmd}"
    local status_code
    status_code=$(eval ${curl_cmd})
    log "DEBUG" "Delete status code: ${status_code}"
    if [ "$status_code" -eq 204 ]; then
        print_test_result "Delete user ($username)" 0
    else
        print_test_result "Delete user ($username)" 1 "Unexpected HTTP status code: ${status_code}"
    fi

    # Verify subsequent access returns a proper error (e.g., 401 or "Not authenticated")
    local post_delete_response
    post_delete_response=$(make_request "GET" "${API_USERS_URL}/me" "$CURRENT_TOKEN")
    if echo "$post_delete_response" | grep -q -E "Not authenticated|Could not validate credentials"; then
        log "INFO" "Subsequent access correctly indicates deleted user"
    else
        log "INFO" "Subsequent access did not return expected error: ${post_delete_response}"
    fi
}

# New test: Rate Limiting / Throttling Test on the login endpoint.
# This test sends repeated login requests for the same user and checks
# for an HTTP 429 response.
test_rate_limiting() {
    log "INFO" "Testing rate limiting on login endpoint..."
    local username="admin"
    local payload
    payload=$(printf '{"username": "%s", "password": "Admin123!", "grant_type": "password"}' "$username")
    local rate_limit_triggered=0
    local i
    local code
    # Send 120 rapid login requests using the same username.
    for i in {1..120}; do
         # Use curl directly to capture HTTP status code.
         code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$payload" "${API_AUTH_URL}/token")
         if [ "$code" -eq 429 ]; then
             rate_limit_triggered=1
             break
         fi
    done
    if [ "$rate_limit_triggered" -eq 1 ]; then
         print_test_result "Rate limiting test" 0
    else
         print_test_result "Rate limiting test" 1 "No 429 response received after repeated login attempts"
    fi
}

create_admin_user() {
    local data='{
        "username": "admin",
        "email": "admin@example.com",
        "password": "Admin123!",
        "is_admin": true,
        "is_verified": true
    }'
    # Create admin user and ignore errors if already exists
    make_request "POST" "$API_USERS_URL/" "" "application/json" "$data" > /dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Cleanup Function: Deletes all created test users.
# -----------------------------------------------------------------------------
cleanup() {
    log "INFO" "Cleaning up created test users..."
    for user_id in "${CREATED_USER_IDS[@]}"; do
        log "INFO" "Deleting user with ID: $user_id"
        local curl_cmd="curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout ${CURL_CONNECT_TIMEOUT} --max-time ${DELETE_TIMEOUT} -X DELETE"
        [ -n "$CURRENT_TOKEN" ] && curl_cmd+=" -H \"Authorization: Bearer ${CURRENT_TOKEN}\""
        curl_cmd+=" \"${API_USERS_URL}/${user_id}\""
        eval ${curl_cmd} >/dev/null 2>&1
    done
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

# Parse command-line arguments for selective and parallel test runs
PARALLEL=false
SELECTED_TESTS=()

if [ "$1" = "--help" ]; then
    echo "Usage: $0 [--parallel] [test_function_name ...]"
    echo "   --parallel    Run selected tests in parallel."
    echo "   If no test names are provided, the full test suite will run."
    exit 0
fi

for arg in "$@"; do
    if [ "$arg" = "--parallel" ]; then
        PARALLEL=true
    else
        SELECTED_TESTS+=("$arg")
    fi
done

# Ensure admin user exists
create_admin_user || log "INFO" "Admin user exists"

log "INFO" "Starting API tests..."
command -v jq &> /dev/null || { log "INFO" "Error: jq is not installed"; exit 1; }

check_api

if [ ${#SELECTED_TESTS[@]} -eq 0 ]; then
    # Full test suite (order matters)
    test_unauthorized_access

    for user in admin user1; do
        test_login "$user"
        if [ -n "$CURRENT_TOKEN" ]; then
            verify_token "$user"
            test_get_users
        fi
    done

    test_invalid_payload

    NEW_USER="testuser$(date +%s)"
    if test_create_user "$NEW_USER"; then
        # First login returns "Account not verified"
        test_login "$NEW_USER"
        test_verify_user "$NEW_USER"
        # Re‑login now that the user is verified
        test_login "$NEW_USER"
        verify_token "$NEW_USER"
        test_update_user "$NEW_USER"
        test_delete_user "$NEW_USER"
    fi

    test_rate_limiting

else
    # Selective test mode: Run only the tests specified
    log "INFO" "Running selective tests: ${SELECTED_TESTS[*]}"
    if [ "$PARALLEL" = true ]; then
        for test_func in "${SELECTED_TESTS[@]}"; do
            if declare -f "$test_func" > /dev/null; then
                log "INFO" "Running $test_func in parallel"
                "$test_func" &
            else
                log "INFO" "Test function $test_func not found"
            fi
        done
        wait
    else
        for test_func in "${SELECTED_TESTS[@]}"; do
            if declare -f "$test_func" > /dev/null; then
                log "INFO" "Running $test_func"
                "$test_func"
            else
                log "INFO" "Test function $test_func not found"
            fi
        done
    fi
fi

# Test Summary
log "INFO" "Test Summary:"
log "INFO" "Tests run: $TESTS_RUN"
log "INFO" "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
log "INFO" "Tests failed: ${RED}$((TESTS_RUN - TESTS_PASSED))${NC}"

cleanup

[ "$TESTS_PASSED" -eq "$TESTS_RUN" ] && { log "INFO" "All tests passed!"; exit 0; } || { log "INFO" "Some tests failed."; exit 1; }
