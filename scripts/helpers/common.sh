#!/bin/bash
# Common helper functions for integration tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# HTTP request helpers
make_request() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    local auth_header="${4:-}"
    
    local curl_args=(-s -w "%{http_code}")
    
    if [[ -n "$auth_header" ]]; then
        curl_args+=(-H "Authorization: $auth_header")
    fi
    
    if [[ -n "$data" ]]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
    fi
    
    curl "${curl_args[@]}" -X "$method" "$url"
}

get_request() {
    local url="$1"
    local auth_header="${2:-}"
    make_request "GET" "$url" "" "$auth_header"
}

post_request() {
    local url="$1" 
    local data="$2"
    local auth_header="${3:-}"
    make_request "POST" "$url" "$data" "$auth_header"
}

put_request() {
    local url="$1"
    local data="$2" 
    local auth_header="${3:-}"
    make_request "PUT" "$url" "$data" "$auth_header"
}

delete_request() {
    local url="$1"
    local auth_header="${2:-}"
    make_request "DELETE" "$url" "" "$auth_header"
}

# JSON parsing helpers (requires jq)
extract_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | jq -r ".$field // empty"
}

# Response validation
check_http_status() {
    local response="$1"
    shift
    local expected_statuses=("$@")
    local actual_status="${response: -3}"
    
    for expected in "${expected_statuses[@]}"; do
        if [[ "$actual_status" == "$expected" ]]; then
            return 0
        fi
    done
    
    # If we get here, none of the expected statuses matched
    local expected_list=$(IFS=', '; echo "${expected_statuses[*]}")
    log_error "Expected HTTP $expected_list, got $actual_status"
    return 1
}

# Wait for service to be ready
wait_for_service() {
    local url="$1"
    local timeout="${2:-60}"
    local interval="${3:-5}"
    
    log_info "Waiting for service at $url to be ready..."
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            log_success "Service is ready"
            return 0
        fi
        
        sleep "$interval"
        elapsed=$((elapsed + interval))
        log_info "Still waiting... (${elapsed}s elapsed)"
    done
    
    log_error "Service not ready after ${timeout}s timeout"
    return 1
}

# Test data generators
generate_random_string() {
    local length="${1:-8}"
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

generate_test_email() {
    local prefix="${1:-testuser}"
    echo "${prefix}$(generate_random_string 6)@example.com"
}

# Cleanup helpers
cleanup_on_exit() {
    local cleanup_function="$1"
    trap "$cleanup_function" EXIT
}

# Docker helpers
check_docker_services() {
    log_info "Checking Docker services status..."
    
    # Check if all required services are healthy
    local required_services=("postgres" "redis" "authly")
    local all_healthy=true
    
    for service in "${required_services[@]}"; do
        if ! docker compose ps | grep "$service" | grep -q "healthy"; then
            log_error "Service '$service' is not healthy"
            all_healthy=false
        fi
    done
    
    if [[ "$all_healthy" != "true" ]]; then
        log_error "Not all Docker services are healthy"
        docker compose ps
        return 1
    fi
    
    log_success "All Docker services are healthy"
}

# Validation helpers
validate_required_env() {
    local var_name="$1"
    if [[ -z "${!var_name:-}" ]]; then
        log_error "Required environment variable $var_name is not set"
        return 1
    fi
}

validate_json_response() {
    local response="$1"
    local body="${response%???}" # Remove last 3 chars (HTTP status)
    
    if ! echo "$body" | jq . >/dev/null 2>&1; then
        log_error "Invalid JSON response: $body"
        return 1
    fi
}

# Export functions for use in other scripts
export -f log_info log_success log_warning log_error
export -f make_request get_request post_request put_request delete_request
export -f extract_json_field check_http_status wait_for_service
export -f generate_random_string generate_test_email cleanup_on_exit
export -f check_docker_services validate_required_env validate_json_response