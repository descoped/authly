#!/bin/bash
# Integration Test Wrapper Script
# Sets up environment and runs the full-stack integration test suite

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
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

# Function to check if Docker Compose services are running
check_docker_services() {
    log_info "Checking Docker Compose services..."
    
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed or not in PATH"
        return 1
    fi
    
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose is not installed or not in PATH"
        return 1
    fi
    
    # Check if services are running
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    if ! $compose_cmd ps --services --filter "status=running" | grep -q "authly"; then
        log_error "Authly service is not running. Please start services first:"
        log_error "  $compose_cmd up -d"
        return 1
    fi
    
    log_success "Docker services are running"
    return 0
}

# Function to get admin password from Docker environment
get_admin_password() {
    log_info "Detecting admin password from Docker environment..."
    
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    # Try to get password from Docker environment
    local docker_admin_password=""
    if docker_admin_password=$($compose_cmd exec -T authly env 2>/dev/null | grep "AUTHLY_ADMIN_PASSWORD" | cut -d'=' -f2 | tr -d '\r\n' 2>/dev/null); then
        if [[ -n "$docker_admin_password" ]]; then
            log_success "Found admin password from Docker environment"
            echo "$docker_admin_password"
            return 0
        fi
    fi
    
    # Fallback to common test passwords
    local test_passwords=("ci_admin_test_password" "dev_admin_password" "admin_password" "admin123")
    
    for password in "${test_passwords[@]}"; do
        log_info "Trying password: $password"
        if curl -s -X POST "http://localhost:8000/api/v1/auth/login" \
           -H "Content-Type: application/json" \
           -d "{\"username\":\"admin\",\"password\":\"$password\"}" | jq -e '.access_token' >/dev/null 2>&1; then
            log_success "Found working admin password: $password"
            echo "$password"
            return 0
        fi
    done
    
    log_error "Could not determine admin password automatically"
    return 1
}

# Function to setup environment variables
setup_environment() {
    log_info "Setting up environment variables..."
    
    # Base configuration
    export AUTHLY_BASE_URL="${AUTHLY_BASE_URL:-http://localhost:8000}"
    export AUTHLY_API_BASE="${AUTHLY_BASE_URL}/api/v1"
    
    # Admin configuration
    export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
    
    # Try to get admin password if not already set
    if [[ -z "${AUTHLY_ADMIN_PASSWORD:-}" && -z "${ADMIN_PASSWORD:-}" ]]; then
        log_info "Admin password not set, attempting to detect..."
        if DETECTED_PASSWORD=$(get_admin_password); then
            export AUTHLY_ADMIN_PASSWORD="$DETECTED_PASSWORD"
            export ADMIN_PASSWORD="$DETECTED_PASSWORD"
        else
            log_error "Please set AUTHLY_ADMIN_PASSWORD or ADMIN_PASSWORD environment variable"
            log_error "Example: export AUTHLY_ADMIN_PASSWORD='your_admin_password'"
            return 1
        fi
    else
        # Use existing password
        export ADMIN_PASSWORD="${ADMIN_PASSWORD:-${AUTHLY_ADMIN_PASSWORD:-}}"
        log_success "Using provided admin password"
    fi
    
    # Test configuration
    export TEST_USER_PREFIX="${TEST_USER_PREFIX:-testuser}"
    export TEST_CLIENT_PREFIX="${TEST_CLIENT_PREFIX:-testclient}"
    export TEST_SCOPE_PREFIX="${TEST_SCOPE_PREFIX:-testscope}"
    
    # Test execution configuration
    export RUN_USER_TESTS="${RUN_USER_TESTS:-true}"
    export RUN_CLIENT_TESTS="${RUN_CLIENT_TESTS:-true}"
    export RUN_SCOPE_TESTS="${RUN_SCOPE_TESTS:-true}"
    export RUN_USER_AUTH_TESTS="${RUN_USER_AUTH_TESTS:-true}"
    export RUN_OAUTH_TESTS="${RUN_OAUTH_TESTS:-true}"
    
    # Cleanup configuration
    export CLEANUP_ON_SUCCESS="${CLEANUP_ON_SUCCESS:-true}"
    export CLEANUP_ON_FAILURE="${CLEANUP_ON_FAILURE:-true}"
    
    log_success "Environment setup complete"
    return 0
}

# Function to wait for services to be ready
wait_for_services() {
    log_info "Waiting for Authly service to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s "http://localhost:8000/health" >/dev/null 2>&1; then
            log_success "Authly service is ready"
            return 0
        fi
        
        log_info "Attempt $attempt/$max_attempts - waiting for service..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "Authly service did not become ready within $((max_attempts * 2)) seconds"
    return 1
}

# Function to show configuration
show_configuration() {
    log_info "Integration Test Configuration:"
    echo "  Base URL: ${AUTHLY_BASE_URL}"
    echo "  Admin User: ${ADMIN_USERNAME}"
    echo "  Admin Password: $(echo "${ADMIN_PASSWORD}" | sed 's/./*/g')"
    echo "  Test Prefixes: ${TEST_USER_PREFIX}, ${TEST_CLIENT_PREFIX}, ${TEST_SCOPE_PREFIX}"
    echo ""
    log_info "Test Modules:"
    echo "  User Management Tests: ${RUN_USER_TESTS}"
    echo "  Client Management Tests: ${RUN_CLIENT_TESTS}"
    echo "  Scope Management Tests: ${RUN_SCOPE_TESTS}"
    echo "  User Authentication Tests: ${RUN_USER_AUTH_TESTS}"
    echo "  OAuth Flow Tests: ${RUN_OAUTH_TESTS}"
    echo ""
    log_info "Cleanup Configuration:"
    echo "  Cleanup on Success: ${CLEANUP_ON_SUCCESS}"
    echo "  Cleanup on Failure: ${CLEANUP_ON_FAILURE}"
    echo ""
}

# Function to start Docker Compose services
start_docker_services() {
    log_info "Starting Docker Compose services..."
    
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    if ! $compose_cmd up -d; then
        log_error "Failed to start Docker Compose services"
        return 1
    fi
    
    log_success "Docker Compose services started"
    return 0
}

# Function to stop Docker Compose services
stop_docker_services() {
    log_info "Stopping Docker Compose services..."
    
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    if ! $compose_cmd down; then
        log_error "Failed to stop Docker Compose services"
        return 1
    fi
    
    log_success "Docker Compose services stopped"
    return 0
}

# Function to display usage
show_usage() {
    echo "Usage: $0 [TEST_MODE] [OPTIONS]"
    echo ""
    echo "Test Modes:"
    echo "  infrastructure  - Basic health and endpoint checks"
    echo "  admin          - Admin API authentication testing"
    echo "  clients        - Client and scope management (core admin tests)"
    echo "  userauth       - User authentication and OIDC testing"
    echo "  oauth          - Complete OAuth 2.1 authorization code flow"
    echo "  comprehensive  - All tests including OAuth flow (default)"
    echo "  cleanup        - Manual cleanup of test data"
    echo "  status         - Current system status"
    echo ""
    echo "Service Management:"
    echo "  start          - Start Docker Compose services and wait for readiness"
    echo "  stop           - Stop Docker Compose services"
    echo "  restart        - Restart Docker Compose services"
    echo ""
    echo "Options:"
    echo "  --help, -h        - Show this help message"
    echo "  --setup-only      - Setup environment and show configuration without running tests"
    echo "  --no-docker-check - Skip Docker service checks"
    echo "  --start-services  - Start services before running tests"
    echo "  --stop-after      - Stop services after running tests"
    echo ""
    echo "Environment Variables:"
    echo "  AUTHLY_ADMIN_PASSWORD - Admin password (auto-detected if not set)"
    echo "  AUTHLY_BASE_URL      - Base URL (default: http://localhost:8000)"
    echo "  RUN_OAUTH_TESTS      - Enable OAuth tests (default: true)"
    echo "  CLEANUP_ON_SUCCESS   - Cleanup after successful tests (default: true)"
    echo ""
    echo "Examples:"
    echo "  $0 start                     # Start Docker services"
    echo "  $0 comprehensive             # Run comprehensive tests"
    echo "  $0 oauth --start-services    # Start services and run OAuth tests"
    echo "  $0 stop                      # Stop Docker services"
    echo "  $0 --setup-only              # Setup environment and show config"
    echo "  AUTHLY_ADMIN_PASSWORD='secret' $0  # Use specific admin password"
}

# Main function
main() {
    local test_mode="${1:-comprehensive}"
    local setup_only=false
    local skip_docker_check=false
    local start_services=false
    local stop_after=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --setup-only)
                setup_only=true
                shift
                ;;
            --no-docker-check)
                skip_docker_check=true
                shift
                ;;
            --start-services)
                start_services=true
                shift
                ;;
            --stop-after)
                stop_after=true
                shift
                ;;
            start)
                start_docker_services
                wait_for_services
                exit $?
                ;;
            stop)
                stop_docker_services
                exit $?
                ;;
            restart)
                stop_docker_services
                start_docker_services
                wait_for_services
                exit $?
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                test_mode="$1"
                shift
                ;;
        esac
    done
    
    log_info "=== Authly Integration Test Wrapper ==="
    log_info "Test mode: $test_mode"
    echo ""
    
    # Start services if requested
    if [[ "$start_services" == "true" ]]; then
        start_docker_services || exit 1
        skip_docker_check=true  # We just started them, no need to check again
    fi
    
    # Check Docker services
    if [[ "$skip_docker_check" != "true" ]]; then
        check_docker_services || exit 1
    fi
    
    # Setup environment
    setup_environment || exit 1
    
    # Wait for services
    if [[ "$skip_docker_check" != "true" ]]; then
        wait_for_services || exit 1
    fi
    
    # Show configuration
    show_configuration
    
    # If setup-only, exit here
    if [[ "$setup_only" == "true" ]]; then
        log_success "Environment setup complete. You can now run tests manually:"
        log_info "  $SCRIPT_DIR/integration-tests/run-full-stack-test.sh $test_mode"
        exit 0
    fi
    
    # Run the integration tests
    log_info "Starting integration tests..."
    echo ""
    
    # Set up cleanup to stop services if requested
    if [[ "$stop_after" == "true" ]]; then
        trap 'stop_docker_services' EXIT
    fi
    
    exec "$SCRIPT_DIR/integration-tests/run-full-stack-test.sh" "$test_mode"
}

# Run main function with all arguments
main "$@"