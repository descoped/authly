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
    if [[ -z "${AUTHLY_ADMIN_PASSWORD:-}" ]]; then
        log_info "Admin password not set, attempting to detect..."
        if DETECTED_PASSWORD=$(get_admin_password); then
            export AUTHLY_ADMIN_PASSWORD="$DETECTED_PASSWORD"
        else
            log_error "Please set AUTHLY_ADMIN_PASSWORD environment variable"
            log_error "Example: export AUTHLY_ADMIN_PASSWORD='your_admin_password'"
            return 1
        fi
    else
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
    
    # Check for database connection issues
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    if $compose_cmd logs authly --tail 10 2>/dev/null | grep -q "password authentication failed"; then
        log_error "Database authentication failure detected!"
        log_error "This is often caused by persistent postgres volumes with old credentials."
        log_error "Try running with the --clean flag to reset the database:"
        log_error "  $0 $* --clean"
        log_error "Or manually reset with:"
        log_error "  $0 reset"
    fi
    
    return 1
}

# Function to show configuration
show_configuration() {
    log_info "Integration Test Configuration:"
    echo "  Base URL: ${AUTHLY_BASE_URL}"
    echo "  Admin User: ${ADMIN_USERNAME}"
    echo "  Admin Password: $(echo "${AUTHLY_ADMIN_PASSWORD}" | sed 's/./*/g')"
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

# Function to clean postgres volume
clean_postgres_volume() {
    log_info "Cleaning postgres volume to reset database..."
    
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    # Stop services first
    log_info "Stopping services before volume cleanup..."
    $compose_cmd down >/dev/null 2>&1
    
    # Remove postgres volume
    if docker volume ls -q | grep -q "authly_postgres_data"; then
        log_info "Removing postgres data volume..."
        if docker volume rm authly_postgres_data >/dev/null 2>&1; then
            log_success "Postgres volume cleaned successfully"
        else
            log_warning "Could not remove postgres volume (may not exist)"
        fi
    else
        log_info "Postgres volume does not exist, skipping cleanup"
    fi
    
    return 0
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

# Function to reset all volumes and containers
reset_all_services() {
    log_info "Resetting all Docker services and volumes..."
    
    local compose_cmd="docker compose"
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    fi
    
    # Stop and remove everything
    log_info "Stopping and removing all containers..."
    $compose_cmd down -v --remove-orphans >/dev/null 2>&1
    
    # Remove specific volumes
    local volumes=("authly_postgres_data" "authly_redis_data" "authly_authly_logs")
    for volume in "${volumes[@]}"; do
        if docker volume ls -q | grep -q "$volume"; then
            log_info "Removing volume: $volume"
            docker volume rm "$volume" >/dev/null 2>&1 || log_warning "Could not remove $volume"
        fi
    done
    
    log_success "All services and volumes reset"
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
    echo "  oidc-discovery - OIDC Discovery endpoints testing"
    echo "  comprehensive  - All tests including OAuth flow (default)"
    echo "  cleanup        - Manual cleanup of test data"
    echo "  status         - Current system status"
    echo ""
    echo "Service Management:"
    echo "  start          - Start Docker Compose services and wait for readiness"
    echo "  stop           - Stop Docker Compose services"
    echo "  restart        - Restart Docker Compose services"
    echo "  reset          - Stop services and remove all volumes (full reset)"
    echo "  clean          - Clean postgres volume and restart services"
    echo ""
    echo "Options:"
    echo "  --help, -h        - Show this help message"
    echo "  --setup-only      - Setup environment and show configuration without running tests"
    echo "  --no-docker-check - Skip Docker service checks (for standalone container)"
    echo "  --start-services  - Start services before running tests"
    echo "  --stop-after      - Stop services after running tests"
    echo "  --clean           - Clean postgres volume before starting (fixes auth issues)"
    echo ""
    echo "Environment Variables:"
    echo "  SKIP_DOCKER_CHECK=true  - Skip Docker service checks (same as --no-docker-check)"
    echo "  AUTHLY_ADMIN_PASSWORD - Admin password (auto-detected if not set)"
    echo "  AUTHLY_BASE_URL      - Base URL (default: http://localhost:8000)"
    echo "  RUN_OAUTH_TESTS      - Enable OAuth tests (default: true)"
    echo "  CLEANUP_ON_SUCCESS   - Cleanup after successful tests (default: true)"
    echo ""
    echo "Examples:"
    echo "  $0 start                     # Start Docker services"
    echo "  $0 comprehensive             # Run comprehensive tests"
    echo "  $0 oauth --start-services    # Start services and run OAuth tests"
    echo "  $0 comprehensive --clean     # Clean database and run all tests"
    echo "  $0 reset                     # Full reset of all services and volumes"
    echo "  $0 clean                     # Clean postgres volume and restart"
    echo "  $0 stop                      # Stop Docker services"
    echo "  $0 --setup-only              # Setup environment and show config"
    echo "  AUTHLY_ADMIN_PASSWORD='secret' $0  # Use specific admin password"
    echo ""
    echo "Troubleshooting:"
    echo "  If you see database authentication errors, try:"
    echo "    $0 comprehensive --clean     # Clean postgres volume"
    echo "    $0 reset                     # Full reset if clean doesn't work"
}

# Main function
main() {
    local test_mode="${1:-comprehensive}"
    local setup_only=false
    local skip_docker_check="${SKIP_DOCKER_CHECK:-false}"
    local start_services=false
    local stop_after=false
    local clean_volumes=false
    
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
            --clean)
                clean_volumes=true
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
            reset)
                reset_all_services
                exit $?
                ;;
            clean)
                clean_postgres_volume
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
    
    # Clean volumes if requested
    if [[ "$clean_volumes" == "true" ]]; then
        clean_postgres_volume || exit 1
        start_services=true  # Auto-start services after cleaning
    fi
    
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
    
    # Run the test script
    if [[ "$stop_after" == "true" ]]; then
        # If stop_after is requested, don't use exec so we can stop services after
        "$SCRIPT_DIR/integration-tests/run-full-stack-test.sh" "$test_mode"
        local test_result=$?
        stop_docker_services
        exit $test_result
    else
        # Use exec to replace current process when not stopping services
        exec "$SCRIPT_DIR/integration-tests/run-full-stack-test.sh" "$test_mode"
    fi
}

# Run main function with all arguments
main "$@"