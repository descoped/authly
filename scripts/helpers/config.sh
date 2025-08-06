#!/bin/bash
# Configuration and constants for integration tests

# Base configuration
AUTHLY_BASE_URL="${AUTHLY_BASE_URL:-http://localhost:8000}"
AUTHLY_API_BASE="${AUTHLY_BASE_URL}/api/v1"

# Admin configuration
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
# Admin password - standardized on AUTHLY_ADMIN_PASSWORD
AUTHLY_ADMIN_PASSWORD="${AUTHLY_ADMIN_PASSWORD:-}"

# Test configuration
TEST_USER_PREFIX="${TEST_USER_PREFIX:-testuser}"
TEST_CLIENT_PREFIX="${TEST_CLIENT_PREFIX:-testclient}"
TEST_SCOPE_PREFIX="${TEST_SCOPE_PREFIX:-testscope}"

# API endpoints
AUTH_LOGIN_ENDPOINT="${AUTHLY_API_BASE}/auth/login"
AUTH_TOKEN_ENDPOINT="${AUTHLY_API_BASE}/oauth/token"
AUTH_REFRESH_ENDPOINT="${AUTHLY_API_BASE}/oauth/refresh"
AUTH_REVOKE_ENDPOINT="${AUTHLY_API_BASE}/oauth/revoke"

USERS_ENDPOINT="${AUTHLY_API_BASE}/users"
ADMIN_USERS_ENDPOINT="${AUTHLY_BASE_URL}/admin/users"

CLIENTS_ENDPOINT="${AUTHLY_BASE_URL}/admin/clients"
SCOPES_ENDPOINT="${AUTHLY_BASE_URL}/admin/scopes"

OAUTH_AUTHORIZE_ENDPOINT="${AUTHLY_API_BASE}/oauth/authorize"
OAUTH_DISCOVERY_ENDPOINT="${AUTHLY_BASE_URL}/.well-known/oauth-authorization-server"

OIDC_DISCOVERY_ENDPOINT="${AUTHLY_BASE_URL}/.well-known/openid_configuration"
OIDC_USERINFO_ENDPOINT="${AUTHLY_BASE_URL}/oidc/userinfo"
USERINFO_ENDPOINT="${OIDC_USERINFO_ENDPOINT}"

# Health and status endpoints
HEALTH_ENDPOINT="${AUTHLY_BASE_URL}/health"
ADMIN_HEALTH_ENDPOINT="${AUTHLY_BASE_URL}/admin/health"

# Test data templates
TEST_USER_TEMPLATE='{
  "username": "%s",
  "email": "%s",
  "password": "%s",
  "first_name": "Test",
  "last_name": "User"
}'

TEST_CLIENT_TEMPLATE='{
  "client_name": "%s",
  "client_type": "public",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["http://localhost:8080/callback"],
  "scopes": ["openid", "profile", "email"]
}'

TEST_SCOPE_TEMPLATE='{
  "name": "%s",
  "description": "Test scope for integration testing",
  "is_default": false
}'

# OAuth flow configuration
OAUTH_REDIRECT_URI="http://localhost:8080/callback"
OAUTH_RESPONSE_TYPE="code"
OAUTH_CODE_CHALLENGE_METHOD="S256"

# Timeouts and retries
SERVICE_WAIT_TIMEOUT=120
SERVICE_WAIT_INTERVAL=5
REQUEST_TIMEOUT=30
MAX_RETRIES=3

# Test cleanup configuration
CLEANUP_ON_SUCCESS="${CLEANUP_ON_SUCCESS:-true}"
CLEANUP_ON_FAILURE="${CLEANUP_ON_FAILURE:-true}"

# Validation function
validate_config() {
    log_info "Validating configuration..."
    
    # Check required tools
    for tool in curl jq openssl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool '$tool' is not installed"
            return 1
        fi
    done
    
    # Check required environment variables
    if [[ -z "$AUTHLY_ADMIN_PASSWORD" ]]; then
        log_error "Admin password not configured. Set AUTHLY_ADMIN_PASSWORD environment variable"
        return 1
    fi
    
    log_success "Configuration validation passed"
    return 0
}

# Display current configuration
show_config() {
    log_info "Integration Test Configuration:"
    echo "  Base URL: $AUTHLY_BASE_URL"
    echo "  API Base: $AUTHLY_API_BASE"
    echo "  Admin User: $ADMIN_USERNAME"
    echo "  Admin Password: $(echo "$AUTHLY_ADMIN_PASSWORD" | sed 's/./*/g')"
    echo "  Test Prefixes: $TEST_USER_PREFIX, $TEST_CLIENT_PREFIX, $TEST_SCOPE_PREFIX"
    echo "  Cleanup on Success: $CLEANUP_ON_SUCCESS"
    echo "  Cleanup on Failure: $CLEANUP_ON_FAILURE"
}

# Export configuration variables
export AUTHLY_BASE_URL AUTHLY_API_BASE
export ADMIN_USERNAME AUTHLY_ADMIN_PASSWORD
export TEST_USER_PREFIX TEST_CLIENT_PREFIX TEST_SCOPE_PREFIX
export AUTH_LOGIN_ENDPOINT AUTH_TOKEN_ENDPOINT AUTH_REVOKE_ENDPOINT
export USERS_ENDPOINT ADMIN_USERS_ENDPOINT CLIENTS_ENDPOINT SCOPES_ENDPOINT
export OAUTH_AUTHORIZE_ENDPOINT OAUTH_DISCOVERY_ENDPOINT
export OIDC_DISCOVERY_ENDPOINT OIDC_USERINFO_ENDPOINT USERINFO_ENDPOINT
export HEALTH_ENDPOINT ADMIN_HEALTH_ENDPOINT
export TEST_USER_TEMPLATE TEST_CLIENT_TEMPLATE TEST_SCOPE_TEMPLATE
export OAUTH_REDIRECT_URI OAUTH_RESPONSE_TYPE OAUTH_CODE_CHALLENGE_METHOD
export SERVICE_WAIT_TIMEOUT SERVICE_WAIT_INTERVAL REQUEST_TIMEOUT MAX_RETRIES
export CLEANUP_ON_SUCCESS CLEANUP_ON_FAILURE
export -f validate_config show_config