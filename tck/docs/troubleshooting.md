# OIDC Conformance Testing Troubleshooting Guide

This guide helps resolve common issues when running OIDC conformance tests against Authly.

## Common Issues and Solutions

### 1. Conformance Suite Won't Start

**Problem**: Docker containers fail to start or immediately exit.

**Solutions**:
- Check Docker is running: `docker ps`
- Check ports are available: `lsof -i :8443` and `lsof -i :8000`
- Review Docker logs: `docker-compose -f docker/docker-compose.yml logs`
- Ensure sufficient memory: Docker needs at least 4GB RAM

### 2. CORS Errors

**Problem**: Browser console shows CORS policy errors.

**Solutions**:
1. Update Authly's CORS configuration:
```python
CORS_ORIGINS = [
    "https://localhost:8443",
    "http://localhost:8443",
    "https://localhost:443"
]
```

2. Restart Authly server after configuration changes

3. If using Docker, ensure the networks are configured correctly

### 3. SSL Certificate Issues

**Problem**: Browser shows SSL certificate warnings.

**Solutions**:
1. Accept the self-signed certificate in your browser
2. Navigate to https://localhost:8443 and click "Advanced" → "Proceed"
3. For automation, use: `curl -k` or `verify=False` in Python requests

### 4. Discovery Endpoint Not Found

**Problem**: Conformance suite can't find `/.well-known/openid_configuration`

**Solutions**:
1. Verify Authly is running: `curl http://localhost:8000/health`
2. Check discovery endpoint: `curl http://localhost:8000/.well-known/openid_configuration | jq .`
3. Ensure OIDC is enabled in Authly configuration
4. If using Docker, check network connectivity between containers
5. Note: Endpoints are under `/api/v1/` prefix:
   - Authorization: `http://localhost:8000/api/v1/oauth/authorize`
   - Token: `http://localhost:8000/api/v1/auth/token`

### 5. Client Authentication Failures

**Problem**: Tests fail with "invalid_client" errors.

**Solutions**:
1. Verify client credentials match between Authly and test configuration
2. Check client_type is "confidential" for secret-based authentication
3. Ensure client_secret is properly encoded (base64 for Basic auth)
4. Create client using Authly admin CLI:
```bash
python -m authly.admin.cli client create \
    --client-id oidc-conformance-test \
    --client-secret conformance-test-secret-change-in-production \
    --client-type confidential
```

### 6. PKCE Validation Errors

**Problem**: Authorization requests fail with PKCE-related errors.

**Solutions**:
1. Ensure code_challenge is properly generated (base64url-encoded SHA256)
2. Verify code_challenge_method is "S256"
3. Check that code_verifier matches the challenge
4. For public clients, PKCE should be mandatory in OAuth 2.1

### 7. ID Token Validation Failures

**Problem**: ID token signature verification fails.

**Solutions**:
1. Check JWKS endpoint is accessible
2. Verify RSA keys are properly formatted
3. Ensure algorithm is RS256 (not HS256 for conformance)
4. Check kid (key ID) matches between token header and JWKS

### 8. UserInfo Endpoint Issues

**Problem**: UserInfo endpoint returns unexpected claims or errors.

**Solutions**:
1. Verify access token has proper scopes (openid, profile, email, etc.)
2. Check token is not expired
3. Ensure Bearer token format: `Authorization: Bearer <token>`
4. Validate user has the requested claim data in database

### 9. Session Management Failures

**Problem**: Session iframe or check_session endpoint not working.

**Solutions**:
1. Verify endpoints are registered in discovery metadata
2. Check iframe can be loaded (X-Frame-Options headers)
3. Ensure session state calculation matches specification
4. Validate postMessage communication between windows

### 10. Database Connection Issues

**Problem**: Authly can't connect to PostgreSQL.

**Solutions**:
1. Check PostgreSQL is running: `docker ps | grep postgres`
2. Verify connection string: `postgresql://authly:authly@localhost:5432/authly`
3. Ensure database is initialized with schema
4. Check firewall/network settings

### 11. Authly Startup Issues

**Problem**: Authly fails to start with various errors.

**Solutions**:

**Missing JWT secrets**:
```bash
export JWT_SECRET_KEY='test-secret-key'
export JWT_REFRESH_SECRET_KEY='test-refresh-key'
```

**Missing database tables**:
```bash
# Initialize schema using init script
docker compose exec -T postgres psql -U authly -d authly < docker-postgres/init-db-and-user.sql
```

**Using embedded mode with testcontainers**:
```bash
# Starts with embedded PostgreSQL (new container each time)
uv run python -m authly serve --embedded --host 0.0.0.0 --port 8000
```

**Using Docker Compose (recommended)**:
```bash
# Starts all services with persistent data
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### 12. Test Client Creation

**Problem**: Can't create test client through admin CLI.

**Solutions**:

**Direct SQL approach (recommended)**:
```bash
# Create SQL file with test client
cat > /tmp/create_test_client.sql << 'EOF'
INSERT INTO oauth_clients (
    client_id, client_name, client_type, client_secret_hash,
    redirect_uris, grant_types, response_types, scope,
    require_pkce, is_active
) VALUES (
    'oidc-conformance-test',
    'OIDC Conformance Test Client',
    'confidential',
    '$2b$12$K4Y4RR5YlF5uBN2H7fP3YuHj6FKThQBqQqZeD/YMBZZIxZLH2Ejha',
    ARRAY['https://localhost:8443/test/a/authly/callback']::text[],
    ARRAY['authorization_code', 'refresh_token']::text[],
    ARRAY['code']::text[],
    'openid profile email',
    true, true
) ON CONFLICT (client_id) DO NOTHING;
EOF

# Execute in database
docker compose exec -T postgres psql -U authly -d authly < /tmp/create_test_client.sql
```

### 13. Authorization Endpoint Returns 401

**Problem**: Authorization endpoint returns 401 instead of redirecting to login.

**Solution**: This is expected behavior for API-first authorization servers. The 401 indicates authentication is required. In a real flow:
1. Client redirects user to authorization endpoint
2. Authorization server returns 401 with login requirements
3. Client handles authentication flow
4. After authentication, authorization proceeds

For testing, you may need to:
- Create a test user first
- Use session cookies or bearer tokens
- Implement the full OAuth flow with authentication

## Debugging Tips

### Enable Debug Logging

In Authly:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

In conformance suite:
```bash
docker-compose -f docker/docker-compose.yml logs -f conformance-suite
```

### Test Individual Endpoints

```bash
# Discovery
curl http://localhost:8000/.well-known/openid_configuration | jq .

# JWKS
curl http://localhost:8000/.well-known/jwks.json | jq .

# Authorization (will redirect)
curl -v "http://localhost:8000/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback&scope=openid"

# UserInfo (requires token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/oidc/userinfo
```

### Check Conformance Suite API

```bash
# Check if suite is running
curl -k https://localhost:8443/api/runner/available

# List test modules
curl -k https://localhost:8443/api/testmodules

# Get test plan status
curl -k https://localhost:8443/api/plan/{plan-id}/status
```

### Common Log Locations

- Authly logs: Check console output or configured log file
- Conformance suite: `docker-compose logs conformance-suite`
- PostgreSQL: `docker-compose logs authly-db`
- MongoDB: `docker-compose logs conformance-mongo`
- Test results: `tck/results/*/test-logs.txt`

## Getting Help

If you encounter issues not covered here:

1. Check Authly's OIDC documentation: `docs/oidc-implementation.md`
2. Review conformance suite documentation: https://gitlab.com/openid/conformance-suite
3. Check test logs in `tck/results/` directory
4. Open an issue with:
   - Error messages
   - Test configuration
   - Authly version
   - Conformance suite version
   - Steps to reproduce