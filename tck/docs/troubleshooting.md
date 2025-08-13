# Troubleshooting Guide

## Common Issues and Solutions

### 1. TCK Container Build Issues

**Problem**: TCK container fails to build or run.

**Solutions**:
```bash
# Clean rebuild
make clean
make build-tck

# Check Docker daemon
docker ps

# Verify Dockerfile
cat Dockerfile.tck
```

### 2. Authly Connection Issues

**Problem**: TCK can't connect to Authly.

**Solutions**:
```bash
# For local Authly
export AUTHLY_BASE_URL=http://localhost:8000

# For Docker Authly
export AUTHLY_BASE_URL=http://host.docker.internal:8000

# Test connection
curl $AUTHLY_BASE_URL/health
```

### 3. Discovery Endpoint Not Found

**Problem**: TCK can't find `/.well-known/openid-configuration`

**Solutions**:
```bash
# Verify Authly is running
curl http://localhost:8000/health

# Check discovery endpoint (note: openid-configuration, not openid_configuration)
curl http://localhost:8000/.well-known/openid-configuration | jq .

# Verify JWKS endpoint
curl http://localhost:8000/.well-known/jwks.json | jq .
```

### 4. Report Generation Failures

**Problem**: Reports not being generated or saved.

**Solutions**:
```bash
# Create reports directory
mkdir -p reports/latest

# Check permissions
ls -la reports/

# Run with verbose output
make validate

# Check generated reports
ls -la reports/latest/
```

### 5. Test Failures

**Problem**: Specific conformance tests are failing.

**Solutions**:
```bash
# View detailed failure reasons
cat reports/latest/SPECIFICATION_CONFORMANCE.md

# Check actionable items for fixes
cat reports/latest/ACTIONABLE_ITEMS.md

# Common fixes:
# - HTTPS issuer: Deploy with HTTPS for production
# - UserInfo POST: Expected to fail (not implemented)
# - Discovery issuer: Check issuer configuration matches
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

### 8. Environment Issues

**Problem**: Environment variables not being recognized.

**Solutions**:
```bash
# Set required variables
export AUTHLY_BASE_URL=http://localhost:8000
export JWT_SECRET_KEY='test-secret-key'
export JWT_REFRESH_SECRET_KEY='test-refresh-key'

# Verify in container
docker compose --profile validator run --rm validator env | grep AUTHLY
```

### 9. CI/CD Issues

**Problem**: Tests fail in CI but pass locally.

**Solutions**:
```bash
# Use CI profile
docker compose --profile github-ci up -d

# Wait longer for services
sleep 30  # Instead of 10

# Use service names instead of localhost
export AUTHLY_BASE_URL=http://authly:8000
```

## Quick Debugging Commands

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

### Check TCK Status

```bash
# View running containers
docker ps | grep tck

# Check TCK logs
docker compose logs validator

# Test specific endpoint
docker compose --profile validator run --rm validator python -c "
import requests
resp = requests.get('http://host.docker.internal:8000/.well-known/openid-configuration')
print(f'Status: {resp.status_code}')
print(f'Issuer: {resp.json().get("issuer")}')
"
```

## Getting Help

If issues persist:

1. **Check reports**: `cat reports/latest/ACTIONABLE_ITEMS.md`
2. **Review logs**: `docker compose logs`
3. **Clean restart**: `make clean && make validate`
4. **Open issue with**:
   - Error messages from reports
   - Output of `make validate`
   - Environment details (`docker version`, `python --version`)