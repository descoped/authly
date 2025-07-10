# Troubleshooting Guide

This comprehensive troubleshooting guide covers common issues, error scenarios, and solutions for Authly's OAuth 2.1 implementation and core authentication features.

## 🚨 Quick Diagnostic Commands

Before diving into specific issues, run these diagnostic commands to get an overview of system health:

```bash
# System status and health check
authly-admin status --verbose

# Database connectivity test
authly-admin config validate

# Check OAuth client configuration
authly-admin client list

# Test authentication endpoints
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "password", "username": "test@example.com", "password": "testpass"}'
```

## 🔐 OAuth 2.1 Authorization Issues

### Authorization Endpoint Errors

#### Error: `invalid_client`
**Symptoms:**
```json
{
  "error": "invalid_client",
  "error_description": "Client not found or inactive"
}
```

**Causes and Solutions:**
1. **Client doesn't exist:**
   ```bash
   # Check if client exists
   authly-admin client show "your-client-id"
   
   # Create client if missing
   authly-admin client create \
     --name "Your App" \
     --type confidential \
     --redirect-uri "https://yourapp.com/callback"
   ```

2. **Client is inactive:**
   ```bash
   # Reactivate client
   authly-admin client update "your-client-id" --activate
   ```

3. **Case sensitivity:**
   - Ensure client_id matches exactly (case-sensitive)
   - Check for leading/trailing whitespace

#### Error: `invalid_request` (Missing PKCE)
**Symptoms:**
```json
{
  "error": "invalid_request",
  "error_description": "code_challenge parameter is required for OAuth 2.1"
}
```

**Solution:**
OAuth 2.1 requires PKCE for all authorization code flows:

```javascript
// Generate PKCE pair (JavaScript example)
function generatePKCE() {
  const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = base64URLEncode(new Uint8Array(digest));
  
  return { codeVerifier, codeChallenge };
}

// Use in authorization request
const { codeVerifier, codeChallenge } = await generatePKCE();
const authUrl = `https://auth.example.com/authorize?` +
  `response_type=code&` +
  `client_id=${clientId}&` +
  `redirect_uri=${redirectUri}&` +
  `scope=read write&` +
  `state=${randomState}&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;
```

#### Error: `invalid_redirect_uri`
**Symptoms:**
```json
{
  "error": "invalid_request",
  "error_description": "redirect_uri not registered for this client"
}
```

**Solution:**
```bash
# Check registered redirect URIs
authly-admin client show "your-client-id"

# Add missing redirect URI
authly-admin client update "your-client-id" \
  --add-redirect-uri "https://newdomain.com/callback"

# For development, ensure exact match (no trailing slashes, etc.)
```

#### Error: `invalid_scope`
**Symptoms:**
```json
{
  "error": "invalid_scope",
  "error_description": "Requested scope not available for client"
}
```

**Solution:**
```bash
# Check available scopes
authly-admin scope list

# Check client's assigned scopes
authly-admin client show "your-client-id"

# Create missing scope
authly-admin scope create \
  --name "missing-scope" \
  --description "Description for missing scope"

# Associate scope with client (if needed)
authly-admin client update "your-client-id" \
  --add-scope "missing-scope"
```

### Token Endpoint Issues

#### Error: `invalid_grant` (PKCE Verification Failed)
**Symptoms:**
```json
{
  "error": "invalid_grant",
  "error_description": "PKCE verification failed"
}
```

**Solution:**
Ensure code_verifier matches the code_challenge used in authorization:

```javascript
// Token exchange with correct code_verifier
const tokenResponse = await fetch('/auth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: authorizationCode,
    client_id: clientId,
    client_secret: clientSecret, // For confidential clients
    code_verifier: codeVerifier,  // Must match original
    redirect_uri: redirectUri     // Must match exactly
  })
});
```

#### Error: `invalid_client` (Authentication Failed)
**Symptoms:**
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

**Solutions:**

1. **For client_secret_basic authentication:**
   ```bash
   # Verify client secret
   authly-admin client show "your-client-id"
   
   # Regenerate if needed
   authly-admin client regenerate-secret "your-client-id"
   ```
   
   ```javascript
   // Correct Basic authentication
   const credentials = btoa(`${clientId}:${clientSecret}`);
   const response = await fetch('/auth/token', {
     method: 'POST',
     headers: {
       'Authorization': `Basic ${credentials}`,
       'Content-Type': 'application/json'
     },
     body: JSON.stringify({
       grant_type: 'authorization_code',
       code: authCode,
       code_verifier: codeVerifier,
       redirect_uri: redirectUri
     })
   });
   ```

2. **For client_secret_post authentication:**
   ```javascript
   // Include credentials in body
   const response = await fetch('/auth/token', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({
       grant_type: 'authorization_code',
       client_id: clientId,
       client_secret: clientSecret,
       code: authCode,
       code_verifier: codeVerifier,
       redirect_uri: redirectUri
     })
   });
   ```

#### Error: `invalid_grant` (Authorization Code Issues)
**Symptoms:**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired or already used"
}
```

**Solutions:**
1. **Code expiration (10 minutes max):**
   - Ensure token exchange happens quickly after authorization
   - Check system clocks are synchronized

2. **Code already used:**
   - Authorization codes are single-use only
   - Generate new authorization request if needed

3. **Code validation:**
   ```bash
   # Check authorization code storage (for debugging)
   # Note: Codes are automatically cleaned up after use/expiration
   ```

## 🔑 Authentication and User Issues

### Password Grant Issues

#### Error: `invalid_grant` (Password Authentication)
**Symptoms:**
```json
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password"
}
```

**Solutions:**
1. **Check user exists and is verified:**
   ```sql
   -- Database check (for administrators)
   SELECT id, email, username, is_verified, is_admin 
   FROM users 
   WHERE email = 'user@example.com';
   ```

2. **Password verification:**
   - Ensure password is sent correctly (no encoding issues)
   - Check for case sensitivity in username/email

3. **Account status:**
   ```python
   # Check user verification status
   user = await user_repository.get_by_email("user@example.com")
   if not user.is_verified:
       # User needs email verification
   ```

#### Error: Rate Limiting
**Symptoms:**
```json
{
  "error": "too_many_requests",
  "error_description": "Rate limit exceeded"
}
```

**Solutions:**
1. **Check rate limiting configuration:**
   ```python
   # In configuration
   RATE_LIMIT_REQUESTS_PER_MINUTE = 100  # Adjust as needed
   ```

2. **Reset rate limiting (for development):**
   ```bash
   # Restart the service to reset in-memory rate limits
   # Or implement Redis-based rate limiting for persistence
   ```

### User Registration Issues

#### Email Verification Not Working
**Symptoms:**
- User receives no verification email
- Verification links don't work

**Solutions:**
1. **Check email configuration:**
   ```bash
   # Verify SMTP settings
   export SMTP_HOST="smtp.gmail.com"
   export SMTP_PORT="587"
   export SMTP_USERNAME="your-email@gmail.com"
   export SMTP_PASSWORD="your-app-password"
   ```

2. **Check email logs:**
   ```python
   import logging
   logging.getLogger("authly.email").setLevel(logging.DEBUG)
   ```

3. **Manual verification (development):**
   ```sql
   -- Manually verify user in database
   UPDATE users 
   SET is_verified = true 
   WHERE email = 'user@example.com';
   ```

## 🗄️ Database Connection Issues

### Connection Pool Problems

#### Error: "Connection pool exhausted"
**Symptoms:**
- Application hangs on database operations
- Timeout errors

**Solutions:**
1. **Increase pool size:**
   ```python
   # In configuration
   DATABASE_POOL_MIN_SIZE = 5
   DATABASE_POOL_MAX_SIZE = 20
   DATABASE_POOL_TIMEOUT = 30
   ```

2. **Check for connection leaks:**
   ```python
   # Ensure proper async context usage
   async with transaction_manager.transaction() as conn:
       # Database operations
       pass  # Connection automatically returned to pool
   ```

3. **Monitor pool status:**
   ```bash
   authly-admin status --verbose
   # Check "Pool: X/Y connections active"
   ```

#### Error: "Database connection refused"
**Symptoms:**
```
psycopg.OperationalError: connection to server failed
```

**Solutions:**
1. **Check database server:**
   ```bash
   # Test direct connection
   psql "postgresql://user:pass@localhost:5432/authly_db" -c "SELECT 1;"
   ```

2. **Verify connection string:**
   ```bash
   # Check DATABASE_URL format
   export DATABASE_URL="postgresql://username:password@host:port/database"
   ```

3. **Database permissions:**
   ```sql
   -- Grant necessary permissions
   GRANT ALL PRIVILEGES ON DATABASE authly_db TO authly_user;
   GRANT ALL ON ALL TABLES IN SCHEMA public TO authly_user;
   GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authly_user;
   ```

### Schema Issues

#### Error: "Table does not exist"
**Symptoms:**
```
psycopg.errors.UndefinedTable: relation "clients" does not exist
```

**Solution:**
```bash
# Run database migrations/schema creation
psql "$DATABASE_URL" -f sql/schema.sql

# Or create tables manually
psql "$DATABASE_URL" -c "
CREATE TABLE IF NOT EXISTS clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id VARCHAR(255) UNIQUE NOT NULL,
  -- ... other columns
);"
```

## 🌐 HTTP and Network Issues

### CORS Problems

#### Error: "CORS policy blocked"
**Symptoms:**
- Browser console shows CORS errors
- API calls from web applications fail

**Solutions:**
1. **Configure CORS properly:**
   ```python
   # In FastAPI application
   from fastapi.middleware.cors import CORSMiddleware
   
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["https://yourapp.com", "http://localhost:3000"],
       allow_credentials=True,
       allow_methods=["GET", "POST", "PUT", "DELETE"],
       allow_headers=["Authorization", "Content-Type"],
   )
   ```

2. **Development CORS:**
   ```python
   # For development only
   allow_origins=["*"]  # Never use in production
   ```

### SSL/TLS Issues

#### Error: "SSL verification failed"
**Symptoms:**
- HTTPS requests fail
- Certificate verification errors

**Solutions:**
1. **Development environment:**
   ```python
   # For development only
   import ssl
   ssl_context = ssl.create_default_context()
   ssl_context.check_hostname = False
   ssl_context.verify_mode = ssl.CERT_NONE
   ```

2. **Production certificates:**
   ```bash
   # Use proper SSL certificates
   # Let's Encrypt, internal CA, or commercial certificate
   ```

## 🖥️ CLI Administration Issues

### CLI Connection Problems

#### Error: "CLI cannot connect to database"
**Symptoms:**
```bash
authly-admin status
# Error: Database connection failed
```

**Solutions:**
1. **Check environment variables:**
   ```bash
   echo $DATABASE_URL
   echo $JWT_SECRET_KEY
   echo $JWT_REFRESH_SECRET_KEY
   ```

2. **Use configuration file:**
   ```bash
   authly-admin --config /path/to/config.toml status
   ```

3. **Test basic connectivity:**
   ```bash
   # Test database connection directly
   psql "$DATABASE_URL" -c "SELECT version();"
   ```

### CLI Permission Issues

#### Error: "Permission denied on table"
**Symptoms:**
```bash
authly-admin client create --name "Test"
# Error: permission denied for table clients
```

**Solution:**
```sql
-- Grant proper permissions to CLI user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authly_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authly_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO authly_admin;
```

## ⚡ Performance Issues

### Slow Database Queries

#### Symptoms:
- Long response times
- High CPU usage
- Query timeouts

**Solutions:**
1. **Check query performance:**
   ```sql
   -- Enable query logging
   ALTER SYSTEM SET log_statement = 'all';
   ALTER SYSTEM SET log_min_duration_statement = 1000; -- Log queries > 1s
   ```

2. **Add missing indexes:**
   ```sql
   -- Add indexes for common queries
   CREATE INDEX CONCURRENTLY idx_tokens_user_id ON tokens(user_id);
   CREATE INDEX CONCURRENTLY idx_tokens_expires_at ON tokens(expires_at);
   CREATE INDEX CONCURRENTLY idx_clients_client_id ON clients(client_id);
   ```

3. **Monitor connection pool:**
   ```bash
   authly-admin status --verbose
   # Check pool utilization and query times
   ```

### Memory Issues

#### High Memory Usage
**Solutions:**
1. **Connection pool tuning:**
   ```python
   # Reduce pool size for low-traffic deployments
   DATABASE_POOL_MAX_SIZE = 5
   ```

2. **Token cleanup:**
   ```sql
   -- Regular cleanup of expired tokens
   DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '1 day';
   DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
   ```

## 🐛 Development and Testing Issues

### Test Failures

#### Intermittent Test Failures
**Symptoms:**
- Tests pass sometimes, fail other times
- Race conditions in async tests

**Solutions:**
1. **Proper test isolation:**
   ```python
   @pytest.mark.asyncio
   async def test_feature(transaction_manager: TransactionManager):
       async with transaction_manager.transaction() as conn:
           # All test operations within transaction
           # Automatic rollback ensures isolation
   ```

2. **Async test patterns:**
   ```python
   # Proper async/await usage
   result = await async_function()
   assert result is not None
   
   # Don't mix sync and async
   # Avoid: result = async_function()  # Wrong!
   ```

### Development Environment Issues

#### Import Errors
**Symptoms:**
```python
ModuleNotFoundError: No module named 'authly'
```

**Solutions:**
1. **Install in development mode:**
   ```bash
   poetry install
   # Or with pip
   pip install -e .
   ```

2. **Python path issues:**
   ```bash
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   ```

## 🔍 Debugging Techniques

### Enable Debug Logging

```python
import logging

# Enable debug logging for Authly
logging.getLogger("authly").setLevel(logging.DEBUG)

# Enable debug logging for database operations
logging.getLogger("psycopg").setLevel(logging.DEBUG)

# Enable debug logging for FastAPI
logging.getLogger("uvicorn").setLevel(logging.DEBUG)
```

### Database Query Debugging

```python
# Log all SQL queries
import logging
logging.getLogger("psycopg.sql").setLevel(logging.DEBUG)

# In code, add query logging
logger = logging.getLogger(__name__)
logger.debug(f"Executing query: {query}")
logger.debug(f"With parameters: {params}")
```

### HTTP Request Debugging

```python
# Log HTTP requests/responses
import logging
logging.getLogger("httpx").setLevel(logging.DEBUG)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response
```

## 📋 Diagnostic Checklist

When encountering issues, work through this checklist:

### Basic System Health
- [ ] Database connection successful (`authly-admin status`)
- [ ] Required environment variables set
- [ ] All required tables exist
- [ ] Basic authentication working (`POST /auth/token` with password grant)

### OAuth 2.1 Specific
- [ ] Client exists and is active (`authly-admin client show`)
- [ ] Redirect URIs match exactly
- [ ] PKCE parameters included in authorization request
- [ ] Code exchange happens within 10 minutes
- [ ] Client authentication configured correctly

### Network and Security
- [ ] CORS configured for client origins
- [ ] SSL/TLS certificates valid
- [ ] Firewall allows required ports
- [ ] Rate limiting not blocking requests

### Performance
- [ ] Database indexes exist for common queries
- [ ] Connection pool not exhausted
- [ ] No memory leaks in long-running processes
- [ ] Regular cleanup of expired tokens/codes

## 🆘 Emergency Procedures

### Complete System Reset (Development Only)

```bash
# 1. Stop all services
pkill -f "uvicorn authly"

# 2. Reset database
dropdb authly_dev
createdb authly_dev
psql authly_dev -f sql/schema.sql

# 3. Clear any cached data
rm -rf __pycache__/
rm -rf .pytest_cache/

# 4. Restart with fresh configuration
export DATABASE_URL="postgresql://user:pass@localhost/authly_dev"
export JWT_SECRET_KEY="new-secret-$(openssl rand -hex 32)"
export JWT_REFRESH_SECRET_KEY="new-refresh-$(openssl rand -hex 32)"

# 5. Restart application
uvicorn authly.main:app --reload
```

### Production Rollback

```bash
# 1. Switch to previous deployment
kubectl rollout undo deployment/authly

# 2. Restore database backup if needed
psql "$DATABASE_URL" < backup_$(date -d yesterday +%Y%m%d).sql

# 3. Clear any invalid cached tokens
redis-cli FLUSHDB  # If using Redis for rate limiting/caching
```

## 📞 Getting Additional Help

### Information to Gather
When seeking help, include:

1. **System Information:**
   ```bash
   authly-admin status --verbose --output json
   ```

2. **Error Details:**
   - Complete error message and stack trace
   - Steps to reproduce
   - Expected vs actual behavior

3. **Configuration:**
   - Relevant environment variables (redact secrets)
   - Database schema version
   - Client configuration (redact secrets)

4. **Logs:**
   - Application logs with debug level
   - Database query logs
   - HTTP access logs

### Log Analysis Commands

```bash
# Search for errors in logs
grep -i "error" /var/log/authly/app.log

# Find OAuth-specific issues
grep -i "oauth\|pkce\|authorization" /var/log/authly/app.log

# Database connection issues
grep -i "psycopg\|connection\|pool" /var/log/authly/app.log

# Performance issues
grep -i "slow\|timeout\|performance" /var/log/authly/app.log
```

This troubleshooting guide covers the most common issues encountered with Authly's OAuth 2.1 implementation. For complex issues not covered here, consider reviewing the specific component documentation in [docs/README.md](README.md) or examining the test cases in [docs/testing-architecture.md](testing-architecture.md) for expected behavior patterns.