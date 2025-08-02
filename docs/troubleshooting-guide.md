# Troubleshooting Guide

Comprehensive troubleshooting guide for Authly OAuth 2.1 Authorization Server, covering common issues, error scenarios, and solutions for deployment, development, and production environments.

## 🚨 Quick Diagnostic Commands

Before diving into specific issues, run these diagnostic commands to get an overview of system health:

```bash
# Application health check
curl -f http://localhost:8000/health

# Docker services status
docker compose ps

# Check service logs
docker compose logs -f authly

# Database connectivity test
docker compose exec postgres pg_isready -U authly -d authly

# Redis connectivity test  
docker compose exec redis redis-cli ping

# Admin CLI status (if available)
docker compose exec authly authly admin status
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
   docker compose exec authly authly admin client show "your-client-id"
   
   # Create client if missing
   docker compose exec authly authly admin client create \
     --name "Your App" \
     --client-type public \
     --redirect-uri "https://yourapp.com/callback"
   ```

2. **Client is inactive:**
   ```bash
   # List all clients and their status
   docker compose exec authly authly admin client list
   
   # Reactivate client if needed
   docker compose exec authly authly admin client update "your-client-id" --activate
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
const authUrl = `https://auth.example.com/oauth/authorize?` +
  `response_type=code&` +
  `client_id=${clientId}&` +
  `redirect_uri=${redirectUri}&` +
  `scope=openid profile email&` +
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
docker compose exec authly authly admin client show "your-client-id"

# Update client with correct redirect URI
docker compose exec authly authly admin client update "your-client-id" \
  --redirect-uris "https://yourapp.com/callback,https://localhost:3000/callback"

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
docker compose exec authly authly admin scope list

# Check client's assigned scopes
docker compose exec authly authly admin client show "your-client-id"

# Create missing scope if needed
docker compose exec authly authly admin scope create \
  --name "missing-scope" \
  --description "Description for missing scope"
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
const tokenResponse = await fetch('/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
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
   # Check client secret exists
   docker compose exec authly authly admin client show "your-client-id"
   
   # Regenerate if needed
   docker compose exec authly authly admin client regenerate-secret "your-client-id"
   ```
   
   ```javascript
   // Correct Basic authentication
   const credentials = btoa(`${clientId}:${clientSecret}`);
   const response = await fetch('/oauth/token', {
     method: 'POST',
     headers: {
       'Authorization': `Basic ${credentials}`,
       'Content-Type': 'application/x-www-form-urlencoded'
     },
     body: new URLSearchParams({
       grant_type: 'authorization_code',
       code: authCode,
       code_verifier: codeVerifier,
       redirect_uri: redirectUri
     })
   });
   ```

2. **For public clients (no authentication):**
   ```javascript
   // No client_secret required
   const response = await fetch('/oauth/token', {
     method: 'POST',
     headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
     body: new URLSearchParams({
       grant_type: 'authorization_code',
       client_id: clientId,
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
   - Verify `AUTHORIZATION_CODE_EXPIRE_MINUTES` configuration

2. **Code already used:**
   - Authorization codes are single-use only
   - Generate new authorization request if needed

## 🔑 Authentication and User Issues

### Login and User Management

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
   ```bash
   # Check user in database
   docker compose exec postgres psql -U authly -d authly -c \
     "SELECT id, email, username, is_verified, is_active FROM users WHERE email = 'user@example.com';"
   ```

2. **Password verification:**
   - Ensure password is sent correctly (no encoding issues)
   - Check for case sensitivity in username/email

3. **Account status:**
   ```bash
   # Manually verify user (development only)
   docker compose exec postgres psql -U authly -d authly -c \
     "UPDATE users SET is_verified = true WHERE email = 'user@example.com';"
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
   ```bash
   # In .env file
   RATE_LIMIT_MAX_REQUESTS=100
   RATE_LIMIT_WINDOW_SECONDS=60
   ```

2. **For Redis-based rate limiting:**
   ```bash
   # Clear rate limit data in Redis
   docker compose exec redis redis-cli FLUSHDB
   ```

3. **Temporary bypass (development only):**
   ```bash
   # Restart services to reset in-memory rate limits
   docker compose restart authly
   ```

## 🗄️ Database Connection Issues

### Connection Pool Problems

#### Error: "Connection pool exhausted"
**Symptoms:**
- Application hangs on database operations
- Timeout errors in logs
- High response times

**Solutions:**
1. **Check current pool status:**
   ```bash
   # Check application metrics
   curl http://localhost:8000/metrics | grep database_connections
   
   # Check PostgreSQL connections
   docker compose exec postgres psql -U authly -d authly -c \
     "SELECT state, count(*) FROM pg_stat_activity WHERE datname = 'authly' GROUP BY state;"
   ```

2. **Increase pool size:**
   ```bash
   # In .env file
   DATABASE_POOL_MIN_SIZE=5
   DATABASE_POOL_MAX_SIZE=20
   DATABASE_POOL_TIMEOUT=30
   ```

3. **Check for connection leaks:**
   ```bash
   # Monitor connection usage over time
   docker compose logs -f authly | grep -i "pool\|connection"
   ```

#### Error: "Database connection refused"
**Symptoms:**
```
asyncpg.exceptions.ConnectionDoesNotExistError: connection is closed
```

**Solutions:**
1. **Check database server:**
   ```bash
   # Test direct connection
   docker compose exec postgres pg_isready -U authly -d authly
   
   # Check PostgreSQL logs
   docker compose logs postgres
   ```

2. **Verify connection string:**
   ```bash
   # Check DATABASE_URL format in logs (secrets redacted)
   docker compose exec authly printenv DATABASE_URL
   ```

3. **Database permissions:**
   ```sql
   -- Grant necessary permissions
   GRANT ALL PRIVILEGES ON DATABASE authly TO authly;
   GRANT ALL ON ALL TABLES IN SCHEMA public TO authly;
   GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authly;
   ```

### Schema Issues

#### Error: "Table does not exist"
**Symptoms:**
```
asyncpg.exceptions.UndefinedTableError: relation "users" does not exist
```

**Solution:**
```bash
# Check if tables exist
docker compose exec postgres psql -U authly -d authly -c "\dt"

# Run database initialization if needed
docker compose exec postgres psql -U authly -d authly -f /docker-entrypoint-initdb.d/init-db-and-user.sql

# Or recreate database (development only)
docker compose down -v
docker compose up -d
```

## 🌐 Network and HTTP Issues

### CORS Problems

#### Error: "CORS policy blocked"
**Symptoms:**
- Browser console shows CORS errors
- API calls from web applications fail
- Preflight OPTIONS requests fail

**Solutions:**
1. **Check CORS configuration:**
   ```bash
   # In .env file
   CORS_ORIGINS=https://yourapp.com,http://localhost:3000
   ```

2. **For development:**
   ```bash
   # Allow all origins (development only)
   CORS_ORIGINS=*
   ```

3. **Debug CORS headers:**
   ```bash
   # Check CORS headers in response
   curl -H "Origin: http://localhost:3000" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: X-Requested-With" \
        -X OPTIONS \
        http://localhost:8000/oauth/token
   ```

### SSL/TLS Issues

#### Error: "SSL verification failed"
**Symptoms:**
- HTTPS requests fail
- Certificate verification errors
- Browser security warnings

**Solutions:**
1. **Development environment:**
   ```bash
   # Generate self-signed certificates
   ./scripts/setup-dev-certs.sh
   
   # Or use HTTP for development
   DEFAULT_API_URL=http://localhost:8000
   ```

2. **Check certificate validity:**
   ```bash
   # Test SSL certificate
   openssl s_client -connect auth.example.com:443 -servername auth.example.com
   
   # Check certificate expiration
   openssl x509 -in docker-compose/nginx/ssl/cert.pem -text -noout
   ```

3. **Production certificates:**
   ```bash
   # Use Let's Encrypt
   sudo certbot certonly --standalone -d auth.example.com
   
   # Copy certificates to Docker volume
   sudo cp /etc/letsencrypt/live/auth.example.com/fullchain.pem docker-compose/nginx/ssl/cert.pem
   sudo cp /etc/letsencrypt/live/auth.example.com/privkey.pem docker-compose/nginx/ssl/key.pem
   ```

## 🐳 Docker Deployment Issues

### Service Won't Start

**Symptoms:**
- Containers exit immediately
- Services fail health checks
- Port binding errors

**Solutions:**
1. **Check service status:**
   ```bash
   # Check container status
   docker compose ps
   
   # Check resource usage
   docker stats
   
   # Check system resources
   df -h
   free -h
   ```

2. **Check service logs:**
   ```bash
   # View service logs
   docker compose logs authly
   docker compose logs postgres
   docker compose logs redis
   
   # Follow logs in real-time
   docker compose logs -f --tail=100 authly
   ```

3. **Port conflicts:**
   ```bash
   # Check if ports are already in use
   netstat -tulpn | grep :8000
   netstat -tulpn | grep :5432
   
   # Use different ports if needed
   AUTHLY_PORT=8001 docker compose up -d
   ```

### Container Build Issues

#### Error: "Image build failed"
**Solutions:**
1. **Clear Docker cache:**
   ```bash
   # Clear build cache
   docker system prune -a
   
   # Rebuild without cache
   docker compose build --no-cache
   ```

2. **Check Docker space:**
   ```bash
   # Check Docker disk usage
   docker system df
   
   # Clean up unused resources
   docker system prune -f
   ```

### Volume Permission Issues

#### Error: "Permission denied"
**Solutions:**
1. **Fix volume permissions:**
   ```bash
   # Check volume permissions
   docker compose exec postgres ls -la /var/lib/postgresql/data
   
   # Fix PostgreSQL permissions
   docker compose exec postgres chown -R postgres:postgres /var/lib/postgresql/data
   ```

## 🔧 Redis Issues

### Redis Connection Problems

#### Error: "Redis connection failed"
**Symptoms:**
- Cache operations fail
- Rate limiting not working
- Session storage errors

**Solutions:**
1. **Check Redis connectivity:**
   ```bash
   # Test Redis connection
   docker compose exec redis redis-cli ping
   
   # Test with password
   docker compose exec redis redis-cli -a redis_dev_password ping
   
   # Check Redis logs
   docker compose logs redis
   ```

2. **Redis configuration:**
   ```bash
   # Check Redis info
   docker compose exec redis redis-cli info server
   
   # Check memory usage
   docker compose exec redis redis-cli info memory
   ```

3. **Clear Redis data (if safe):**
   ```bash
   # Clear all Redis data
   docker compose exec redis redis-cli FLUSHALL
   
   # Clear specific pattern
   docker compose exec redis redis-cli --scan --pattern "authly:*" | xargs docker compose exec redis redis-cli del
   ```

## ⚡ Performance Issues

### Slow Response Times

**Symptoms:**
- High response latencies
- Timeouts
- Poor user experience

**Solutions:**
1. **Check application metrics:**
   ```bash
   # Check metrics endpoint
   curl http://localhost:8000/metrics
   
   # Monitor response times
   curl -o /dev/null -s -w "Total time: %{time_total}s\n" http://localhost:8000/health
   ```

2. **Database performance:**
   ```sql
   -- Check slow queries
   SELECT query, calls, total_time, mean_time 
   FROM pg_stat_statements 
   ORDER BY total_time DESC LIMIT 10;
   
   -- Check database locks
   SELECT * FROM pg_locks WHERE NOT granted;
   ```

3. **Add missing indexes:**
   ```sql
   -- Common performance indexes
   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_auth_codes_expires_at ON authorization_codes(expires_at);
   ```

### Memory Issues

#### High Memory Usage
**Solutions:**
1. **Check memory usage:**
   ```bash
   # Check container memory usage
   docker stats --no-stream
   
   # Check system memory
   free -h
   ```

2. **Database optimization:**
   ```sql
   -- Clean up expired tokens
   DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '1 day';
   DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
   
   -- Vacuum tables
   VACUUM ANALYZE tokens;
   VACUUM ANALYZE authorization_codes;
   ```

3. **Connection pool tuning:**
   ```bash
   # Reduce pool size for low-traffic deployments
   DATABASE_POOL_MAX_SIZE=5
   DATABASE_POOL_MIN_SIZE=2
   ```

## 🐛 Development Issues

### Import and Module Errors

#### Error: `ModuleNotFoundError`
**Symptoms:**
```python
ModuleNotFoundError: No module named 'authly'
```

**Solutions:**
1. **Install in development mode:**
   ```bash
   # Using Poetry (recommended)
   poetry install
   poetry shell
   
   # Using pip
   pip install -e .
   ```

2. **Python path issues:**
   ```bash
   # Set Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   
   # Or use full path imports
   python -m authly.main
   ```

### Test Failures

#### Intermittent Test Failures
**Solutions:**
1. **Proper test isolation:**
   ```python
   # Use transaction rollback for test isolation
   @pytest.mark.asyncio
   async def test_feature(transaction_manager: TransactionManager):
       async with transaction_manager.transaction() as conn:
           # Test operations - automatically rolled back
           pass
   ```

2. **Async test patterns:**
   ```python
   # Proper async/await usage
   @pytest.mark.asyncio
   async def test_async_function():
       result = await async_function()
       assert result is not None
   ```

3. **Test database cleanup:**
   ```bash
   # Reset test database
   docker compose exec postgres psql -U authly -d authly_test -c "TRUNCATE TABLE tokens, authorization_codes CASCADE;"
   ```

## 🔍 Debugging Techniques

### Enable Debug Logging

```bash
# Set debug logging level
export AUTHLY_LOG_LEVEL=DEBUG

# Or in .env file
AUTHLY_LOG_LEVEL=DEBUG

# View structured logs
docker compose logs authly | jq '.'
```

### Database Query Debugging

```bash
# Enable PostgreSQL query logging
docker compose exec postgres psql -U authly -d authly -c \
  "ALTER SYSTEM SET log_statement = 'all';"

docker compose exec postgres psql -U authly -d authly -c \
  "ALTER SYSTEM SET log_min_duration_statement = 100;"

# Restart PostgreSQL to apply changes
docker compose restart postgres
```

### HTTP Request Debugging

```bash
# Trace HTTP requests with curl
curl -v -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test&client_secret=secret"

# Monitor network traffic
docker compose exec authly netstat -tulpn
```

## 📋 Diagnostic Checklist

When encountering issues, work through this checklist:

### Basic System Health
- [ ] All containers running (`docker compose ps`)
- [ ] Database connection successful (`pg_isready`)
- [ ] Redis connection working (`redis-cli ping`)
- [ ] Health endpoint responding (`curl /health`)
- [ ] Required environment variables set

### OAuth 2.1 Specific
- [ ] Client exists and is active
- [ ] Redirect URIs match exactly
- [ ] PKCE parameters included in authorization requests
- [ ] Code exchange happens within timeout period
- [ ] Client authentication configured correctly
- [ ] Scopes are valid and assigned to client

### Network and Security
- [ ] CORS configured for client origins
- [ ] SSL/TLS certificates valid (production)
- [ ] Firewall allows required ports
- [ ] Rate limiting not blocking legitimate requests
- [ ] Security headers present in responses

### Performance
- [ ] Database indexes exist for common queries
- [ ] Connection pool not exhausted
- [ ] No memory leaks in long-running processes
- [ ] Regular cleanup of expired tokens/codes
- [ ] Reasonable response times (<500ms for most operations)

## 🆘 Emergency Procedures

### Complete System Reset (Development Only)

```bash
# 1. Stop all services
docker compose down

# 2. Remove volumes (WARNING: deletes all data)
docker compose down -v

# 3. Clear Docker cache
docker system prune -f

# 4. Rebuild and restart
docker compose build --no-cache
docker compose up -d

# 5. Verify system health
curl http://localhost:8000/health
```

### Production Rollback

```bash
# 1. Switch to previous Docker image
docker compose pull descoped/authly:previous-version
AUTHLY_VERSION=previous-version docker compose up -d

# 2. Restore database backup if needed
docker compose exec postgres psql -U authly -d authly < backup.sql

# 3. Clear cache if needed
docker compose exec redis redis-cli FLUSHALL

# 4. Verify system is operational
curl https://auth.example.com/health
```

## 📞 Getting Additional Help

### Information to Gather

When seeking help, include:

1. **System Information:**
   ```bash
   # Docker environment
   docker compose version
   docker version
   docker compose ps
   docker compose logs --tail=50 authly
   ```

2. **Configuration (redact secrets):**
   ```bash
   # Environment variables (without secrets)
   docker compose exec authly printenv | grep -E "^(AUTHLY|DATABASE|REDIS)" | sed 's/=.*SECRET.*/=***/'
   ```

3. **Error Details:**
   - Complete error message and stack trace
   - Steps to reproduce
   - Expected vs actual behavior
   - When the issue started occurring

4. **Network and Timing:**
   ```bash
   # Test connectivity
   curl -v http://localhost:8000/health
   curl -v http://localhost:8000/.well-known/oauth-authorization-server
   ```

### Log Analysis Commands

```bash
# Search for errors in logs
docker compose logs authly | grep -i error

# Find OAuth-specific issues
docker compose logs authly | grep -i "oauth\|pkce\|authorization"

# Database connection issues
docker compose logs authly | grep -i "database\|connection\|pool"

# Performance issues
docker compose logs authly | grep -i "slow\|timeout\|performance"

# Extract structured logs
docker compose logs authly | jq -r 'select(.level == "ERROR") | "\(.timestamp): \(.message)"'
```

This troubleshooting guide covers the most common issues encountered with Authly's OAuth 2.1 implementation across development, testing, and production environments. For complex issues not covered here, consider reviewing the specific component documentation or examining the test cases for expected behavior patterns.