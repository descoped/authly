# Authly Standalone Docker Image

The `descoped/authly-standalone` image is an all-in-one container that includes Authly with embedded PostgreSQL 17 and KeyDB (Redis-compatible), perfect for testing, development, and troubleshooting.

## What's New

- **🔍 OAuth Token Introspection**: RFC 7662 compliant introspection endpoint at `/api/v1/oauth/introspect`
- **🔌 Remote Database Access**: PostgreSQL (5432) and Redis (6379) ports can be exposed for external tools
- **📊 Management Tools**: pgAdmin, Redis Commander, Prometheus, and Grafana via docker-compose
- **🔐 OAuth Database Auth**: Experimental proxy servers for token-based database access
- **🚀 Service URLs Display**: Automatic display of all service endpoints on startup
- **🛠️ Enhanced Troubleshooting**: 300+ MB of debugging tools (htop, tcpdump, vim, git, etc.)

## Features

- **Zero Dependencies**: Everything needed runs in a single container
- **Production Tools**: Full sysadmin utilities for debugging (htop, tcpdump, vim, git, etc.)
- **Direct Database Access**: `psql` and `redis` commands with tab completion
- **Service URL Display**: Automatic display of all service URLs on startup
- **Remote Access**: PostgreSQL (5432) and Redis (6379) ports can be exposed
- **Management Tools**: Optional pgAdmin, Redis Commander, Prometheus, Grafana via docker-compose
- **OAuth Authorization**: Experimental proxy for token-based database access
- **Quick Start**: Running in seconds with no configuration
- **Developer Friendly**: Direct CLI access with `authly` command
- **Persistent Data**: Optional volume mounting for data persistence
- **Multi-Architecture**: Supports both AMD64 and ARM64
- **Size**: ~771MB with all troubleshooting tools included

## Quick Start

### Simplest Usage - Ephemeral

```bash
# Run with default settings (data is lost when container stops)
docker run -it --rm -p 8000:8000 descoped/authly-standalone
```

### Interactive Development

```bash
# Start container in background
docker run -d --name authly -p 8000:8000 -e AUTHLY_ADMIN_PASSWORD=admin descoped/authly-standalone

# Enter interactive shell
docker exec -it authly bash

# Inside the container:
authly> authly --help                   # Main CLI with all commands
authly> man authly                      # Manual with how-to guides and testing docs
authly> psql                            # Direct database access with tab completion
authly> redis                           # Direct cache access (KeyDB/Redis)
authly> simple-auth-flow                # OAuth flow testing
authly> run-end-to-end-test comprehensive  # Full integration tests
authly> unlock-admin-account            # Unlock admin if locked out
```

### Production-like with Persistence

```bash
docker run -d \
  --name authly \
  -p 8000:8000 \
  -v authly-data:/data \
  -e JWT_SECRET_KEY=your-secret-key-here \
  -e AUTHLY_ADMIN_PASSWORD=secure-password \
  descoped/authly-standalone
```

### Full Access Mode (Development/Debugging)

```bash
# Expose all internal services for remote access
docker run -d \
  --name authly \
  -p 8000:8000 \    # Authly API
  -p 5432:5432 \    # PostgreSQL direct access
  -p 6379:6379 \    # KeyDB/Redis direct access
  -e AUTHLY_ADMIN_PASSWORD=admin \
  descoped/authly-standalone

# Connect from host machine:
psql -h localhost -p 5432 -U authly -d authly  # password: authly
redis-cli -h localhost -p 6379
curl http://localhost:8000/health
```

### Service URLs on Startup

When the container starts, it displays all available service URLs:

```
================================================================================
🚀 All services are ready!
================================================================================

Service URLs (from container):
  • Authly API:        http://localhost:8000
  • PostgreSQL:        postgresql://authly:authly@localhost:5432/authly
  • KeyDB/Redis:       redis://localhost:6379

Service URLs (from host - use these ports in docker run):
  • Authly API:        http://localhost:8000     (-p 8000:8000)
  • PostgreSQL:        localhost:5432             (-p 5432:5432)
  • KeyDB/Redis:       localhost:6379             (-p 6379:6379)

Health check:          curl http://localhost:8000/health
OpenAPI docs:          http://localhost:8000/docs
================================================================================
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | dev-standalone-insecure-key | JWT signing key (⚠️ change in production!) |
| `JWT_REFRESH_SECRET_KEY` | dev-standalone-insecure-refresh-key | Refresh token key (⚠️ change in production!) |
| `AUTHLY_ADMIN_PASSWORD` | admin | Admin user password |
| `AUTHLY_ADMIN_USERNAME` | admin | Admin username |
| `AUTHLY_ADMIN_EMAIL` | admin@localhost | Admin email |
| `DATABASE_URL` | (auto-configured) | PostgreSQL connection string |
| `REDIS_URL` | (auto-configured) | Redis connection string |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | 60 | Time window for rate limiting |
| `AUTHLY_LOCKOUT_MAX_ATTEMPTS` | 10 | Max failed login attempts |
| `AUTHLY_LOCKOUT_DURATION_SECONDS` | 300 | Lockout duration (5 minutes) |

## Direct Database Access

The container provides immediate access to both data stores:

### PostgreSQL
```bash
authly> psql
authly=# SELECT * FROM users;           # Don't forget the semicolon!
authly=# :tables                        # List all tables
authly=# :stats                         # Show database statistics
authly=# :users                         # Show recent users
authly=# \q                            # Quit
```

### Redis/KeyDB
```bash
authly> redis
127.0.0.1:6379> PING
127.0.0.1:6379> KEYS *                 # Show all keys
127.0.0.1:6379> INFO memory            # Memory statistics
127.0.0.1:6379> MONITOR                # Watch commands in real-time
127.0.0.1:6379> QUIT
```

Both support tab completion for commands!

## Admin CLI Usage

### Authentication with Token Display
```bash
# Login and show tokens (useful for debugging)
authly> authly admin auth login --show-token
Username: admin
Password: [enter password]
# Displays access token, refresh token, expiration, and granted scopes
```

### Client Management
```bash
# Create OAuth client
authly> authly admin client create \
  --name "My App" \
  --type public \
  --redirect-uri "http://localhost:3000/callback"

# List clients
authly> authly admin client list
```

## Testing Tools

### Integration Tests
```bash
# Run full test suite (9 modules, ~7 seconds)
authly> run-end-to-end-test comprehensive

# Expected: 9 passed, 0 failed, 2 skipped
```

### OAuth Flow Testing
```bash
# Interactive OAuth flow tests (16 tests)
authly> simple-auth-flow
# When prompted, enter 'y' to create test user
```

### Account Recovery
```bash
# If admin account gets locked after failed attempts
authly> unlock-admin-account
# This clears lockout, resets flags, and restarts service
```

## Troubleshooting Tools

The container includes comprehensive sysadmin utilities:

### System Monitoring
```bash
w                    # Show load average and uptime
htop                 # Interactive process monitor
sysinfo              # Custom system resource summary
topmem               # Top 10 memory consumers
topcpu               # Top 10 CPU consumers
dbcheck              # Check database connections
```

### Network Debugging
```bash
netstat -antp        # All connections
tcpdump -i any       # Packet capture
whoisport 8000       # Find process on port
connection_count     # Connections by IP
```

### Python Debugging
```bash
pyinfo               # Python process inspection
strace -p PID        # Trace system calls
authly_errors        # Show Authly errors from logs
```

See `alias` for all available shortcuts.

## Docker Compose with Management Tools

The standalone image can be used with additional management and monitoring tools:

### Basic Usage
```bash
# Just Authly standalone
docker compose -f docker-compose.standalone.yml up -d

# With management tools (pgAdmin, Redis Commander)
docker compose -f docker-compose.standalone.yml --profile tools up -d

# With monitoring stack (Prometheus, Grafana)
docker compose -f docker-compose.standalone.yml --profile monitoring up -d

# With OAuth authorization proxies (experimental)
docker compose -f docker-compose.standalone.yml --profile authz up -d

# Everything
docker compose -f docker-compose.standalone.yml \
  --profile tools --profile monitoring --profile authz up -d
```

### Available Services

| Service | URL | Credentials | Profile |
|---------|-----|-------------|---------|
| Authly API | http://localhost:8000 | admin / admin | (always) |
| PostgreSQL | localhost:5432 | authly / authly | (always) |
| Redis/KeyDB | localhost:6379 | (none) | (always) |
| pgAdmin | http://localhost:5050 | admin@authly.localhost / admin | tools |
| Redis Commander | http://localhost:8081 | admin / admin | tools |
| Prometheus | http://localhost:9090 | (none) | monitoring |
| Grafana | http://localhost:3000 | admin / admin | monitoring |
| PG Proxy (OAuth) | localhost:5433 | Bearer token | authz |
| Redis Proxy (OAuth) | localhost:6380 | Bearer token | authz |

## OAuth Authorization for Databases (Experimental)

The standalone container includes experimental support for using Authly as the authorization server for database access. This implementation uses the **OAuth 2.0 Token Introspection endpoint (RFC 7662)** to validate tokens and enforce scope-based access control.

### Token Introspection Endpoint

Authly provides a fully compliant RFC 7662 introspection endpoint:

**Endpoint:** `POST /api/v1/oauth/introspect`

**Example Response for Valid Token:**
```json
{
  "active": true,
  "scope": "openid profile database:read database:write",
  "token_type": "Bearer",
  "exp": 1754696255,
  "iat": 1754692655,
  "sub": "test-user-id",
  "jti": "test-token-id"
}
```

**Example Response for Invalid/Expired Token:**
```json
{
  "active": false
}
```

### How OAuth Database Authorization Works

Instead of using database passwords, clients authenticate with OAuth tokens:

```bash
# 1. Get an OAuth token from Authly
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=database:read database:write" \
  http://localhost:8000/api/v1/oauth/token | jq -r '.access_token')

# 2. Test token introspection directly
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${TOKEN}&token_type_hint=access_token" \
  http://localhost:8000/api/v1/oauth/introspect | jq .

# 3. Query PostgreSQL using token (via proxy on port 5433)
curl -X POST http://localhost:5433/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT COUNT(*) FROM users"}'

# 4. Access Redis using token (via proxy on port 6380)
curl -X POST http://localhost:6380/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "GET", "args": ["mykey"]}'
```

### OAuth Scopes for Database Access

The system supports fine-grained access control with these scopes:

- **`database:read`** - SELECT queries on PostgreSQL
- **`database:write`** - INSERT, UPDATE, DELETE on PostgreSQL  
- **`cache:read`** - GET operations on Redis/KeyDB
- **`cache:write`** - SET, DEL operations on Redis/KeyDB

### Proxy Server Integration

The database proxy servers validate tokens using the introspection endpoint:

1. **Client sends request** with `Authorization: Bearer <token>` header
2. **Proxy extracts token** and calls introspection endpoint
3. **Authly validates token** and returns metadata including scopes
4. **Proxy checks required scope** (e.g., `database:read` for SELECT)
5. **Request is allowed/denied** based on token validity and scopes

This demonstrates using Authly as a central authorization server for all infrastructure components.

### Testing Token Introspection

**Create a test token:**
```bash
# Generate test token using container's JWT secret
docker exec authly-app bash -c "
source /app/.venv/bin/activate && python -c \"
import jwt
from datetime import datetime, timedelta, timezone

payload = {
    'sub': 'test-user-id',
    'username': 'testuser', 
    'scope': 'openid profile database:read database:write cache:read cache:write',
    'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    'iat': int(datetime.now(timezone.utc).timestamp()),
    'jti': 'test-token-id'
}

secret = 'ci-test-secret-key-256-bit-long-for-jwt-tokens'
token = jwt.encode(payload, secret, algorithm='HS256')
print(token)
\"
"
```

**Test introspection:**
```bash
# Test valid token
VALID_TOKEN="your_generated_token_here"
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${VALID_TOKEN}&token_type_hint=access_token" \
  http://localhost:8000/api/v1/oauth/introspect | jq .

# Test invalid token
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=invalid.token.here" \
  http://localhost:8000/api/v1/oauth/introspect | jq .
```

## Data Persistence

The container stores all data in `/data`:
- `/data/postgres` - PostgreSQL 17 database files
- `/data/redis` - KeyDB persistence (if enabled)
- `/data/authly` - Application data

To persist data:
```bash
docker run -v authly-data:/data ...
```

## Health Checks

```bash
# Container health status
docker ps --filter "name=authly" --format "table {{.Names}}\t{{.Status}}"

# API health
curl http://localhost:8000/health
```

## Security Considerations

### ⚠️ Production Checklist
- [ ] **Change default JWT secrets** - The defaults are insecure!
- [ ] Set strong admin password
- [ ] Use TLS/HTTPS (reverse proxy recommended)
- [ ] Limit resource usage
- [ ] Regular backups
- [ ] Monitor logs
- [ ] Keep image updated

### ⚠️ Port Exposure Warning
When exposing PostgreSQL (5432) and Redis (6379) ports:
- **Development**: OK for local debugging
- **Production**: NEVER expose these ports publicly
- Use firewall rules to restrict access
- Default PostgreSQL password is `authly` - change it!
- Redis has no authentication by default - secure it!

### Backup and Restore

**Backup:**
```bash
docker run --rm -v authly-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/authly-backup-$(date +%Y%m%d).tar.gz /data
```

**Restore:**
```bash
docker run --rm -v authly-data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/authly-backup-20240101.tar.gz -C /
```

## Troubleshooting

### Services Not Connecting
```bash
# Check if Authly is healthy
docker exec authly-standalone curl http://localhost:8000/health

# Check PostgreSQL
docker exec authly-standalone psql -c "SELECT 1"

# Check Redis
docker exec authly-standalone redis PING
```

### Cannot Connect from Host
```bash
# Ensure ports are exposed
docker ps  # Check PORTS column shows 0.0.0.0:5432->5432/tcp

# Test PostgreSQL connection
PGPASSWORD=authly psql -h localhost -p 5432 -U authly -d authly -c "SELECT 1"

# Test Redis connection  
echo "PING" | nc localhost 6379
```

### Management Tools Not Working
```bash
# Ensure you're using the right profile
docker compose -f docker-compose.standalone.yml --profile tools ps

# Check pgAdmin logs
docker logs authly-pgadmin

# Check Redis Commander logs
docker logs authly-redis-commander
```

### OAuth Proxy Issues
```bash
# Check proxy is running
docker compose -f docker-compose.standalone.yml --profile authz ps

# Test token generation
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=database:read"

# Test introspection endpoint directly
curl -X POST http://localhost:8000/api/v1/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=invalid.token.here"
# Should return: {"active": false}

# Test with valid token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=database:read" | jq -r '.access_token')

curl -X POST http://localhost:8000/api/v1/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${TOKEN}&token_type_hint=access_token"
# Should return: {"active": true, "scope": "database:read", ...}

# Check proxy logs
docker logs authly-pg-proxy
docker logs authly-redis-proxy
```

## Limitations

The standalone image is perfect for:
- Development and testing
- Troubleshooting production issues
- POCs and demos
- CI/CD pipelines
- Small deployments (<1000 users)

For larger deployments, consider:
- Using separate PostgreSQL and Redis instances
- The standard `descoped/authly` image with external databases
- Kubernetes deployment with proper scaling

## Support

- **Issues**: https://github.com/descoped/authly/issues
- **Documentation**: https://github.com/descoped/authly
- **Docker Hub**: https://hub.docker.com/r/descoped/authly-standalone
- **Compose Examples**: See `docker-compose.standalone.yml` for full configuration
- **OAuth Proxy Docs**: See `docker-standalone/authly-db-proxy/README.md`