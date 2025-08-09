# Using Authly as Authorization Server for PostgreSQL & Redis

## Concept: Eating Our Own Dog Food

This document outlines how to use Authly as the authorization server for PostgreSQL and Redis/KeyDB access in the standalone container.

## Architecture

```
┌─────────────────┐
│   pgAdmin       │──────┐
└─────────────────┘      │
                         ▼
┌─────────────────┐    ┌─────────────────┐
│ Redis Commander │───▶│     Authly      │
└─────────────────┘    │  (AuthZ Server) │
                       └─────────────────┘
                              │ │
                    ┌─────────┘ └─────────┐
                    ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │  PostgreSQL  │      │    KeyDB     │
            └──────────────┘      └──────────────┘
```

## Implementation Options

### Option 1: PAM Authentication (PostgreSQL)

Create a PAM module that validates OAuth tokens with Authly:

```bash
# /etc/pam.d/postgresql
auth required pam_authly.so \
  authly_url=http://localhost:8000/api/v1/oauth/introspect \
  required_scope=database:access
```

### Option 2: Custom Authentication Hook (PostgreSQL)

Use PostgreSQL's authentication hook to validate tokens:

```sql
-- Create authentication function
CREATE OR REPLACE FUNCTION authly_check_token(token text)
RETURNS boolean AS $$
DECLARE
  response json;
BEGIN
  -- Call Authly's introspection endpoint
  SELECT content::json INTO response
  FROM http_post(
    'http://localhost:8000/api/v1/oauth/introspect',
    'token=' || token,
    'application/x-www-form-urlencoded'
  );
  
  RETURN response->>'active' = 'true';
END;
$$ LANGUAGE plpgsql;
```

### Option 3: Proxy Authentication

Create a proxy that handles authentication before forwarding to the database:

```python
# authly_db_proxy.py
from authly.oauth import introspect_token
import asyncpg
import asyncio

class AuthlyDatabaseProxy:
    def __init__(self, authly_url, db_url):
        self.authly_url = authly_url
        self.db_url = db_url
    
    async def handle_connection(self, reader, writer):
        # Extract token from connection
        token = await self.extract_token(reader)
        
        # Validate with Authly
        if not await self.validate_token(token):
            writer.write(b"Authentication failed\n")
            await writer.drain()
            writer.close()
            return
        
        # Proxy to real database
        await self.proxy_to_database(reader, writer)
```

## Redis/KeyDB ACL Integration

### Dynamic ACL Generation from Authly

```python
# sync_redis_acl.py
import redis
import requests

def sync_redis_users_with_authly():
    """Sync Redis ACL with Authly users"""
    
    # Get users from Authly
    authly_users = requests.get(
        "http://localhost:8000/api/v1/admin/users",
        headers={"Authorization": "Bearer <admin_token>"}
    ).json()
    
    # Connect to Redis
    r = redis.Redis(host='localhost', port=6379)
    
    for user in authly_users:
        # Create Redis user with Authly credentials
        r.acl_setuser(
            user['username'],
            enabled=True,
            passwords=[f"authly:{user['id']}"],  # Use Authly ID as password
            commands=['+@read', '+@write'] if user['is_admin'] else ['+@read'],
            keys=['*']
        )

# Run periodically or on user changes
sync_redis_users_with_authly()
```

### Redis AUTH Command Override

Create a Redis module that validates tokens with Authly:

```c
// authly_redis_auth.c
#include "redismodule.h"

int AuthlyAuth_Command(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);
    
    const char *token = RedisModule_StringPtrLen(argv[1], NULL);
    
    // Validate token with Authly
    if (validate_with_authly(token)) {
        // Set authenticated context
        RedisModule_AuthenticateClient(ctx);
        RedisModule_ReplyWithSimpleString(ctx, "OK");
    } else {
        RedisModule_ReplyWithError(ctx, "ERR invalid token");
    }
    
    return REDISMODULE_OK;
}
```

## OAuth Scopes for Database Access

Define specific scopes in Authly for database operations:

```yaml
scopes:
  # PostgreSQL scopes
  - postgres:read      # SELECT operations
  - postgres:write     # INSERT, UPDATE, DELETE
  - postgres:admin     # DDL operations, user management
  
  # Redis scopes  
  - redis:read        # GET, MGET, etc.
  - redis:write       # SET, DEL, etc.
  - redis:admin       # CONFIG, FLUSHDB, etc.
  
  # Combined scopes
  - database:full     # Full access to all databases
```

## Implementation in Standalone Container

### Step 1: Add OAuth Token Support to psql Wrapper

```bash
#!/bin/sh
# /opt/postgresql/bin/psql wrapper with Authly auth

# Check for AUTHLY_TOKEN environment variable
if [ -n "$AUTHLY_TOKEN" ]; then
    # Validate token with Authly
    VALID=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$AUTHLY_TOKEN" \
        http://localhost:8000/api/v1/oauth/introspect \
        | jq -r '.active')
    
    if [ "$VALID" = "true" ]; then
        # Extract username from token
        USERNAME=$(curl -s -X POST \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "token=$AUTHLY_TOKEN" \
            http://localhost:8000/api/v1/oauth/introspect \
            | jq -r '.username')
        
        # Connect with extracted username
        exec /opt/postgresql/bin/psql.orig -h /run/postgresql -U "$USERNAME" "$@"
    else
        echo "Error: Invalid Authly token"
        exit 1
    fi
else
    # Fallback to default authentication
    exec /opt/postgresql/bin/psql.orig -h /run/postgresql -U authly -d authly "$@"
fi
```

### Step 2: Token-based Connection String

```bash
# Connect using Authly token
AUTHLY_TOKEN=$(authly admin auth login --show-token | jq -r '.access_token')
export DATABASE_URL="postgresql://token:${AUTHLY_TOKEN}@localhost:5432/authly"
```

### Step 3: Management Tools Configuration

Configure pgAdmin and Redis Commander to use OAuth tokens:

```python
# pgadmin_authly_auth.py
def authenticate_with_authly(username, password):
    """Use Authly OAuth for pgAdmin authentication"""
    
    # If password starts with "token:", treat as OAuth token
    if password.startswith("token:"):
        token = password[6:]
        response = requests.post(
            "http://authly-standalone:8000/api/v1/oauth/introspect",
            data={"token": token}
        )
        return response.json().get("active", False)
    
    # Otherwise, standard password auth
    return validate_password(username, password)
```

## Benefits

1. **Single Source of Truth**: All authentication/authorization through Authly
2. **Fine-grained Access Control**: OAuth scopes map to database permissions
3. **Token-based Access**: No need to manage database passwords
4. **Audit Trail**: All access logged through Authly
5. **Dynamic Permissions**: Update access without database restarts

## Security Considerations

1. **Token Expiration**: Database connections should handle token refresh
2. **Scope Validation**: Ensure scopes match required database operations
3. **Network Security**: Use TLS for token validation requests
4. **Connection Pooling**: Handle token refresh in connection pools
5. **Fallback Auth**: Maintain emergency access method

## Future Enhancements

1. **JWT Validation**: Local JWT validation without network calls
2. **Permission Caching**: Cache permissions for performance
3. **Dynamic Role Mapping**: Map OAuth scopes to database roles
4. **Audit Integration**: Stream database audit logs to Authly
5. **Multi-tenancy**: Isolate database access by OAuth client/tenant

## Testing

```bash
# 1. Get an Authly token
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=database:full" \
  http://localhost:8000/api/v1/oauth/token | jq -r '.access_token')

# 2. Use token for PostgreSQL access
AUTHLY_TOKEN=$TOKEN psql

# 3. Use token for Redis access
redis-cli -a "token:$TOKEN"
```

This is a proof-of-concept for using Authly as the central authorization server for all services in the container.