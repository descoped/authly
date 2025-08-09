# Authly Database Proxies - Proof of Concept

This is a working proof-of-concept that demonstrates using Authly as the authorization server for PostgreSQL and Redis access.

## How It Works

```
Client → OAuth Token → Proxy → Validate with Authly → Database/Cache
```

1. **Client gets OAuth token** from Authly with appropriate scopes
2. **Client sends queries** to proxy with Bearer token
3. **Proxy validates token** with Authly's introspection endpoint
4. **Proxy checks scopes** (database:read/write, cache:read/write)
5. **Proxy executes query** using service credentials
6. **Results returned** to client

## Quick Start

```bash
# Start everything with authorization proxies
docker compose -f docker-compose.standalone.yml --profile authz up -d

# Wait for services to be ready
sleep 10

# Get an OAuth token from Authly
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=database:read cache:read" \
  http://localhost:8000/api/v1/oauth/token | jq -r '.access_token')

# Use token to query PostgreSQL through proxy
curl -X POST http://localhost:5433/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT COUNT(*) FROM users"}'

# Use token to access Redis through proxy
curl -X POST http://localhost:6380/command \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "SET", "args": ["mykey", "myvalue"]}'
```

## OAuth Scopes

The proxies enforce these OAuth scopes:

- `database:read` - SELECT queries on PostgreSQL
- `database:write` - INSERT, UPDATE, DELETE on PostgreSQL
- `cache:read` - GET operations on Redis
- `cache:write` - SET, DEL operations on Redis

## Python Test Client

```python
# Install dependencies
pip install aiohttp

# Run test client
python test_proxy.py
```

## Security Features

1. **Token Validation**: Every request validated with Authly
2. **Scope Enforcement**: Operations require appropriate scopes
3. **User Isolation**: Redis keys prefixed with user ID
4. **Row-Level Security**: PostgreSQL session variables set for RLS
5. **Audit Trail**: All access logged through Authly

## Production Considerations

This is a proof-of-concept. For production:

1. **Performance**: Add token caching to reduce latency
2. **Connection Pooling**: Reuse database connections
3. **TLS**: Use HTTPS for all communications
4. **High Availability**: Run multiple proxy instances
5. **Monitoring**: Add metrics and alerting

## API Endpoints

### PostgreSQL Proxy (port 5433)

**POST /query**
```json
{
  "query": "SELECT * FROM users WHERE id = $1",
  "params": ["user123"]
}
```

Response:
```json
{
  "data": [{"id": "user123", "username": "john"}],
  "row_count": 1
}
```

### Redis Proxy (port 6380)

**POST /command**
```json
{
  "command": "GET",
  "args": ["mykey"]
}
```

Response:
```json
{
  "result": "myvalue",
  "command": "GET",
  "user": "admin"
}
```

## Benefits Over Traditional Auth

1. **No Database Passwords**: Use OAuth tokens instead
2. **Fine-grained Access**: Control with OAuth scopes
3. **Temporary Access**: Tokens expire automatically
4. **Central Management**: All auth through Authly
5. **Audit Trail**: Every access logged

## Limitations

1. **Additional Latency**: Token validation adds overhead
2. **Complexity**: Extra proxy layer
3. **Limited SQL Support**: Basic queries only
4. **No Prepared Statements**: Simple queries only

## Future Enhancements

1. **JWT Local Validation**: Validate JWTs without network call
2. **Query Caching**: Cache frequently used queries
3. **Connection Pooling**: Reuse database connections
4. **WebSocket Support**: For real-time subscriptions
5. **GraphQL Interface**: Higher-level query language

This demonstrates that Authly can successfully act as an authorization server for database access!