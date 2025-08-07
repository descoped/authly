# Authly Standalone Interactive Shell Demo

This demonstrates the interactive shell experience described in the plan.

## Quick Start Interactive Session

```bash
# Pull and run the standalone container
docker run -it --rm -p 8000:8000 descoped/authly-standalone

# You'll see:
Welcome to Authly Standalone!
Services: PostgreSQL, Redis, and Authly are running
Try: authly --help, authly-admin --help, or authly-test comprehensive

authly> # <-- This is your interactive shell prompt
```

## Inside the Container Shell

The container provides a complete OAuth/OIDC development environment with:

### 1. Direct CLI Access
```bash
authly> authly --help                    # Show all available commands
authly> authly-admin --help              # Direct admin CLI access
authly> authly admin client --help       # OAuth client management
authly> authly admin user --help         # User management (if implemented)
authly> authly serve --help              # Server commands (already running)
```

### 2. Create OAuth Clients
```bash
authly> authly admin client create --name "My Test App" --client-type public --redirect-uri "http://localhost:3000/callback"
✅ Client created successfully!
  Client ID: client_CsRzIMupN9ZsdoKXRmg8zg
  Client Name: My Test App
  Client Type: public
  Client Secret: None (public client)
```

### 3. List OAuth Clients
```bash
authly> authly admin client list
```

### 4. Create Custom Scopes
```bash
authly> authly admin scope create --name "read:users" --description "Read user information"
```

### 5. Run Integration Tests
```bash
authly> authly-test comprehensive        # Full test suite
authly> authly-test admin               # Just admin tests
authly> authly-test oauth               # OAuth flow tests
authly> authly-test oidc-discovery      # OIDC discovery tests
```

### 6. Check System Status
```bash
authly> curl http://localhost:8000/health
{"status":"healthy","database":"connected"}

authly> curl http://localhost:8000/.well-known/openid_configuration | jq
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
  "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
  ...
}
```

## Development Workflow

The interactive shell makes it easy to:

1. **Quick Prototyping**: Test OAuth flows immediately without external dependencies
2. **Client Development**: Create test clients for your applications  
3. **Integration Testing**: Validate your implementation against a real OAuth/OIDC server
4. **Learning**: Explore OAuth 2.1 and OIDC 1.0 concepts hands-on

## Available Tools

Inside the container you have:
- `authly` - Full CLI access to all Authly commands
- `authly-test` - Integrated test runner for OAuth/OIDC conformance
- `curl` - HTTP client for testing endpoints
- `jq` - JSON processing for parsing responses
- `psql` - Direct PostgreSQL access (if needed)
- `redis-cli` - Redis debugging (if needed)

## Production Note

This interactive mode is designed for development and testing. For production deployments, use the container without interactive mode and configure through environment variables.