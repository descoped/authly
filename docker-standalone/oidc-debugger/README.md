# OAuth2/OIDC Debugger Integration with Authly

This directory contains a Docker-based integration of the [OAuth2/OIDC Debugger](https://github.com/rcbj/oauth2-oidc-debugger) tool, pre-configured to work with Authly's OAuth and OpenID Connect implementation.

## Overview

The OAuth2/OIDC Debugger is an interactive testing tool that helps developers understand and debug OAuth 2.0 and OpenID Connect flows. This integration provides:

- **Pre-configured endpoints** for Authly
- **Interactive UI** for testing various OAuth/OIDC flows
- **Support for all major grant types** and authentication flows
- **Token introspection** and validation
- **PKCE support** for enhanced security

## Features

### Supported OAuth2 Grants
- Authorization Code Grant
- Implicit Grant
- Resource Owner Password Grant
- Client Credentials Grant
- Refresh Token Grant

### Supported OIDC Flows
- Authorization Code Flow
- Implicit Flow (2 variants)
- Hybrid Flow (3 variants)

### Additional Features
- PKCE (RFC 7636) support
- Token introspection (RFC 7662)
- OIDC Discovery support
- Custom parameter support
- JWT token decoding
- JWKS endpoint testing

## Quick Start

### 1. Start the Services

```bash
# Start with tools profile to include OIDC debugger
docker compose -f docker-compose.standalone.yml --profile tools up -d

# Or using make
make standalone-start-all
```

### 2. Access the Debugger

- **UI**: http://localhost:8083
- **API**: http://localhost:8084

### 3. Create a Test Client

```bash
# Login to Authly admin
docker exec authly-standalone bash -c 'echo YOUR_ADMIN_PASSWORD | authly admin auth login --username admin'

# Create OAuth client for debugger
docker exec authly-standalone authly admin client create \
  --name "OIDC Debugger" \
  --type public \
  --redirect-uri "http://localhost:8083/callback" \
  --scope "openid profile email"
```

## Configuration

### Authly Endpoints

When using the debugger, configure these Authly endpoints:

| Endpoint | URL |
|----------|-----|
| Authorization | `http://localhost:8000/oauth/authorize` |
| Token | `http://localhost:8000/api/v1/oauth/token` |
| UserInfo | `http://localhost:8000/api/v1/userinfo` |
| JWKS | `http://localhost:8000/.well-known/jwks.json` |
| Discovery | `http://localhost:8000/.well-known/openid-configuration` |
| Introspection | `http://localhost:8000/api/v1/oauth/introspect` |

### Test Credentials

- **Username**: `admin`
- **Password**: Your `AUTHLY_ADMIN_PASSWORD` (default: `ci_admin_test_password`)
- **Client ID**: Use the ID from client creation (e.g., `client_xxxxx`)
- **Redirect URI**: `http://localhost:8083/callback`

## Usage Examples

### Testing Authorization Code Flow

1. Navigate to http://localhost:8083
2. Select "Authorization Code Grant" 
3. Enter configuration:
   - **Authorization Endpoint**: `http://localhost:8000/oauth/authorize`
   - **Token Endpoint**: `http://localhost:8000/api/v1/oauth/token`
   - **Client ID**: Your client ID from creation step
   - **Redirect URI**: `http://localhost:8083/callback`
   - **Scope**: `openid profile email`
4. Click "Build Authorization URL" and then "Authorize"
5. Login with admin credentials
6. Approve the consent
7. View the returned authorization code and tokens

### Testing PKCE Flow

1. Enable PKCE in the debugger UI
2. The tool will automatically:
   - Generate code verifier
   - Calculate code challenge
   - Include challenge in authorization request
   - Send verifier during token exchange

### Testing Token Introspection

1. Obtain an access token using any flow
2. Navigate to the Introspection tab
3. Enter:
   - **Introspection Endpoint**: `http://localhost:8000/api/v1/oauth/introspect`
   - **Token**: Your access token
4. View token metadata including:
   - Active status
   - Expiration time
   - Granted scopes
   - Subject (user ID)

### Testing Refresh Token

1. Complete an authorization code flow
2. Copy the refresh token
3. Use the Refresh Grant option
4. Enter:
   - **Token Endpoint**: `http://localhost:8000/api/v1/oauth/token`
   - **Refresh Token**: Your refresh token
   - **Client ID**: Your client ID
5. Get new access and refresh tokens

## Architecture

```
┌─────────────────────┐
│   Browser/User      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐       ┌─────────────────────┐
│  OIDC Debugger UI   │◄─────►│  OIDC Debugger API  │
│   (Port 8083)       │       │    (Port 8084)      │
└──────────┬──────────┘       └─────────────────────┘
           │
           ▼
┌─────────────────────┐
│      Authly         │
│   (Port 8000)       │
└─────────────────────┘
```

## Files

- `Dockerfile` - Multi-stage build for the debugger
- `authly-config.js` - Pre-configured settings for Authly
- `start.sh` - Startup script for both UI and API servers
- `test-integration.sh` - Integration test script
- `README.md` - This documentation

## Environment Variables

The debugger respects these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_FILE` | `./env/authly.js` | Configuration file path |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `3000` (UI), `4000` (API) | Server ports |
| `LOG_LEVEL` | `debug` | Logging verbosity |

## Troubleshooting

### Debugger Not Starting

Check logs:
```bash
docker logs authly-oidc-debugger
```

### Cannot Access UI

Verify services are running:
```bash
docker ps --filter name=oidc-debugger
```

### Authorization Fails

1. Ensure client is created with correct redirect URI
2. Check Authly logs: `docker logs authly-standalone`
3. Verify endpoints are accessible from debugger container

### Token Validation Errors

1. Check token hasn't expired
2. Verify client configuration matches
3. Ensure scopes are properly configured

## Testing Script

Run the integration test:
```bash
./docker-standalone/oidc-debugger/test-integration.sh
```

This verifies:
- UI accessibility
- API accessibility  
- Authly connectivity
- OIDC discovery endpoint

## Security Notes

⚠️ **Development Only**: This debugger is intended for development and testing only.

- Never expose the debugger ports publicly
- Use strong passwords for Authly admin
- Rotate client secrets regularly in production
- The debugger stores some data in browser localStorage

## Advanced Usage

### Custom Parameters

The debugger supports up to 10 custom parameters for authorization requests:
1. Click "Show Custom Parameters"
2. Add parameter name and value
3. Parameters will be included in authorization request

### Multiple Identity Providers

To test against different Authly instances:
1. Modify `authly-config.js` 
2. Rebuild the container
3. Or use environment variables to override settings

### Debugging Network Issues

From inside the debugger container:
```bash
docker exec -it authly-oidc-debugger sh
# Test connectivity
wget -O- http://authly-standalone:8000/health
```

## References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
- [Token Introspection RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)
- [Original Debugger Project](https://github.com/rcbj/oauth2-oidc-debugger)

## License

This integration follows the licensing terms of both:
- OAuth2/OIDC Debugger (original project)
- Authly (Apache License 2.0 or proprietary)