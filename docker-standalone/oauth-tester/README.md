# OAuth/OIDC Tester for Authly

A simple, reliable OAuth 2.0 and OpenID Connect testing tool designed specifically for Authly.

## Why This Tool?

After testing the popular oauth2-oidc-debugger, we found it had several issues:
- State management problems (state mismatches)
- Confusing UI with hidden sections
- Doesn't handle OAuth flows properly
- Complex setup with multiple services

This tool is a **simple, single-page application** that just works.

## Features

✅ **Authorization Code Flow with PKCE** - The recommended flow for SPAs and mobile apps
✅ **Password Grant** - For testing with username/password
✅ **Client Credentials** - For machine-to-machine auth
✅ **Refresh Token** - Test token refresh
✅ **Token Introspection** - Validate and inspect tokens
✅ **UserInfo Endpoint** - Fetch user profile
✅ **Clean, intuitive UI** - No hidden sections or confusing buttons
✅ **Proper state management** - No state mismatch errors
✅ **Single container** - Just nginx serving static files

## Quick Start

### 1. Start the Tester

```bash
# With Docker Compose
docker compose -f docker-compose.standalone.yml --profile tools up -d

# Or using Make
make standalone-start-all
```

### 2. Access the UI

Open http://localhost:8085 in your browser

### 3. Use the Test Client

A test client has been created for you:
- **Client ID**: `client_mgjOYWRSXsb1PIGxicSooQ`
- **Type**: Public (no secret required)
- **Redirect URI**: `http://localhost:8085/callback`

Or create your own:

```bash
docker exec authly-standalone authly admin client create \
  --name "My Test App" \
  --type public \
  --redirect-uri "http://localhost:8085/callback" \
  --scope "openid profile email"
```

## Usage Guide

### Testing Authorization Code Flow (Recommended)

**Note**: Authly is an API-only OAuth server without a built-in login UI. You'll get a "login_required" error because there's no login page to redirect to.

**Workaround - Use Password Grant Instead**:
1. Select **"Resource Owner Password"** from Flow Type
2. Enter your username and password
3. Click **"Get Tokens"**

This is a limitation of Authly - it expects you to build your own login UI for the authorization code flow.

### Testing Password Grant

1. Select **"Resource Owner Password"** from Flow Type
2. Enter username and password
3. Click **"Get Tokens"**

### Testing Token Refresh

1. Complete any flow to get a refresh token
2. Select **"Refresh Token"** from Flow Type
3. Paste the refresh token
4. Click **"Refresh Tokens"**

## Features Explained

### PKCE (Proof Key for Code Exchange)

Authly **requires PKCE** for public clients as a security best practice. The tester:
- Automatically generates code verifier and challenge
- Includes them in the authorization request
- Sends the verifier during token exchange

### State Management

Unlike other tools, this tester:
- Properly generates and validates state parameter
- Stores state in sessionStorage
- Verifies state on callback to prevent CSRF

### Token Display

The results section shows:
- **Raw tokens** - Full token strings
- **Decoded tokens** - JWT header and payload
- **Token metadata** - Expiry, type, scope

## Architecture

```
┌─────────────────┐
│   Browser       │
│  (localhost)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  OAuth Tester   │
│   Port 8085     │
│  (Static HTML)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Authly      │
│   Port 8000     │
│  (OAuth Server) │
└─────────────────┘
```

## Endpoints

All endpoints are pre-configured:

| Endpoint | URL |
|----------|-----|
| Authorization | `http://localhost:8000/api/v1/oauth/authorize` |
| Token | `http://localhost:8000/api/v1/oauth/token` |
| UserInfo | `http://localhost:8000/api/v1/userinfo` |
| Introspection | `http://localhost:8000/api/v1/oauth/introspect` |
| Discovery | `http://localhost:8000/.well-known/openid-configuration` |

## Troubleshooting

### "Client not found"
Create a client first or use the provided test client ID.

### "code_challenge is required"
Make sure PKCE is enabled (checkbox checked).

### "Invalid grant"
The authorization code might have expired. Try the flow again.

### "Access denied"
Make sure you're using the correct username/password.

## Technical Details

- **Container**: nginx:alpine
- **Size**: ~40MB (vs 950MB for oauth2-oidc-debugger)
- **Technology**: Pure HTML/CSS/JavaScript
- **Dependencies**: None (just nginx)
- **State Management**: sessionStorage and localStorage
- **Security**: PKCE enabled by default, state validation

## Why It's Better

| Feature | This Tester | oauth2-oidc-debugger |
|---------|------------|---------------------|
| Size | ~40MB | ~950MB |
| Setup | Single file | Multiple services |
| State Management | ✅ Works | ❌ Broken |
| UI | Simple & Clear | Confusing |
| PKCE | Default On | Manual |
| Dependencies | None | Node, Browserify |
| Maintenance | Easy | Complex |

## Files

- `index.html` - The complete application
- `nginx.conf` - Simple nginx configuration
- `Dockerfile` - Minimal container setup
- `README.md` - This documentation

## Development

To modify the tester:

1. Edit `index.html`
2. Rebuild: `docker compose -f docker-compose.standalone.yml --profile tools build oauth-tester`
3. Restart: `docker compose -f docker-compose.standalone.yml --profile tools restart oauth-tester`

## License

Part of the Authly project. Same license terms apply.