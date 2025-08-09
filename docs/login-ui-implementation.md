# Authly Login UI Implementation

## Overview

Authly now includes an optional browser-based login UI that enables OAuth 2.1 Authorization Code flow with PKCE. This implementation follows package-by-feature architecture for future modular refactoring.

## Architecture

### Package Structure

The login UI is implemented as a self-contained `authentication` package:

```
src/authly/authentication/
├── __init__.py              # Package exports
├── models.py                # Session and login models
├── repository.py            # Redis-based session storage
├── service.py               # Authentication business logic
├── router.py                # FastAPI endpoints
├── dependencies.py          # FastAPI dependencies
├── oauth_integration.py     # OAuth authorization integration
└── templates/
    └── login.html          # Jinja2 login template
```

### Design Principles

1. **Package-by-Feature**: Self-contained authentication module
2. **Minimal Dependencies**: Uses existing Authly infrastructure
3. **Dual Authentication**: Supports both session (browser) and token (API) flows
4. **Security-First**: CSRF protection, secure cookies, session expiration
5. **Simple UI**: Jinja2 templates with minimal JavaScript

## Components

### Session Management

Sessions are stored in Redis with automatic expiration:

- **Session ID**: Cryptographically secure random token
- **CSRF Token**: Per-session CSRF protection
- **Duration**: 30 minutes (default) or 24 hours (remember me)
- **Storage**: Redis with TTL matching session duration

### Login Page

Simple, responsive login form at `/auth/login`:

- Username/email and password fields
- Remember me checkbox (24-hour session)
- OAuth context display when redirected from authorization
- CSRF protection on form submission
- Styled with existing Authly CSS

### OAuth Integration

The OAuth authorization endpoint now supports both authentication methods:

1. **Session-based (Browser)**:
   - Checks for `authly_session` cookie
   - Redirects to login if not authenticated
   - Preserves OAuth parameters through login flow

2. **Token-based (API)**:
   - Checks for Bearer token in Authorization header
   - Returns 401 if not authenticated
   - Maintains backward compatibility

## Usage

### Browser Flow (Authorization Code with PKCE)

1. Client redirects to `/api/v1/oauth/authorize` with parameters
2. If not logged in, redirects to `/auth/login`
3. User enters credentials and submits
4. On success, creates session and redirects back to authorize
5. User sees consent page and approves/denies
6. Authorization code returned to client

### API Flow (Resource Owner Password)

Unchanged - continues to work with Bearer tokens:

```bash
# Get token
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -d "grant_type=password&username=admin&password=admin"

# Use token for authorization
curl http://localhost:8000/api/v1/oauth/authorize \
  -H "Authorization: Bearer <token>" \
  -G --data-urlencode "client_id=..." ...
```

## Endpoints

### Authentication Endpoints

- `GET /auth/login` - Display login page
- `POST /auth/login` - Process login form
- `GET /auth/logout` - Log out user
- `GET /auth/session` - Get current session info
- `POST /auth/session/validate` - Validate session

### Modified OAuth Endpoints

- `GET /api/v1/oauth/authorize` - Now supports session auth
- `POST /api/v1/oauth/authorize` - Now supports session auth

## Configuration

### Cookie Settings

```python
COOKIE_NAME = "authly_session"
COOKIE_HTTPONLY = True
COOKIE_SECURE = False  # Set to True for HTTPS
COOKIE_SAMESITE = "lax"
```

### Session Durations

- Default: 30 minutes
- Remember Me: 24 hours
- Configurable via `duration_minutes` parameter

## Security Considerations

### CSRF Protection

- Unique CSRF token per session
- Token validated on form submission
- Prevents cross-site request forgery

### Session Security

- Sessions stored server-side in Redis
- Only session ID sent to client
- Automatic expiration with TTL
- IP address and user agent tracking

### Cookie Security

- HttpOnly flag prevents JavaScript access
- SameSite=lax prevents CSRF
- Secure flag for HTTPS (configurable)

## Testing

### Manual Testing

1. **Authorization Code Flow**:
   ```bash
   # Navigate to OAuth tester
   http://localhost:8085
   
   # Select "Authorization Code with PKCE"
   # Click "Start Authorization"
   # Login with admin/ci_admin_test_password
   # Approve consent
   # Receive authorization code
   ```

2. **Direct Login**:
   ```bash
   # Navigate to login page
   http://localhost:8000/auth/login
   
   # Enter credentials
   # Check session endpoint
   http://localhost:8000/auth/session
   ```

### Automated Testing

```python
# Test session creation
async def test_login_creates_session():
    response = await client.post("/auth/login", data={
        "username": "admin",
        "password": "admin",
        "csrf_token": "test"
    })
    assert response.status_code == 302
    assert "authly_session" in response.cookies

# Test OAuth with session
async def test_oauth_with_session():
    # Login first
    login_response = await client.post("/auth/login", ...)
    session_cookie = login_response.cookies["authly_session"]
    
    # Use session for OAuth
    auth_response = await client.get(
        "/api/v1/oauth/authorize",
        cookies={"authly_session": session_cookie}
    )
    assert auth_response.status_code == 200
```

## Future Enhancements

### Planned Features

1. **User Registration UI**: Self-service registration
2. **Password Reset**: Email-based password reset
3. **MFA Support**: TOTP/WebAuthn integration
4. **Account Management**: Profile editing, session management
5. **Social Login**: OAuth providers (Google, GitHub, etc.)

### Modular Refactoring

The package-by-feature design enables future splitting:

```yaml
# Future microservices
authly-core:        # Core authentication
  - authentication/
  - users/
  
authly-oauth:       # OAuth/OIDC server
  - oauth/
  - oidc/
  
authly-admin:       # Admin interface
  - admin/
  - monitoring/
```

## Migration Notes

### For Existing Deployments

1. **No Breaking Changes**: Existing API flows continue to work
2. **Optional Feature**: Login UI can be disabled if not needed
3. **Redis Required**: Sessions require Redis (already in Authly)
4. **Database Compatible**: No schema changes required

### Environment Variables

No new required environment variables. Optional configuration:

```bash
# Optional: Custom session duration (minutes)
AUTHLY_SESSION_DURATION=30

# Optional: Cookie domain for multi-subdomain
AUTHLY_COOKIE_DOMAIN=.example.com

# Optional: Enable secure cookies (HTTPS only)
AUTHLY_COOKIE_SECURE=true
```

## Troubleshooting

### Common Issues

1. **"login_required" error**:
   - Ensure Redis is running
   - Check session cookie in browser
   - Verify cookie domain matches

2. **CSRF token mismatch**:
   - Clear browser cookies
   - Ensure form includes CSRF token
   - Check for multiple tabs/windows

3. **Session expires quickly**:
   - Check Redis TTL configuration
   - Verify clock synchronization
   - Use "Remember Me" for longer sessions

### Debug Commands

```bash
# Check Redis sessions
redis-cli keys "session:*"

# View session data
redis-cli get "session:<session_id>"

# Monitor authentication logs
docker logs authly-standalone | grep -i auth

# Test session endpoint
curl -v http://localhost:8000/auth/session \
  -H "Cookie: authly_session=<session_id>"
```

## Summary

The login UI implementation provides:

- ✅ Browser-based OAuth Authorization Code flow
- ✅ Backward compatible with API flows
- ✅ Secure session management
- ✅ Package-by-feature architecture
- ✅ Minimal, maintainable codebase
- ✅ Ready for future modularization

This enables Authly to serve both browser-based applications (SPAs, traditional web apps) and API clients (mobile apps, services) with appropriate authentication methods for each.