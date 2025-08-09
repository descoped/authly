# Adminer OAuth Integration with Authly

This directory contains a custom Adminer implementation that integrates with Authly's OAuth authentication system, providing secure database access without exposing database credentials.

## Overview

Instead of using traditional database username/password authentication, this Adminer instance validates OAuth tokens against Authly's introspection endpoint. This provides:

- **Enhanced Security**: Database credentials never leave the server
- **Single Sign-On**: Use Authly OAuth tokens for database access
- **Scope-based Access Control**: Requires `database:read` and `database:write` scopes
- **Developer-friendly**: Auto-populates OAuth tokens in development mode

## How It Works

### Architecture

```
User → Adminer Login → OAuth Token → Authly Introspection → Database Access
                           ↓                    ↓
                    (Bearer Token)     (Validates & Returns Scopes)
```

### Authentication Flow

1. **Token Generation**: User obtains OAuth token from Authly
2. **Login Form**: User enters OAuth token in password field (or it's auto-populated)
3. **Token Validation**: `oauth-wrapper.php` validates token via `/api/v1/oauth/introspect`
4. **Credential Substitution**: Valid tokens are replaced with actual DB credentials internally
5. **Database Access**: User accesses database through Adminer interface

## Files

- `oauth-wrapper.php` - Main OAuth integration wrapper
- `Dockerfile` - Builds custom Adminer image with OAuth support
- `README.md` - This documentation

## Configuration

The integration is configured via environment variables in `docker-compose.standalone.yml`:

```yaml
adminer:
  environment:
    AUTHLY_URL: "http://authly-standalone:8000"
    AUTHLY_ADMIN_PASSWORD: "${AUTHLY_ADMIN_PASSWORD:-ci_admin_test_password}"
    DB_SERVER: "authly-standalone"
    DB_USERNAME: "authly"
    DB_PASSWORD: "authly"
    DB_NAME: "authly"
```

## Features

### 1. Auto-populated OAuth Token (Development)

In development mode, the login form automatically generates and pre-fills a valid OAuth token:

- Token is generated using admin credentials from environment
- Password field is pre-filled and highlighted in green
- User can simply click "Login" without manual token entry

### 2. Pre-filled Form Fields

The following fields are automatically populated:
- **System**: PostgreSQL
- **Server**: authly-standalone
- **Username**: admin (display only, replaced internally)
- **Database**: authly

### 3. Visual Feedback

#### Login Page
- Blue banner with instructions for OAuth authentication
- Green-highlighted password field when token is auto-filled
- Clear error messages for invalid tokens

#### After Login
- Green success banner showing authenticated user and scopes
- Banner auto-fades after 3 seconds
- Positioned in right panel for better UI integration

### 4. Session Persistence

Once authenticated, the session is maintained until:
- User explicitly logs out
- Session expires
- Token becomes invalid

## Usage

### Starting the Service

```bash
# Start with tools profile to include Adminer
make standalone-start-all

# Or using docker-compose directly
docker compose -f docker-compose.standalone.yml --profile tools up -d
```

### Accessing Adminer

Navigate to: http://localhost:8082

#### Development Mode (Auto-login)
1. Visit the URL
2. Token is pre-filled automatically
3. Click "Login"

#### Manual Token Entry
1. Generate OAuth token:
```bash
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -d "grant_type=password&username=admin&password=YOUR_PASSWORD&scope=database:read database:write"
```

2. Copy the `access_token` from response
3. Paste into password field
4. Click "Login"

## Security Considerations

### Token Validation

The wrapper validates:
- Token is active (`active: true`)
- Token has required scopes (`database:read`, `database:write`)
- Token structure (JWT format)

### Credential Protection

- Database credentials are never exposed to the client
- Token validation happens server-side
- Invalid tokens receive generic error messages
- Credentials are substituted only after successful validation

### Development vs Production

**⚠️ Important**: Auto-token generation is for development only!

In production:
- Disable auto-token generation
- Use proper OAuth flow
- Implement token refresh mechanism
- Consider adding rate limiting

## Implementation Details

### PHP Shutdown Function

The implementation uses PHP's `register_shutdown_function()` to inject content after Adminer executes. This approach handles Adminer's internal `exit()` calls gracefully.

### CSP Nonce Handling

Scripts are injected with proper Content Security Policy nonces extracted from Adminer's output, ensuring compatibility with Adminer's security headers.

### Output Buffering

Output buffering (`ob_start()`) prevents header conflicts and allows modification of Adminer's HTML output before sending to the client.

## Troubleshooting

### Common Issues

1. **"Invalid OAuth token" error**
   - Ensure token has correct scopes
   - Check token hasn't expired
   - Verify Authly service is running

2. **Auto-fill not working**
   - Check `AUTHLY_ADMIN_PASSWORD` environment variable
   - Verify Authly is accessible from Adminer container
   - Check Docker logs: `docker logs authly-adminer`

3. **Banner not disappearing**
   - May be browser JavaScript disabled
   - Check browser console for errors

### Debugging

Enable detailed logging:
```bash
docker logs -f authly-adminer
```

Look for:
- `DevToken generated: ...` - Token generation status
- `Shutdown function: Replaced X password fields` - Injection success
- `OAuth validated` - Successful authentication

## Customization

### Modify Banner Display Time

Edit `oauth-wrapper.php`, line ~145:
```javascript
}, 3000);  // Change 3000 to desired milliseconds
```

### Disable Auto-fill

Remove or comment out the `getDevToken()` function call in `oauth-wrapper.php`.

### Change Required Scopes

Modify scope validation in `oauth-wrapper.php`, line ~91:
```php
if (in_array('database:read', $scopes) && in_array('database:write', $scopes)) {
```

## Future Enhancements

Potential improvements:
- [ ] Support for read-only access with just `database:read` scope
- [ ] Token refresh mechanism for long sessions
- [ ] Role-based database selection
- [ ] Audit logging of database access
- [ ] Support for multiple database connections
- [ ] Integration with OIDC providers

## License

This integration follows Adminer's Apache License 2.0 and Authly's licensing terms.