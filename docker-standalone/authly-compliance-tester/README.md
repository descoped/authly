# Authly Compliance Tester

A high-security compliance testing tool for validating OAuth 2.1 + PKCE (Authorization Code ONLY) and OpenID Connect 1.0 compliance of Authly authentication server.

## Scope

**Authly supports ONLY the OAuth 2.1 Authorization Code Flow with PKCE** for maximum security. 

**NOT Supported (by design):**
- ❌ Implicit Flow
- ❌ Hybrid Flow  
- ❌ Resource Owner Password Credentials
- ❌ Client Credentials (for user auth)
- ❌ Plain PKCE method

## Features

- **OAuth 2.1 + PKCE Strict Testing**
  - Authorization Code Flow ONLY
  - PKCE mandatory with S256 only
  - No implicit/hybrid flow support verification
  - Strict redirect URI exact matching
  - State parameter mandatory
  - High-security validation

- **OpenID Connect 1.0 Testing**
  - Discovery document validation
  - JWKS endpoint verification
  - ID token structure validation
  - UserInfo endpoint testing
  - Standard claims validation
  - Nonce parameter support

- **Browser Session Flow Testing**
  - Login/logout functionality
  - Session management
  - CSRF protection validation
  - Remember me functionality
  - Session validation endpoints

- **Security Feature Validation**
  - PKCE S256 challenge verification
  - Token expiration handling
  - Rate limiting detection
  - CORS header validation
  - HTTPS enforcement checks

## Quick Start

### Standalone Mode

1. Open `index.html` in a web browser
2. Configure your Authly server settings
3. Run individual test suites or all tests

### Docker Mode

Build and run with Docker:

```bash
# Build the image
docker build -t authly-compliance-tester .

# Run the container
docker run -d \
  --name authly-compliance-tester \
  -p 8080:8080 \
  --network authly-network \
  authly-compliance-tester
```

Or use Docker Compose:

```bash
docker-compose up -d
```

Access the tester at `http://localhost:8080`

## Configuration

Configure the following settings in the UI:

- **Server URL**: Your Authly server URL (default: `http://localhost:8000`)
- **Client ID**: OAuth client identifier
- **Client Secret**: OAuth client secret (for confidential clients)
- **Redirect URI**: Callback URL for OAuth flows
- **Scopes**: Space-separated list of requested scopes
- **Test Credentials**: Username and password for test user

Configuration is saved in browser localStorage for convenience.

## Test Suites

### OAuth 2.1 Core
Validates mandatory OAuth 2.1 requirements:
- PKCE enforcement
- S256 challenge method
- Redirect URI exact matching
- State parameter handling
- Authorization code single-use
- No implicit flow support
- Refresh token rotation

### OpenID Connect 1.0
Tests OIDC compliance:
- Discovery document (`.well-known/openid-configuration`)
- JWKS endpoint
- ID token validation
- UserInfo endpoint
- Standard claims
- Nonce parameter support

### Browser Session Flow
Tests session-based authentication:
- Login page accessibility
- CSRF protection
- Session management
- Logout functionality
- Session validation

### Security Validation
Verifies security features:
- CORS headers
- Rate limiting
- Token expiration
- HTTPS enforcement

## Test Execution

### Running Tests

1. **Individual Suite**: Click "Run Tests" on any test suite card
2. **All Suites**: Click "Run All Test Suites" button
3. **Custom Flow**: Use "Custom Test Flow" for specific scenarios

### Test Results

Results are displayed in real-time with:
- Pass/fail status for each test
- Detailed error messages
- Execution duration
- Test logs

### Exporting Results

Click "Export Report" to download a JSON report containing:
- Test configuration
- Complete test results
- Summary statistics
- Timestamp information

## Integration with Authly

The compliance tester is designed to work seamlessly with Authly:

1. **Network Setup**: When using Docker, ensure both Authly and the tester are on the same network
2. **Client Registration**: Register a test client in Authly with appropriate redirect URIs
3. **Test User**: Create a test user account for authentication flows

## Development

### Project Structure

```
authly-compliance-tester/
├── index.html              # Main UI
├── css/
│   └── styles.css         # Styling
├── js/
│   ├── compliance-tester.js  # Core logic
│   ├── oauth-flows.js        # OAuth 2.1 flows
│   ├── oidc-flows.js         # OIDC flows
│   └── test-suites.js        # Test definitions
├── Dockerfile               # Container configuration
├── docker-compose.yml       # Compose configuration
└── README.md               # Documentation
```

### Adding New Tests

1. Define test in `js/test-suites.js`
2. Implement test logic using existing flow helpers
3. Add to appropriate test suite

Example test:

```javascript
{
    id: 'custom_test',
    name: 'Custom Test Name',
    description: 'Test description',
    run: async (config, tester) => {
        // Test implementation
        const result = await someTestLogic(config, tester);
        
        return {
            passed: result.isValid,
            details: result.details,
            error: result.error || null
        };
    }
}
```

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure Authly server has proper CORS configuration
2. **Connection Refused**: Verify Authly server is running and accessible
3. **Invalid Client**: Check client registration in Authly
4. **Network Issues**: Ensure Docker containers are on the same network

### Debug Mode

Open browser developer console to see detailed logs and network requests.

## Requirements

- Modern web browser with JavaScript enabled
- Authly server instance (local or remote)
- Registered OAuth client with appropriate configuration
- Test user account (for authenticated flows)

## License

Part of the Authly authentication platform.