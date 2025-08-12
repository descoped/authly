# Implementation Tickets for Missing Features

Based on the comprehensive testing and gap analysis, here are the features that need implementation:

## Priority 1: Core OAuth/OIDC Features

### Ticket 1: Implement Client Credentials Grant
**Module**: `authly.api.oauth_router`
**Function**: Add handler for `grant_type=client_credentials`
**Requirements**:
- Only allow confidential clients
- No user context (machine-to-machine)
- No refresh tokens
- Validate client authentication (Basic auth or POST)
**Test Coverage**: `tests/oauth_flows/test_client_credentials_flow_fixed.py`

### Ticket 2: Implement OIDCTokenService
**Module**: `authly.oidc.token_service` (new)
**Requirements**:
- Generate ID tokens with required claims (iss, sub, aud, exp, iat)
- Support optional claims (nonce, at_hash, auth_time)
- Include user claims based on requested scopes (profile, email)
- Sign tokens with RS256
**Test Coverage**: `tests/oidc_features/test_id_token_validation.py`

### Ticket 3: Add ID Token to Token Response
**Module**: `authly.api.oauth_router`
**Function**: Modify token endpoint response
**Requirements**:
- When `openid` scope is requested, include `id_token` in response
- Pass nonce from authorization request to ID token
- Include at_hash when issued with access token
**Test Coverage**: `tests/integration/test_complete_auth_flows_fixed.py`

## Priority 2: Token Management

### Ticket 4: Implement Token Introspection Endpoint
**Module**: `authly.api.oauth_router`
**Endpoint**: `POST /api/v1/oauth/introspect`
**Requirements**:
- RFC 7662 compliant
- Return token metadata (active, scope, client_id, username, exp)
- Support token_type_hint parameter
**Test Coverage**: `tests/oauth_flows/test_client_credentials_flow_fixed.py`

### Ticket 5: Fix ClientRepository.authenticate_client Method
**Module**: `authly.oauth.client_repository`
**Requirements**:
- Add `authenticate_client(client_id, client_secret)` method
- Support different auth methods (Basic, POST)
- Use secure password comparison
**Test Coverage**: `tests/oauth_flows/test_client_credentials_flow_fixed.py`

## Priority 3: Browser Authentication (Optional)

### Ticket 6: Implement Browser Login Endpoints
**Module**: `authly.api.auth_router` (new)
**Endpoints**:
- `GET /auth/login` - Render login form
- `POST /auth/login` - Process login, create session
- `POST /auth/logout` - Terminate session
- `GET /auth/session` - Get session info
**Note**: These are complementary to OAuth, not replacements
**Test Coverage**: `tests/authentication/test_browser_login_fixed.py`

### Ticket 7: Implement Session Management
**Module**: `authly.sessions` (new)
**Requirements**:
- Cookie-based sessions
- Session storage (Redis or database)
- CSRF protection
- Remember me functionality
**Test Coverage**: `tests/authentication/test_session_management.py`

## Priority 4: Bug Fixes

### Ticket 8: Fix PKCE Validation Order
**Module**: `authly.api.oauth_router`
**Issue**: Returns 302 (login required) before validating PKCE parameters
**Fix**: Validate PKCE parameters before checking authentication
**Test Coverage**: Compliance tester PKCE tests

### Ticket 9: Fix UserService.create_user Usage
**Module**: Test files
**Issue**: Tests use dict parameter, method expects individual parameters
**Fix**: Update all test calls to use correct signature
**Status**: COMPLETED in refactored tests

## Implementation Order

1. **Phase 1**: Core OAuth/OIDC (Tickets 1-3, 5)
   - Essential for OAuth 2.1/OIDC compliance
   - Blocks many tests
   
2. **Phase 2**: Token Management (Ticket 4)
   - Important for token validation
   - Required for production use

3. **Phase 3**: Bug Fixes (Ticket 8)
   - Improves compliance
   - Quick wins

4. **Phase 4**: Browser Auth (Tickets 6-7)
   - Optional - only if web UI needed
   - Can use OAuth endpoints directly

## Acceptance Criteria

Each implementation should:
1. Follow existing code patterns
2. Include proper error handling
3. Add logging for debugging
4. Update OpenAPI documentation
5. Pass all related tests
6. Not break existing functionality

## Testing Strategy

After each implementation:
1. Run specific test suite for that feature
2. Run integration tests
3. Run compliance tester
4. Check for regressions

## Notes

- Client Credentials Grant is critical for M2M authentication
- OIDCTokenService is required for full OIDC compliance
- Browser endpoints are optional if using OAuth directly
- All implementations should maintain backward compatibility