# OAuth 2.1 Authorization Flow

This document describes the complete OAuth 2.1 authorization code flow with PKCE (Proof Key for Code Exchange) as implemented in Authly.

## Flow Overview

The OAuth 2.1 authorization flow provides secure third-party access to user resources without exposing user credentials. Authly implements the authorization code flow with mandatory PKCE for enhanced security.

## Visual Flow Diagram

![OAuth 2.1 Authorization Flow](oauth-authorization-flow.mmd)

## Flow Steps

### 1. Client Preparation
The OAuth client generates PKCE parameters and initiates the authorization request:
- **code_verifier**: Random string (43-128 characters)
- **code_challenge**: SHA256 hash of the code_verifier
- **state**: CSRF protection parameter

### 2. Authorization Request
Client redirects user to the authorization endpoint with required parameters:
```
GET /authorize?
  response_type=code&
  client_id={client_id}&
  redirect_uri={redirect_uri}&
  scope={requested_scopes}&
  state={state}&
  code_challenge={code_challenge}&
  code_challenge_method=S256
```

### 3. Client and Scope Validation
The authorization server validates:
- **Client Identity**: Verifies client_id and redirect_uri
- **Scope Permissions**: Validates requested scopes against client permissions
- **PKCE Parameters**: Ensures code_challenge is present for OAuth 2.1 compliance

### 4. User Authentication
If the user is not authenticated:
- Present login form
- Validate user credentials
- Establish authenticated session

### 5. User Consent
Present consent screen showing:
- Client application details (name, description, logo)
- Requested permissions/scopes
- User can approve or deny the request

### 6. Authorization Code Generation
Upon user approval:
- Generate unique authorization code
- Store code with associated client_id, user_id, scopes, and code_challenge
- Set expiration time (10 minutes maximum per OAuth 2.1)
- Redirect user back to client with authorization code

### 7. Token Exchange
Client exchanges authorization code for tokens:
```json
POST /auth/token
{
  "grant_type": "authorization_code",
  "code": "{authorization_code}",
  "client_id": "{client_id}",
  "code_verifier": "{code_verifier}",
  "redirect_uri": "{redirect_uri}"
}
```

### 8. PKCE Verification
Authorization server validates:
- **Authorization Code**: Valid, unexpired, matches client_id
- **PKCE Proof**: SHA256(code_verifier) equals stored code_challenge
- **Client Authentication**: For confidential clients
- **One-time Use**: Code is immediately invalidated after use

### 9. Token Response
Return access and refresh tokens:
```json
{
  "access_token": "jwt_access_token",
  "refresh_token": "jwt_refresh_token", 
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "granted_scopes"
}
```

### 10. Protected Resource Access
Client uses access token to access protected resources:
```
Authorization: Bearer {access_token}
```

## Security Features

### PKCE Protection
- **Code Interception**: PKCE prevents authorization code interception attacks
- **Dynamic Secrets**: Each authorization request uses unique code_verifier/code_challenge pair
- **No Client Secret Required**: Public clients can securely use OAuth without storing secrets

### Authorization Code Security
- **Single Use**: Authorization codes are immediately invalidated after token exchange
- **Short Expiration**: Maximum 10 minutes lifetime per OAuth 2.1 specification
- **Client Binding**: Codes are bound to specific client_id and redirect_uri

### State Parameter
- **CSRF Protection**: State parameter prevents cross-site request forgery attacks
- **Client Validation**: Client must verify state matches the original request

### Scope Management
- **Granular Permissions**: Users see exactly what permissions are requested
- **Consent Required**: Users must explicitly approve each authorization request
- **Scope Limitation**: Granted tokens are limited to approved scopes only

## Error Handling

### Client Errors
- **invalid_client**: Invalid client_id or authentication failure
- **unauthorized_client**: Client not authorized for authorization code grant
- **invalid_request**: Missing or malformed parameters

### Authorization Errors  
- **access_denied**: User denied the authorization request
- **invalid_scope**: Requested scope is invalid or unavailable
- **server_error**: Internal server error during processing

### Token Exchange Errors
- **invalid_grant**: Invalid or expired authorization code
- **invalid_client**: Client authentication failed
- **unsupported_grant_type**: Authorization code grant not supported

## Implementation Standards

### OAuth 2.1 Compliance
- **Mandatory PKCE**: All authorization code flows require PKCE
- **Security BCP**: Follows OAuth 2.1 security best current practices
- **RFC Compliance**: Implements RFC 6749, RFC 7636 (PKCE), RFC 8252

### Database Schema
```sql
-- Authorization codes table
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id),
    user_id UUID NOT NULL REFERENCES users(id),
    scopes TEXT[] NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Configuration Options
```python
# OAuth authorization code settings
AUTHORIZATION_CODE_EXPIRE_MINUTES = 10  # OAuth 2.1 maximum
PKCE_REQUIRED = True  # Mandatory for OAuth 2.1
CONSENT_REQUIRED = True  # Always require user consent
```

This implementation provides enterprise-grade OAuth 2.1 security while maintaining usability for both confidential and public client applications.