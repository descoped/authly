# Token Refresh Flow

This document describes the token refresh process in Authly, supporting both traditional password authentication and OAuth 2.1 flows with automatic token rotation and security features.

## Overview

Token refresh allows clients to obtain new access tokens without requiring user re-authentication. This process maintains user sessions while ensuring security through token rotation and validation.

## Visual Refresh Flow

![Token Refresh Flow](token-refresh-flow.mmd)

## Refresh Process

### 1. Refresh Request
Clients send refresh tokens to obtain new access tokens:

```http
POST /auth/refresh HTTP/1.1
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "grant_type": "refresh_token"
}
```

### 2. Token Validation
The server validates the refresh token through multiple checks:
- **JWT Signature**: Verify token hasn't been tampered with
- **Expiration Check**: Ensure token hasn't expired (7-day default)
- **JTI Lookup**: Confirm token hasn't been revoked
- **User Status**: Verify user account is still active

### 3. Token Rotation
Upon successful validation:
- **Revoke Old Tokens**: Mark current tokens as invalid
- **Generate New Pair**: Create fresh access and refresh tokens
- **Update Database**: Store new tokens with new JTI values
- **Response**: Return new token pair to client

### 4. Security Features
- **Automatic Rotation**: Refresh tokens are single-use
- **JTI Tracking**: Enables immediate token revocation
- **Scope Preservation**: OAuth tokens maintain original scopes
- **Client Binding**: Tokens tied to specific OAuth clients

## Implementation Details

### Database Operations
The refresh process involves several atomic database operations:

```sql
-- Validate refresh token
SELECT user_id, expires_at, invalidated 
FROM tokens 
WHERE jti = ? AND token_type = 'refresh';

-- Invalidate old tokens
UPDATE tokens 
SET invalidated = true 
WHERE user_id = ? AND invalidated = false;

-- Store new tokens
INSERT INTO tokens (jti, user_id, token_type, expires_at, scopes)
VALUES (?, ?, 'access', ?, ?),
       (?, ?, 'refresh', ?, ?);
```

### OAuth 2.1 Enhancements
For OAuth tokens, the refresh process includes additional validations:
- **Client Authentication**: Verify OAuth client credentials
- **Scope Validation**: Maintain originally granted scopes
- **Client Status**: Ensure OAuth client is still active
- **Redirect URI**: Validate against registered URIs

### Error Handling
Common refresh errors and responses:
- **Invalid Token**: `401 Unauthorized` - Token signature invalid
- **Expired Token**: `401 Unauthorized` - Refresh token expired
- **Revoked Token**: `401 Unauthorized` - Token already used or revoked
- **User Inactive**: `401 Unauthorized` - User account disabled

This refresh mechanism provides secure, efficient token renewal while maintaining strong security guarantees for both traditional and OAuth 2.1 authentication flows.
