# Logout Flow

This document describes the comprehensive logout process in Authly, including session termination, token revocation, and security cleanup for both traditional authentication and OAuth 2.1 flows.

## Overview

The logout process ensures secure session termination by invalidating all active tokens and preventing further use of authentication credentials. This process supports both individual token revocation and bulk user session cleanup.

## Visual Logout Flow

![Logout Flow](logout-flow.mmd)

## Logout Process

### 1. Logout Request
Clients initiate logout by sending their current access token:

```http
POST /auth/logout HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. Token Validation
The server validates the provided access token:
- **JWT Decoding**: Extract user information from token
- **User Lookup**: Verify user account exists and is active
- **Token Status**: Confirm token is valid and not already revoked

### 3. Token Revocation
The logout process invalidates tokens in two phases:

**Phase 1: Current Token**
- Invalidate the token used for logout request
- Mark specific JTI as revoked in database

**Phase 2: User Session Cleanup**
- Find all active tokens for the user
- Invalidate all access and refresh tokens
- Update database to mark all tokens as revoked

### 4. Response
Return logout confirmation with metrics:

```json
{
  "message": "Successfully logged out",
  "invalidated_tokens": 3
}
```

## Security Features

### Comprehensive Revocation
- **Current Token**: Immediately invalidates logout request token
- **All User Tokens**: Revokes all active sessions across devices
- **OAuth Tokens**: Includes OAuth-specific token cleanup
- **Cascade Effect**: Related tokens automatically invalidated

### Audit Trail
- **Logout Events**: All logout actions logged for security monitoring
- **Token Tracking**: JTI-based tracking enables forensic analysis
- **User Activity**: Logout timestamps recorded for compliance

### Error Handling
- **Invalid Token**: Graceful handling of already-expired tokens
- **User Not Found**: Secure error responses prevent enumeration
- **Database Errors**: Rollback protection for partial failures

## OAuth 2.1 Integration

### OAuth Token Cleanup
For OAuth-authenticated sessions:
- **Client-Specific Cleanup**: Revoke tokens for specific OAuth clients
- **Scope Preservation**: Maintain audit records of revoked scope grants
- **Token Revocation Endpoint**: Integration with RFC 7009 revocation

### Multi-Client Sessions
- **Cross-Client Revocation**: Logout affects all OAuth client sessions
- **Client Isolation**: Option to revoke tokens for specific clients only
- **Consent Cleanup**: Clear stored consent decisions on logout

This logout implementation provides secure session termination with comprehensive token cleanup, supporting both traditional authentication and OAuth 2.1 flows with full audit capabilities.
