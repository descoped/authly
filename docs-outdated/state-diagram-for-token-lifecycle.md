# Token Lifecycle State Diagram

This document describes the comprehensive token lifecycle in Authly, including OAuth 2.1 enhancements, scope management, and token revocation capabilities.

## Overview

The token lifecycle manages the complete journey from token creation to cleanup, supporting both traditional password-based authentication and OAuth 2.1 authorization flows with enhanced security features.

## Visual Lifecycle Diagram

![Token Lifecycle](token-lifecycle.mmd)

## Token States and Transitions

### 1. Token Creation

**Triggers:**
- User authentication (password grant)
- OAuth authorization code exchange
- Token refresh operations

**Process:**
1. **JTI Generation**: Create unique JWT ID for tracking
2. **JWT Signing**: Sign token with server secret key
3. **Database Storage**: Store token metadata with JTI
4. **Scope Assignment**: Include granted permissions (OAuth tokens)

**Token Types Created:**
- **Access Tokens**: Short-lived (30 minutes) for API access
- **Refresh Tokens**: Long-lived (7 days) for token renewal
- **Authorization Codes**: Very short-lived (10 minutes) for OAuth flow

### 2. Active Token State

**Characteristics:**
- Token is valid and usable for API access
- JTI exists in database and is not revoked
- Token signature is valid
- Expiration time has not been reached

**Validation Process:**
1. **Signature Verification**: Validate JWT signature with secret key
2. **Expiration Check**: Ensure token hasn't expired
3. **JTI Lookup**: Confirm token hasn't been revoked
4. **User Status**: Verify user account is still active
5. **Scope Validation**: Check required permissions (OAuth tokens)
6. **Client Validation**: Verify OAuth client is still active

### 3. Token Usage and Validation

**API Request Flow:**
1. **Request Received**: Client sends token in Authorization header
2. **Token Extraction**: Parse Bearer token from header
3. **JWT Decoding**: Decode and validate token structure
4. **Multi-layer Validation**: Execute all validation checks
5. **Access Decision**: Grant or deny based on validation results

**Validation Failures:**
- **Invalid Signature**: Token tampered with or wrong secret
- **Token Expired**: Past expiration time
- **Token Revoked**: JTI not found or marked invalid
- **User Inactive**: User account disabled or deleted
- **Insufficient Scope**: Required permissions not granted
- **Client Deactivated**: OAuth client no longer active

### 4. Token Revocation

**Revocation Triggers:**
- **User Logout**: User-initiated session termination
- **Admin Revocation**: Administrative token invalidation
- **Refresh Token Usage**: Old tokens invalidated when refresh used
- **Security Events**: Breach response or suspicious activity
- **Client Deactivation**: OAuth client disabled
- **Token Revocation Endpoint**: RFC 7009 compliant revocation

**Revocation Process:**
1. **Identify Tokens**: Find all tokens to be revoked
2. **Database Update**: Mark JTI as invalidated
3. **Cascade Revocation**: Revoke related tokens (refresh → access)
4. **Audit Logging**: Record revocation event with details
5. **Immediate Effect**: Tokens rejected on next validation

**Revocation Scope:**
- **Single Token**: Individual access or refresh token
- **Token Pair**: Both access and refresh tokens
- **User Session**: All tokens for specific user
- **Client Tokens**: All tokens for specific OAuth client
- **Global Revocation**: All tokens (security emergency)

### 5. Token Expiration

**Natural Expiration:**
- **Access Tokens**: Automatically expire after 30 minutes
- **Refresh Tokens**: Automatically expire after 7 days
- **Authorization Codes**: Automatically expire after 10 minutes

**Expiration Handling:**
- **Graceful Degradation**: API returns 401 with clear error message
- **Refresh Opportunity**: Client can use refresh token for new access token
- **Re-authentication**: If refresh token also expired, require login

**Cleanup Eligibility:**
- **Grace Period**: Allow brief period for client-side cleanup
- **Database Cleanup**: Remove expired tokens after grace period
- **Audit Retention**: Preserve audit records per compliance requirements

### 6. Token Refresh Flow

**OAuth 2.1 Refresh Process:**
1. **Refresh Token Validation**: Verify refresh token is valid and not expired
2. **Client Authentication**: Authenticate OAuth client (confidential clients)
3. **Scope Preservation**: Maintain originally granted scopes
4. **Token Revocation**: Invalidate current access and refresh tokens
5. **New Token Generation**: Create new token pair with fresh JTI
6. **Token Rotation**: Generate new refresh token for security
7. **Response**: Return new tokens to client

**Security Features:**
- **Automatic Rotation**: Refresh tokens are single-use
- **Scope Limitation**: New tokens limited to original granted scopes
- **Client Binding**: Tokens tied to specific OAuth client
- **Replay Protection**: Old refresh tokens immediately invalidated

### 7. Database Cleanup Process

**Automated Maintenance:**
- **Scheduled Jobs**: Regular cleanup of expired tokens
- **Performance Optimization**: Remove unnecessary database records
- **Audit Preservation**: Maintain security audit trails
- **Cascading Cleanup**: Remove related records (client_scopes, etc.)

**Cleanup Criteria:**
- **Expired Tokens**: Past expiration + grace period
- **Revoked Tokens**: After audit retention period
- **Orphaned Records**: Tokens for deleted users/clients
- **Performance Thresholds**: When database growth impacts performance

## OAuth 2.1 Enhancements

### Scope-Based Access Control

**Scope Validation:**
- **Request Scopes**: Validate required scopes for API endpoints
- **Token Scopes**: Check granted scopes in token payload
- **Scope Hierarchy**: Support for nested permission structures
- **Dynamic Scopes**: Runtime scope validation and enforcement

**Scope Management:**
- **Default Scopes**: Automatically granted permissions
- **Requested Scopes**: Client-requested permissions requiring user consent
- **Granted Scopes**: Final approved permissions stored in token
- **Scope Limitation**: Tokens cannot exceed originally granted scopes

### PKCE Integration

**Authorization Code Tokens:**
- **PKCE Verification**: Code verifier validation during token exchange
- **Single Use**: Authorization codes immediately invalidated after use
- **Short Expiration**: 10-minute maximum lifetime per OAuth 2.1
- **Client Binding**: Codes tied to specific client and redirect URI

### Token Revocation Endpoint

**RFC 7009 Compliance:**
- **POST /auth/revoke**: Standard token revocation endpoint
- **Token Type Hints**: Support for access_token and refresh_token hints
- **Client Authentication**: Proper client credential validation
- **Consistent Response**: Always return HTTP 200 to prevent enumeration

## Security Considerations

### JTI-Based Tracking

**Benefits:**
- **Immediate Revocation**: Tokens can be invalidated instantly
- **Replay Prevention**: Each token has unique identifier
- **Audit Trail**: Complete token lifecycle tracking
- **Granular Control**: Individual token management

**Implementation:**
- **UUID JTI**: Cryptographically secure unique identifiers
- **Database Index**: Optimized JTI lookups for performance
- **Memory Efficiency**: Minimal additional storage overhead
- **Scalability**: Supports high-volume token operations

### Token Security

**Cryptographic Protection:**
- **Strong Signatures**: HMAC-SHA256 or RSA signatures
- **Secret Rotation**: Support for key rotation without downtime
- **Entropy Requirements**: High-quality random number generation
- **Timing Attack Prevention**: Constant-time comparisons

**Transport Security:**
- **HTTPS Only**: Tokens never transmitted over unencrypted connections
- **Secure Headers**: Proper HTTP security headers
- **CORS Protection**: Cross-origin request validation
- **Content Security Policy**: XSS and injection prevention

## Performance Optimization

### Database Efficiency

**Optimized Queries:**
- **Indexed Lookups**: JTI and user_id indexes for fast retrieval
- **Bulk Operations**: Efficient batch processing for cleanup
- **Connection Pooling**: Reuse database connections
- **Query Caching**: Cache frequently accessed data

**Scalability Features:**
- **Stateless Design**: No server-side session storage
- **Horizontal Scaling**: Multiple server instances supported
- **Load Balancing**: Distribute token validation load
- **Caching Layers**: Optional Redis integration for high volume

### Monitoring and Metrics

**Token Metrics:**
- **Creation Rate**: Tokens generated per time period
- **Validation Rate**: Token validation requests per second
- **Revocation Rate**: Token invalidation frequency
- **Error Rate**: Failed validation attempts

**Performance Metrics:**
- **Database Latency**: Token lookup response times
- **Memory Usage**: Server memory consumption
- **CPU Utilization**: Token processing overhead
- **Network Throughput**: Token-related network traffic

This comprehensive token lifecycle provides enterprise-grade security, performance, and compliance for both traditional authentication and modern OAuth 2.1 flows.
