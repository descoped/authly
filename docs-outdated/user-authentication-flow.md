# User Authentication Flow

This document describes the authentication flows supported by Authly, including both traditional password-based authentication and OAuth 2.1 authorization code flow.

## Authentication Methods

Authly supports multiple authentication grant types for different use cases:

1. **Password Grant**: Direct username/password authentication for trusted clients
2. **Authorization Code Grant**: OAuth 2.1 flow with PKCE for third-party applications

## Visual Flow Diagram

![User Authentication Flow](user-authentication-flow.mmd)

## Password Grant Flow

The password grant provides direct authentication for trusted first-party applications:

### Flow Steps
1. **Rate Limiting**: Check for brute force protection
2. **User Lookup**: Retrieve user by username from database
3. **Password Verification**: Validate credentials using bcrypt
4. **Token Creation**: Generate access and refresh tokens with JTI
5. **Token Storage**: Store tokens in database for revocation support
6. **Login Update**: Record successful login timestamp

### Security Features
- **Rate Limiting**: Protects against brute force attacks
- **Bcrypt Hashing**: Secure password storage with salt
- **JTI Tracking**: Enables token revocation and replay prevention
- **Token Rotation**: Fresh tokens on each authentication

## Authorization Code Grant Flow

The authorization code grant implements OAuth 2.1 with mandatory PKCE:

### Flow Steps  
1. **Client Authentication**: Verify OAuth client credentials
2. **Code Validation**: Validate authorization code and expiration
3. **PKCE Verification**: Verify code_verifier matches code_challenge
4. **Single Use**: Immediately invalidate authorization code
5. **Token Creation**: Generate scoped access and refresh tokens
6. **Scope Assignment**: Include granted scopes in token response

### Security Features
- **PKCE Protection**: Prevents authorization code interception
- **Client Authentication**: Secure confidential client verification
- **Code Expiration**: 10-minute maximum lifetime per OAuth 2.1
- **Single Use Codes**: Authorization codes cannot be reused
- **Scope Limitation**: Tokens limited to granted permissions

## Token Validation

Both grant types produce tokens validated identically:

### Validation Process
1. **JWT Signature**: Verify token signature with secret key
2. **Expiration Check**: Ensure token hasn't expired
3. **JTI Lookup**: Check token hasn't been revoked
4. **User Status**: Verify user account is still active
5. **Scope Check**: Validate required permissions (OAuth tokens)

### Token Types
- **Access Tokens**: Short-lived (30 minutes) for API access
- **Refresh Tokens**: Long-lived (7 days) for token renewal
- **Scoped Tokens**: OAuth tokens include granted scope limitations

## Error Handling

### Password Grant Errors
- **429 Too Many Requests**: Rate limit exceeded
- **401 Unauthorized**: Invalid username or password
- **403 Forbidden**: Account inactive or unverified

### Authorization Code Grant Errors
- **400 Bad Request**: Invalid authorization code or PKCE failure
- **401 Unauthorized**: Client authentication failed
- **400 Invalid Grant**: Expired or already used authorization code

### Token Access Errors
- **401 Unauthorized**: Invalid or expired token
- **403 Forbidden**: Insufficient scope permissions
- **401 Unauthorized**: Revoked token (JTI not found)

## Grant Type Selection

### Use Password Grant When:
- First-party applications with trusted client credentials
- Mobile apps with secure credential storage
- Server-to-server authentication
- Legacy system integration

### Use Authorization Code Grant When:
- Third-party applications requiring user authorization
- Web applications without secure credential storage
- Public clients (SPAs, mobile apps) using OAuth
- Applications requiring granular scope permissions

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false
);
```

### Tokens Table
```sql
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    token_type VARCHAR(20) NOT NULL,
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    invalidated BOOLEAN DEFAULT false
);
```

### OAuth Tables
```sql
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),
    client_type VARCHAR(20) NOT NULL,
    redirect_uris TEXT[] NOT NULL
);

CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id),
    user_id UUID NOT NULL REFERENCES users(id),
    scopes TEXT[] NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

## Configuration

### Token Settings
```python
# JWT token configuration
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
JWT_ALGORITHM = "HS256"

# OAuth authorization code settings  
AUTHORIZATION_CODE_EXPIRE_MINUTES = 10
PKCE_REQUIRED = True  # Mandatory for OAuth 2.1
```

### Security Settings
```python
# Rate limiting configuration
MAX_LOGIN_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW = 300  # 5 minutes

# Password security
BCRYPT_ROUNDS = 12
PASSWORD_MIN_LENGTH = 8
```

This multi-grant authentication system provides flexibility for various client types while maintaining enterprise-grade security standards.