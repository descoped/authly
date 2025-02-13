# Authly

Authly is a robust Python framework for Authentication and User Token Handling built on FastAPI. It provides secure, scalable, and easy-to-integrate authentication services with features like JWT token management, user sessions, and secure password handling.

## Features

- **Secure Authentication**
  - JWT-based authentication with access and refresh tokens
  - Password hashing with bcrypt
  - Rate limiting and brute force protection
  - Secure token storage and management

- **User Management**
  - User registration and verification
  - Role-based access control (admin/user)
  - User profile management
  - Session management

- **Token Management**
  - Automatic token rotation
  - Token invalidation and cleanup
  - Refresh token handling
  - Token blacklisting

- **Security Features**
  - Secure secret management
  - CORS protection
  - Security headers
  - Rate limiting

- **Database Integration**
  - PostgreSQL support with psycopg
  - Connection pooling
  - Transaction management
  - Vector support (pgvector)

## Installation

```bash
pip install authly
```

Or with Poetry:

```bash
poetry add authly
```

## Quick Start

1. Create a new project and install dependencies:

```bash
poetry new myproject
cd myproject
poetry add authly
```

2. Set up your environment variables:

```bash
# .env
JWT_SECRET_KEY="your-production-secret-here"
JWT_REFRESH_SECRET_KEY="your-refresh-secret-key-here"
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

3. Create your FastAPI application:

```python
from fastapi import FastAPI
from authly import Authly, AuthlyConfig
from authly.config import EnvSecretProvider
from authly.api import auth_router, users_router

# Initialize configuration
secret_provider = EnvSecretProvider()
config = AuthlyConfig.load(secret_provider)

# Create database pool
pool = AsyncConnectionPool(
    "postgresql://user:password@localhost:5432/db"
)

# Initialize Authly
authly = Authly.initialize(pool, config)

# Create FastAPI app
app = FastAPI()

# Include Authly routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
```

## Sequence diagrams

### System Architecture
- [🏗️ Component Architecture](https://github.com/descoped/authly/blob/master/docs/component-architecture.md)

### Authentication Flows
- [🔐 User Registration and Verification Flow](https://github.com/descoped/authly/blob/master/docs/user-registration-and-verification-flow.md)
- [🔑 User Authentication Flow](https://github.com/descoped/authly/blob/master/docs/user-authentication-flow.md)
- [🚪 Logout Flow](https://github.com/descoped/authly/blob/master/docs/logout-flow.md)

### Token Management
- [🔄 Token Refresh Flow](https://github.com/descoped/authly/blob/master/docs/token-refresh-flow.md)
- [📊 State Diagram for Token Lifecycle](https://github.com/descoped/authly/blob/master/docs/state-diagram-for-token-lifecycle.md)
- [📊 State Diagram for User Account](https://github.com/descoped/authly/blob/master/docs/state-diagram-for-user-account.md)


## API Documentation

### Authentication Endpoints

#### POST /auth/token
Login and obtain access token.

**Request Body:**
```json
{
    "username": "string",
    "password": "string",
    "grant_type": "password"
}
```

**Response:**
```json
{
    "access_token": "string",
    "refresh_token": "string",
    "token_type": "Bearer",
    "expires_in": 1800
}
```

**Status Codes:**
- 200: Successful login
- 400: Invalid request body
- 401: Invalid credentials
- 403: Account not verified/inactive
- 429: Too many requests

#### POST /auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
    "refresh_token": "string",
    "grant_type": "refresh_token"
}
```

**Response:**
```json
{
    "access_token": "string",
    "refresh_token": "string",
    "token_type": "Bearer",
    "expires_in": 1800
}
```

**Status Codes:**
- 200: Token refreshed successfully
- 400: Invalid refresh token
- 401: Invalid or expired refresh token

#### POST /auth/logout
Logout and invalidate all active tokens.

**Headers:**
- Authorization: Bearer {access_token}

**Response:**
```json
{
    "message": "Successfully logged out",
    "invalidated_tokens": 2
}
```

**Status Codes:**
- 200: Successful logout
- 401: Invalid token
- 500: Server error

### User Management Endpoints

#### POST /users/
Create a new user account.

**Request Body:**
```json
{
    "username": "string",
    "email": "string",
    "password": "string"
}
```

**Response:**
```json
{
    "id": "uuid",
    "username": "string",
    "email": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "last_login": "datetime",
    "is_active": true,
    "is_verified": false,
    "is_admin": false
}
```

**Status Codes:**
- 201: User created successfully
- 400: Invalid request body or duplicate username/email
- 500: Server error

#### GET /users/me
Get current user information.

**Headers:**
- Authorization: Bearer {access_token}

**Response:**
```json
{
    "id": "uuid",
    "username": "string",
    "email": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "last_login": "datetime",
    "is_active": true,
    "is_verified": true,
    "is_admin": false
}
```

**Status Codes:**
- 200: Success
- 401: Not authenticated
- 403: Forbidden

#### GET /users/{user_id}
Get user information by ID.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- user_id: UUID of the user

**Response:**
```json
{
    "id": "uuid",
    "username": "string",
    "email": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "last_login": "datetime",
    "is_active": true,
    "is_verified": true,
    "is_admin": false
}
```

**Status Codes:**
- 200: Success
- 404: User not found
- 401: Not authenticated

#### PUT /users/{user_id}
Update user information.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- user_id: UUID of the user

**Request Body:**
```json
{
    "username": "string",
    "email": "string",
    "password": "string",
    "is_active": true,
    "is_verified": true,
    "is_admin": false
}
```

**Response:**
```json
{
    "id": "uuid",
    "username": "string",
    "email": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "last_login": "datetime",
    "is_active": true,
    "is_verified": true,
    "is_admin": false
}
```

**Status Codes:**
- 200: Success
- 400: Invalid request body
- 401: Not authenticated
- 403: Forbidden
- 404: User not found

#### DELETE /users/{user_id}
Delete a user account.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- user_id: UUID of the user

**Status Codes:**
- 204: Successfully deleted
- 401: Not authenticated
- 403: Forbidden
- 404: User not found

#### PUT /users/{user_id}/verify
Verify a user account.

**Headers:**
- Authorization: Bearer {access_token}

**Parameters:**
- user_id: UUID of the user

**Response:**
```json
{
    "id": "uuid",
    "username": "string",
    "email": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "last_login": "datetime",
    "is_active": true,
    "is_verified": true,
    "is_admin": false
}
```

**Status Codes:**
- 200: Successfully verified
- 401: Not authenticated
- 403: Forbidden
- 404: User not found

## Configuration

Authly can be configured through environment variables or configuration providers:

```python
from authly.config import FileSecretProvider, StaticSecretProvider

# Using environment variables
provider = EnvSecretProvider()

# Using file-based secrets
provider = FileSecretProvider(Path("secrets.json"))

# Using static secrets (for testing)
provider = StaticSecretProvider(
    secret_key="test-secret-key",
    refresh_secret_key="test-refresh-key"
)
```

## Database Setup

1. Create the required database and user:

```sql
CREATE USER authly WITH PASSWORD 'your_password';
CREATE DATABASE authly_db;
GRANT ALL PRIVILEGES ON DATABASE authly_db TO authly;
```

2. Run the initialization scripts:

```sql
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- Additional fields...
);

CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_jti VARCHAR(64) NOT NULL UNIQUE,
    -- Additional fields...
);
```

## Security Features

### Password Hashing and Storage

Authly uses bcrypt for secure password hashing with the following security measures:

- Automatic salt generation for each password
- Configurable work factor for future-proofing against hardware improvements
- Memory-hard hashing algorithm resistant to GPU/ASIC attacks

Example implementation:

```python
from authly.auth import get_password_hash, verify_password

# Hash password with bcrypt
hashed = get_password_hash("user_password")

# Verify password - timing-safe comparison
is_valid = verify_password("user_password", hashed)
```

### Token Security

Authly implements a comprehensive token security system:

#### JWT Token Management
- Short-lived access tokens (configurable, default 30 minutes)
- Separate refresh tokens with longer lifetime
- JTI (JWT ID) claim for token revocation
- Token payload encryption for sensitive data
- Automatic token rotation on refresh

#### Token Storage and Validation
```python
# Token creation with JTI
access_token = create_access_token(
    data={"sub": user_id, "jti": token_jti},
    secret_key=config.secret_key,
    algorithm="HS256",
    expires_delta=30  # minutes
)

# Token validation
try:
    payload = decode_token(token, secret_key, algorithm="HS256")
    is_valid = await token_service.is_token_valid(payload["jti"])
except JWTError:
    raise InvalidToken()
```

#### Token Cleanup and Management
- Automatic cleanup of expired tokens
- Token blacklisting for immediate revocation
- Database-backed token storage for persistence
- Transaction-safe token operations

### Rate Limiting and Brute Force Protection

Comprehensive protection against automated attacks:

#### Rate Limiting Implementation
```python
from authly.api.rate_limiter import RateLimiter

# Configure rate limits
limiter = RateLimiter(
    max_requests=5,     # Maximum requests
    window_seconds=60   # Time window
)

# Usage in endpoint
async def login_endpoint():
    await limiter.check_rate_limit(f"login:{username}")
```

#### Login Security
- Progressive delays on failed attempts
- Account lockout after multiple failures
- IP-based rate limiting
- User agent tracking
- Geographic location monitoring (optional)

### Secure Session Management

Robust session handling features:

- Secure session creation and validation
- Session timeout management
- Concurrent session control
- Forced logout capabilities
- Session activity tracking

### Database Security

Secure database operations:

- Prepared statements for SQL injection prevention
- Connection pooling with SSL/TLS
- Transaction isolation
- Automatic connection encryption
- Least privilege database users

### API Security Headers

Comprehensive security headers implementation:

```python
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        })
        return response
```

### Secret Management

Secure handling of sensitive configuration:

- Encrypted secret storage
- Automatic key rotation
- Secure memory wiping
- Hardware security module (HSM) support
- Environment variable protection

### CORS Protection

Configurable CORS policy:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Security Best Practices

Additional security measures:

1. **Input Validation**
   - Strict type checking
   - Schema validation
   - Content length limits
   - Character encoding validation

2. **Output Encoding**
   - HTML escaping
   - JSON encoding
   - CSV injection prevention
   - File name sanitization

3. **Error Handling**
   - Generic error messages
   - No stack traces in production
   - Structured error logging
   - Security event auditing

4. **Secure Development**
   - Regular dependency updates
   - Security scanning integration
   - Code review requirements
   - Security testing automation

## Testing

Run the test suite:

```bash
pytest
```

Run specific tests:

```bash
pytest tests/test_auth.py -v
pytest tests/test_users.py -v
```

Run the API test script:

```bash
./api-test.sh
```

## Development

1. Clone the repository:

```bash
git clone https://github.com/yourusername/authly.git
cd authly
```

2. Install development dependencies:

```bash
poetry install
```

3. Run linting:

```bash
poetry run flake8
poetry run black .
poetry run isort .
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Acknowledgments

- FastAPI
- PostgreSQL
- Python-Jose
- Bcrypt
- Psycopg