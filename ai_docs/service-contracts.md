# Authly Service Contracts Documentation

This document describes the actual service contracts in the Authly codebase to guide test writing and avoid API mismatches.

## TokenService

**Module**: `authly.tokens.service`

### Constructor
```python
def __init__(
    self, 
    repository: TokenRepository, 
    config: AuthlyConfig, 
    client_repository: Optional[ClientRepository] = None
)
```

### Key Methods

#### Token Creation
```python
async def create_token_pair(
    self, 
    user: UserModel, 
    scope: str | None = None
) -> TokenPairResponse
```
- Creates access and refresh token pair for a user
- Returns TokenPairResponse with access_token, refresh_token, token_type, expires_in, scope

#### Token Refresh
```python
async def refresh_token_pair(
    self, 
    refresh_token: str, 
    user_repo: UserRepository
) -> TokenPairResponse
```
- Refreshes tokens using a refresh token
- Validates and rotates refresh tokens

#### Token Revocation
```python
async def revoke_token(
    self, 
    token: str, 
    token_type_hint: str | None = None
) -> bool
```
- Revokes a specific token
- Returns True if successful

#### Token Validation
```python
async def is_token_valid(self, token_jti: str) -> bool
```
- Checks if a token JTI is valid
- Requires extracting JTI from token first using decode_token

### Usage Pattern
```python
# Create service
token_service = TokenService(
    repository=token_repo,
    config=config,
    client_repository=client_repo  # Optional
)

# Create tokens for user
tokens = await token_service.create_token_pair(user, "read write")

# Refresh tokens
new_tokens = await token_service.refresh_token_pair(
    tokens.refresh_token, 
    user_repo
)

# Revoke token
await token_service.revoke_token(tokens.access_token, "access_token")
```

## TokenRepository

**Module**: `authly.tokens.repository`

### Key Methods
- `store_token(token: TokenModel) -> TokenModel` - Store a new token
- `get_by_jti(jti: str) -> TokenModel | None` - Get token by JTI
- `get_user_tokens(user_id, token_type, valid_only) -> list[TokenModel]` - Get user's tokens
- `invalidate_token(jti: str) -> None` - Invalidate a token
- `is_token_valid(jti: str) -> bool` - Check token validity

## OAuth Token Endpoint

**Endpoint**: `POST /api/v1/oauth/token`

### Request Format
- Content-Type: `application/x-www-form-urlencoded`
- Body parameters:
  - `grant_type`: "password", "authorization_code", "refresh_token"
  - Grant-specific parameters

### Supported Grant Types

#### Password Grant (Implemented)
```
grant_type=password
username={username}
password={password}
scope={optional_scope}
```

#### Authorization Code Grant (Implemented)
```
grant_type=authorization_code
code={authorization_code}
redirect_uri={redirect_uri}
code_verifier={pkce_verifier}
client_id={client_id}
```

#### Refresh Token Grant (Implemented)
```
grant_type=refresh_token
refresh_token={refresh_token}
```

#### Client Credentials Grant (NOT IMPLEMENTED)
```
grant_type=client_credentials
scope={scope}
# With Basic Auth header for client authentication
```

### Response Format
```json
{
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "read write"
}
```

## ClientRepository

**Module**: `authly.oauth.client_repository`

### Key Methods
- `create_client(data: dict) -> ClientModel` - Create new OAuth client
- `get_client(client_id: str) -> ClientModel | None` - Get client by ID
- `update_client(client_id: str, data: dict) -> ClientModel` - Update client
- `delete_client(client_id: str) -> None` - Delete client
- `list_clients(limit, offset) -> list[ClientModel]` - List clients

**Note**: No `authenticate_client` method exists. Client authentication is handled differently.

## AuthorizationService

**Module**: `authly.oauth.authorization_service`

### Constructor
```python
def __init__(
    self,
    client_repo: ClientRepository,
    scope_repo: ScopeRepository,
    auth_code_repo: AuthorizationCodeRepository
)
```

### Key Methods
```python
async def validate_authorization_request(
    self, 
    request: OAuthAuthorizationRequest
) -> tuple[bool, str | None, ClientModel | None]
```

```python
async def generate_authorization_code(
    self, 
    consent: UserConsentRequest
) -> str
```

```python
async def exchange_authorization_code(
    self,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str
) -> tuple[bool, AuthorizationCodeModel | None, str | None]
```

## Missing Services/Features

### OIDCTokenService
- **Status**: NOT IMPLEMENTED
- **Expected Module**: `authly.oidc.token_service`
- **Purpose**: Generate and validate ID tokens for OIDC

### Browser Authentication Endpoints
- **Status**: NOT IMPLEMENTED
- **Expected Endpoints**:
  - `GET /auth/login` - Login page
  - `POST /auth/login` - Process login
  - `POST /auth/logout` - Logout
  - `GET /auth/session` - Session info

### Session Management
- **Status**: NOT IMPLEMENTED
- **Expected Features**:
  - Session cookie handling
  - Session validation
  - Remember me functionality

## Testing Guidelines

### DO:
1. Use actual service constructors with correct parameter names
2. Import from correct modules (e.g., `authly.tokens.service` not `authly.oauth.token_service`)
3. Test via HTTP endpoints for integration tests
4. Test service methods directly for unit tests
5. Check for feature existence before testing

### DON'T:
1. Assume methods exist without checking
2. Create mock services that don't match actual signatures
3. Import from non-existent modules
4. Expect unimplemented features to work

## Example: Correct Test Pattern

```python
# Correct imports
from authly.tokens.service import TokenService
from authly.tokens.repository import TokenRepository
from authly.oauth.client_repository import ClientRepository

# Correct service initialization
async with transaction_manager.transaction() as conn:
    token_repo = TokenRepository(conn)
    client_repo = ClientRepository(conn)
    
    token_service = TokenService(
        repository=token_repo,
        config=config,
        client_repository=client_repo
    )
    
    # Use actual methods
    tokens = await token_service.create_token_pair(user, "read write")
```

## Notes for Future Development

1. **Client Credentials Grant**: Needs implementation in oauth_router.py
2. **OIDCTokenService**: Needs complete implementation for ID token handling
3. **Browser Auth**: Needs login/logout endpoints and session management
4. **Client Authentication**: Consider adding authenticate_client method to ClientRepository
5. **Token Introspection**: Consider adding proper introspection endpoint per RFC 7662