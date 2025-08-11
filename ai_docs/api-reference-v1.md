Total endpoints found: 59
Tags found: ['OAuth 2.1', 'OAuth 2.1 Discovery', 'OpenID Connect', 'admin', 'auth', 'authentication', 'health', 'metrics', 'users']

# Authly API Reference v1

Generated from OpenAPI specification at http://localhost:8000/openapi.json

**Total Endpoints:** 59

## API Endpoints by Category

### OAuth 2.1

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/api/v1/oauth/authorize` | OAuth 2.1 Authorization with Session Support | OAuth 2.1 Authorization endpoint with support for both session-based |
| **POST** | `/api/v1/oauth/authorize` | OAuth 2.1 Authorization Processing with Session Support | OAuth 2.1 Authorization processing endpoint with support for both |
| **POST** | `/api/v1/oauth/introspect` | Introspect Token Endpoint | OAuth 2.0 Token Introspection Endpoint (RFC 7662). |
| **POST** | `/api/v1/oauth/refresh` | Refresh Access Token | Create new token pair while invalidating old refresh token |
| **POST** | `/api/v1/oauth/revoke` | Revoke Token | OAuth 2.0 Token Revocation Endpoint (RFC 7009). |
| **POST** | `/api/v1/oauth/token` | Get Access Token | OAuth 2.1 Token Endpoint - supports multiple grant types. |

### OAuth 2.1 Discovery

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/.well-known/oauth-authorization-server` | OAuth 2.1 Authorization Server Discovery | OAuth 2.1 Authorization Server Metadata endpoint as defined in RFC 8414. |

### OpenID Connect

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/.well-known/jwks.json` | JSON Web Key Set (JWKS) | JSON Web Key Set endpoint as defined in RFC 7517. |
| **GET** | `/.well-known/openid-configuration` | OpenID Connect Discovery | OpenID Connect Discovery endpoint as defined in OpenID Connect Discovery 1.0. |
| **GET** | `/oidc/frontchannel/logout` | OIDC Front-Channel Logout | Front-channel logout endpoint as defined in OIDC Front-Channel Logout 1.0. |
| **GET** | `/oidc/logout` | OpenID Connect End Session | OpenID Connect End Session endpoint as defined in OIDC Session Management 1.0. |
| **GET** | `/oidc/session/check` | OIDC Session Status Check | Session status check endpoint for OIDC Session Management 1.0. |
| **GET** | `/oidc/session/iframe` | OIDC Session Management iframe | Session management iframe endpoint as defined in OIDC Session Management 1.0. |
| **GET** | `/oidc/userinfo` | OpenID Connect UserInfo Endpoint | OpenID Connect UserInfo endpoint as defined in OIDC Core 1.0 Section 5.3. |
| **PUT** | `/oidc/userinfo` | Update OpenID Connect UserInfo | Update user profile information via OpenID Connect UserInfo endpoint. |

### admin

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/admin/clients` | List Clients | List OAuth clients with pagination. |
| **POST** | `/admin/clients` | Create Client | Create a new OAuth client. |
| **GET** | `/admin/clients/oidc/algorithms` | Get Supported Oidc Algorithms | Get list of supported OpenID Connect ID token signing algorithms. |
| **DELETE** | `/admin/clients/{client_id}` | Delete Client | Delete (deactivate) a client. |
| **GET** | `/admin/clients/{client_id}` | Get Client | Get detailed information about a specific client. |
| **PUT** | `/admin/clients/{client_id}` | Update Client | Update client information. |
| **GET** | `/admin/clients/{client_id}/oidc` | Get Client Oidc Settings | Get OpenID Connect specific settings for a client. |
| **PUT** | `/admin/clients/{client_id}/oidc` | Update Client Oidc Settings | Update OpenID Connect specific settings for a client. |
| **POST** | `/admin/clients/{client_id}/regenerate-secret` | Regenerate Client Secret | Regenerate client secret for confidential clients. |
| **GET** | `/admin/dashboard/stats` | Get Admin Dashboard Stats | Get cached dashboard statistics for admin overview. |
| **GET** | `/admin/health` | Admin Health | Admin API health check endpoint. |
| **GET** | `/admin/scopes` | List Scopes | List OAuth scopes with pagination and filtering. |
| **POST** | `/admin/scopes` | Create Scope | Create a new OAuth scope. |
| **GET** | `/admin/scopes/defaults` | Get Default Scopes | Get all default scopes. |
| **DELETE** | `/admin/scopes/{scope_name}` | Delete Scope | Delete (deactivate) a scope. |
| **GET** | `/admin/scopes/{scope_name}` | Get Scope | Get detailed information about a specific scope. |
| **PUT** | `/admin/scopes/{scope_name}` | Update Scope | Update scope information. |
| **GET** | `/admin/status` | Get System Status | Get comprehensive system status and configuration. |
| **GET** | `/admin/users` | Get Admin Users | Get paginated list of users with advanced filtering capabilities. |
| **POST** | `/admin/users` | Create Admin User | Create a new user with admin privileges. |
| **DELETE** | `/admin/users/{user_id}` | Delete Admin User | Delete a user with complete cascade cleanup. |
| **GET** | `/admin/users/{user_id}` | Get Admin User Details | Get detailed information about a specific user. |
| **PUT** | `/admin/users/{user_id}` | Update Admin User | Update a user with admin privileges. |
| **POST** | `/admin/users/{user_id}/reset-password` | Reset User Password | Reset a user's password with secure temporary password generation. |
| **DELETE** | `/admin/users/{user_id}/sessions` | Revoke All User Sessions | Revoke all active sessions for a user (force logout). |
| **GET** | `/admin/users/{user_id}/sessions` | Get User Sessions | Get paginated list of user sessions with detailed information. |
| **DELETE** | `/admin/users/{user_id}/sessions/{session_id}` | Revoke Specific User Session | Revoke a specific user session by session ID. |

### auth

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **POST** | `/api/v1/auth/change-password` | Change Password | Change user password. |
| **POST** | `/api/v1/auth/logout` | Logout | Invalidate all active tokens for the current user |
| **GET** | `/api/v1/auth/password-status` | Get Password Status | Check if current user requires password change. |

### authentication

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/auth/login` | Show Login Page | Display the login page. |
| **POST** | `/auth/login` | Login | Process login form submission. |
| **GET** | `/auth/logout` | Logout | Log out the current user. |
| **POST** | `/auth/logout` | Logout | Log out the current user. |
| **GET** | `/auth/session` | Get Session Info | Get current session information. |
| **POST** | `/auth/session/validate` | Validate Session | Validate the current session. |

### health

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/health` | Health Check | - |

### metrics

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/metrics` | Get Metrics | Prometheus metrics endpoint. |

### users

| Method | Path | Summary | Description |
|--------|------|---------|-------------|
| **GET** | `/api/v1/users/` | Get Users | Get a list of users with pagination - ADMIN ONLY. |
| **POST** | `/api/v1/users/` | Create a new user account | Create a new user account with a unique username and email. |
| **DELETE** | `/api/v1/users/{user_id}` | Delete User | Delete user account - ADMIN ONLY. |
| **GET** | `/api/v1/users/{user_id}` | Get User | Get user by ID - ADMIN ONLY |
| **PUT** | `/api/v1/users/{user_id}` | Update User | Update user information - ADMIN ONLY. |
| **PUT** | `/api/v1/users/{user_id}/verify` | Verify User | Verify a user's account - ADMIN ONLY. |

## Complete Endpoint List

| Method | Path | Tags |
|--------|------|------|
| **GET** | `/.well-known/jwks.json` | OpenID Connect |
| **GET** | `/.well-known/oauth-authorization-server` | OAuth 2.1 Discovery |
| **GET** | `/.well-known/openid-configuration` | OpenID Connect |
| **GET** | `/admin/clients` | admin |
| **POST** | `/admin/clients` | admin |
| **GET** | `/admin/clients/oidc/algorithms` | admin |
| **DELETE** | `/admin/clients/{client_id}` | admin |
| **GET** | `/admin/clients/{client_id}` | admin |
| **PUT** | `/admin/clients/{client_id}` | admin |
| **GET** | `/admin/clients/{client_id}/oidc` | admin |
| **PUT** | `/admin/clients/{client_id}/oidc` | admin |
| **POST** | `/admin/clients/{client_id}/regenerate-secret` | admin |
| **GET** | `/admin/dashboard/stats` | admin |
| **GET** | `/admin/health` | admin |
| **GET** | `/admin/scopes` | admin |
| **POST** | `/admin/scopes` | admin |
| **GET** | `/admin/scopes/defaults` | admin |
| **DELETE** | `/admin/scopes/{scope_name}` | admin |
| **GET** | `/admin/scopes/{scope_name}` | admin |
| **PUT** | `/admin/scopes/{scope_name}` | admin |
| **GET** | `/admin/status` | admin |
| **GET** | `/admin/users` | admin |
| **POST** | `/admin/users` | admin |
| **DELETE** | `/admin/users/{user_id}` | admin |
| **GET** | `/admin/users/{user_id}` | admin |
| **PUT** | `/admin/users/{user_id}` | admin |
| **POST** | `/admin/users/{user_id}/reset-password` | admin |
| **DELETE** | `/admin/users/{user_id}/sessions` | admin |
| **GET** | `/admin/users/{user_id}/sessions` | admin |
| **DELETE** | `/admin/users/{user_id}/sessions/{session_id}` | admin |
| **POST** | `/api/v1/auth/change-password` | auth |
| **POST** | `/api/v1/auth/logout` | auth |
| **GET** | `/api/v1/auth/password-status` | auth |
| **GET** | `/api/v1/oauth/authorize` | OAuth 2.1 |
| **POST** | `/api/v1/oauth/authorize` | OAuth 2.1 |
| **POST** | `/api/v1/oauth/introspect` | OAuth 2.1 |
| **POST** | `/api/v1/oauth/refresh` | OAuth 2.1 |
| **POST** | `/api/v1/oauth/revoke` | OAuth 2.1 |
| **POST** | `/api/v1/oauth/token` | OAuth 2.1 |
| **GET** | `/api/v1/users/` | users |
| **POST** | `/api/v1/users/` | users |
| **DELETE** | `/api/v1/users/{user_id}` | users |
| **GET** | `/api/v1/users/{user_id}` | users |
| **PUT** | `/api/v1/users/{user_id}` | users |
| **PUT** | `/api/v1/users/{user_id}/verify` | users |
| **GET** | `/auth/login` | authentication |
| **POST** | `/auth/login` | authentication |
| **GET** | `/auth/logout` | authentication |
| **POST** | `/auth/logout` | authentication |
| **GET** | `/auth/session` | authentication |
| **POST** | `/auth/session/validate` | authentication |
| **GET** | `/health` | health |
| **GET** | `/metrics` | metrics |
| **GET** | `/oidc/frontchannel/logout` | OpenID Connect |
| **GET** | `/oidc/logout` | OpenID Connect |
| **GET** | `/oidc/session/check` | OpenID Connect |
| **GET** | `/oidc/session/iframe` | OpenID Connect |
| **GET** | `/oidc/userinfo` | OpenID Connect |
| **PUT** | `/oidc/userinfo` | OpenID Connect |

