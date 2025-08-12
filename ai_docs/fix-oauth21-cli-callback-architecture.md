# Fix OAuth 2.1 CLI Callback Architecture

## Problem Statement

The current Authly CLI implementation violates SOLID principles by embedding an HTTP server for OAuth callbacks. This creates significant architectural, scalability, and deployment issues.

## Current Implementation Issues

### 1. Embedded HTTPServer in CLI (`src/authly/admin/api_client.py`)

```python
# Lines 442-453: CLI acts as both client AND server
server = HTTPServer(("localhost", callback_port), OAuthCallbackHandler)
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
```

**Problems:**
- Violates Single Responsibility Principle (SRP)
- CLI becomes both OAuth client and HTTP server
- Creates port conflicts with multiple instances
- Doesn't work properly in containerized environments

### 2. Docker Standalone Misconfiguration

The Docker setup (`docker-standalone/setup-cli-client.py`) registers OAuth client with localhost callbacks:

```python
redirect_uris = [
    f"http://localhost:{callback_port}/callback",  # Default: localhost:8899
    f"http://127.0.0.1:{callback_port}/callback",
]
```

**Issues:**
- `localhost:8899` is meaningless inside Docker containers
- s6-overlay manages services but doesn't provide callback handling
- Network isolation breaks the callback flow

### 3. SOLID Principles Violations

| Principle | Violation | Impact |
|-----------|-----------|---------|
| **Single Responsibility** | CLI is both client and server | Complex, hard to maintain |
| **Open/Closed** | Hard to extend for different environments | Can't adapt to cloud/container deployments |
| **Dependency Inversion** | Depends on concrete HTTPServer | Tightly coupled to implementation |

### 4. Scalability and Deployment Issues

- **Port Conflicts**: Each CLI instance needs unique port
- **Firewall Issues**: Local server requires open ports
- **Container Networking**: Localhost callbacks fail in Docker
- **Security Risk**: Exposes local HTTP server
- **Testing Complexity**: Hard to mock HTTP server in tests

## Root Cause Analysis

The issue arose from converting password grant (deprecated in OAuth 2.1) to Authorization Code Flow with PKCE. The implementation incorrectly assumed browser-based flow was appropriate for CLI, leading to the embedded HTTPServer anti-pattern.

## OAuth 2.1 Compliance Analysis

### OAuth 2.1 Requirements (draft-ietf-oauth-v2-1-11)

The OAuth 2.1 specification mandates:

1. **PKCE is REQUIRED** for all OAuth clients using Authorization Code flow (Section 7.1)
2. **Password grant is REMOVED** (Section 2.1)
3. **Implicit grant is REMOVED** (Section 2.1)
4. **Bearer tokens in query parameters FORBIDDEN** (Section 7.4)
5. **HTTPS is REQUIRED** for all endpoints except localhost (Section 7.5)
6. **Refresh tokens MUST be sender-constrained or one-time use** (Section 6.1)
7. **Authorization codes MUST be single-use** (Section 4.1.3)

### Compliance Status of Proposed Solutions

| Solution | OAuth 2.1 Compliant | Notes |
|----------|-------------------|--------|
| **Option 1: Device Flow** | ✅ **YES** | Device Authorization Grant (RFC 8628) is fully compatible with OAuth 2.1. PKCE is recommended but not required for Device Flow since there's no redirect. |
| **Option 2: Copy-Paste Auth Code** | ✅ **YES** | Authorization Code flow with PKCE is the core of OAuth 2.1. Manual code entry doesn't violate any requirements. |
| **Option 3: Current HTTPServer** | ❌ **NO** | While technically compliant, localhost HTTP servers create security risks and deployment issues that go against OAuth 2.1's security goals. |

### Why These Solutions Are OAuth 2.1 Compliant

#### Device Flow (RFC 8628) + OAuth 2.1
```
✅ No password grant used
✅ No implicit flow
✅ Authorization codes are single-use
✅ Tokens never in query parameters
✅ HTTPS for all server endpoints
✅ Refresh tokens can be bound or rotated
✅ PKCE optional but recommended for Device Flow
```

#### Authorization Code + PKCE (Manual)
```
✅ PKCE is mandatory and implemented
✅ No password grant used
✅ Authorization codes are single-use
✅ No redirect means no query parameters
✅ HTTPS for all server endpoints
✅ Refresh tokens follow OAuth 2.1 rules
```

### Important: Device Flow in OAuth 2.1 Context

While Device Flow (RFC 8628) is not explicitly mentioned in OAuth 2.1, it is:
- **Fully compatible** with OAuth 2.1 requirements
- **Recommended by OAuth working group** for CLI/device scenarios
- **More secure** than localhost redirects
- **Already standardized** as RFC 8628

The OAuth 2.1 draft doesn't prohibit additional grant types; it only removes insecure ones (password, implicit).

## Authentication Flow Clarification

**Important**: In all OAuth flows, the user must authenticate (enter username and password) before any authorization code is generated. The flow is:

1. **CLI initiates flow** → Gets device code or auth URL
2. **User visits browser** → Must login with credentials
3. **After successful login** → User enters device code OR server generates auth code
4. **CLI receives token** → After user completes authentication

The authorization code is only generated AFTER successful authentication. This ensures that only authenticated users can authorize CLI access.

## Recommended Solutions

### Option 1: Device Authorization Grant (RFC 8628) - **RECOMMENDED**

The Device Authorization Grant is specifically designed for CLI and limited-input devices.

#### Complete Flow Sequence Diagram

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   CLI User  │                    │  Authly CLI │                    │Authly Server│
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                   │                                   │
       │  1. authly admin auth login       │                                   │
       ├──────────────────────────────────►│                                   │
       │                                   │                                   │
       │                                   │  2. POST /oauth/device_authorization
       │                                   │     {client_id: "authly-cli"}    │
       │                                   ├──────────────────────────────────►│
       │                                   │                                   │
       │                                   │  3. Device Authorization Response │
       │                                   │     {device_code: "ABC123",      │
       │                                   │      user_code: "HJKL-MNOP",     │
       │                                   │      verification_uri: "...",    │
       │                                   │      expires_in: 600,            │
       │                                   │      interval: 5}                │
       │                                   │◄──────────────────────────────────┤
       │                                   │                                   │
       │  4. Display instructions:         │                                   │
       │     "Visit: https://authly/device"│                                   │
       │     "Enter code: HJKL-MNOP"       │                                   │
       │◄──────────────────────────────────┤                                   │
       │                                   │                                   │
       │                                   │  5. Start polling loop            │
       │                                   │     (every 5 seconds)             │
       │                                   ├───┐                               │
       │                                   │   │                               │
       │                                   │◄──┘                               │
       │                                   │                                   │
═══════╪═══════════════════════════════════╪═══════════════════════════════════╪═══════
       │                                   │                                   │
       │  6. Open browser, visit URL       │                                   │
       ├───────────────────────────────────┼──────────────────────────────────►│
       │                                   │                                   │
       │  7. Login page displayed          │                                   │
       │◄──────────────────────────────────┼───────────────────────────────────┤
       │                                   │                                   │
       │  8. Enter credentials             │                                   │
       │     username: admin               │                                   │
       │     password: ****                │                                   │
       ├───────────────────────────────────┼──────────────────────────────────►│
       │                                   │                                   │
       │                                   │                                   ├───┐
       │                                   │                                   │   │ Verify
       │                                   │                                   │   │ credentials
       │                                   │                                   │◄──┘
       │                                   │                                   │
       │  9. Device code entry page        │                                   │
       │     "Enter code: [HJKL-MNOP]"     │                                   │
       │◄──────────────────────────────────┼───────────────────────────────────┤
       │                                   │                                   │
       │  10. Submit device code           │                                   │
       ├───────────────────────────────────┼──────────────────────────────────►│
       │                                   │                                   │
       │                                   │                                   ├───┐
       │                                   │                                   │   │ 11. Validate
       │                                   │                                   │   │     user_code
       │                                   │                                   │◄──┘
       │                                   │                                   │
       │  12. "Authorization successful!"  │                                   │
       │      "Return to your CLI"         │                                   │
       │◄──────────────────────────────────┼───────────────────────────────────┤
       │                                   │                                   │
═══════╪═══════════════════════════════════╪═══════════════════════════════════╪═══════
       │                                   │                                   │
       │                                   │  13. POST /oauth/token            │
       │                                   │     {grant_type: "...device_code",│
       │                                   │      device_code: "ABC123",      │
       │                                   │      client_id: "authly-cli"}    │
       │                                   ├──────────────────────────────────►│
       │                                   │                                   │
       │                                   │                                   ├───┐
       │                                   │                                   │   │ 14. Verify
       │                                   │                                   │   │     device_code
       │                                   │                                   │   │     & approved
       │                                   │                                   │◄──┘
       │                                   │                                   │
       │                                   │  15. Token Response               │
       │                                   │     {access_token: "...",        │
       │                                   │      refresh_token: "...",       │
       │                                   │      expires_in: 3600,           │
       │                                   │      scope: "admin:*"}           │
       │                                   │◄──────────────────────────────────┤
       │                                   │                                   │
       │                                   ├───┐                               │
       │                                   │   │ 16. Save tokens               │
       │                                   │   │     to ~/.authly/             │
       │                                   │◄──┘     tokens.json              │
       │                                   │                                   │
       │  17. "✅ Authentication successful"│                                   │
       │      "Logged in as: admin"         │                                   │
       │◄──────────────────────────────────┤                                   │
       │                                   │                                   │
       │  18. authly admin clients list     │                                   │
       ├──────────────────────────────────►│                                   │
       │                                   │                                   │
       │                                   │  19. GET /admin/clients           │
       │                                   │     Authorization: Bearer ...     │
       │                                   ├──────────────────────────────────►│
       │                                   │                                   │
       │                                   │  20. Client list response         │
       │                                   │◄──────────────────────────────────┤
       │                                   │                                   │
       │  21. Display client list           │                                   │
       │◄──────────────────────────────────┤                                   │
       │                                   │                                   │
       ▼                                   ▼                                   ▼
```

#### Polling Detail During User Authorization

```
┌─────────────┐                    ┌─────────────┐
│  Authly CLI │                    │Authly Server│
└──────┬──────┘                    └──────┬──────┘
       │                                   │
       │  POST /oauth/token                │
       │  {grant_type: "device_code",      │
       │   device_code: "ABC123"}          │
       ├──────────────────────────────────►│
       │                                   │
       │  400 Bad Request                  │
       │  {error: "authorization_pending"} │
       │◄──────────────────────────────────┤
       │                                   │
       │  Wait 5 seconds...                │
       ├───┐                               │
       │   │                               │
       │◄──┘                               │
       │                                   │
       │  POST /oauth/token                │
       │  {grant_type: "device_code",      │
       │   device_code: "ABC123"}          │
       ├──────────────────────────────────►│
       │                                   │
       │  400 Bad Request                  │
       │  {error: "authorization_pending"} │
       │◄──────────────────────────────────┤
       │                                   │
       │  Wait 5 seconds...                │
       ├───┐                               │
       │   │                               │
       │◄──┘                               │
       │                                   │
       │  [User completes authorization]   │
       │                                   │
       │  POST /oauth/token                │
       │  {grant_type: "device_code",      │
       │   device_code: "ABC123"}          │
       ├──────────────────────────────────►│
       │                                   │
       │  200 OK                           │
       │  {access_token: "...",            │
       │   refresh_token: "..."}           │
       │◄──────────────────────────────────┤
       │                                   │
       ▼                                   ▼
```

#### Server-Side Implementation

```python
# New endpoints needed in oauth_router.py

@router.post("/api/v1/oauth/device_authorization")
async def device_authorization(
    client_id: str = Form(...),
    scope: str = Form(None),
) -> DeviceAuthorizationResponse:
    """Initiate device authorization flow."""
    device_code = generate_device_code()
    user_code = generate_user_code()  # Short, human-readable
    
    # Store pending authorization
    await store_device_auth(device_code, user_code, client_id, scope)
    
    return DeviceAuthorizationResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri="https://authly.example.com/device",
        verification_uri_complete=f"https://authly.example.com/device?user_code={user_code}",
        expires_in=600,
        interval=5
    )

@router.get("/device")
async def device_verification_page(user_code: str = None):
    """Serve device verification page."""
    return templates.TemplateResponse("device_auth.html", {
        "user_code": user_code
    })
```

#### CLI Implementation (No HTTPServer!)

```python
async def login_device_flow(self, scope: str | None = None) -> TokenInfo:
    """Authenticate using Device Authorization Grant - no local server needed."""
    
    # 1. Request device authorization
    device_response = await self._request("POST", "/api/v1/oauth/device_authorization", 
        form_data={
            "client_id": "authly-cli",
            "scope": scope
        },
        authenticated=False
    )
    
    device_data = device_response.json()
    
    # 2. Display instructions to user
    print(f"\n🔐 Device Authentication Required")
    print(f"   1. Visit: {device_data['verification_uri']}")
    print(f"   2. Enter code: {device_data['user_code']}")
    print(f"\n   Or visit directly: {device_data['verification_uri_complete']}\n")
    
    # 3. Poll for token
    interval = device_data.get('interval', 5)
    device_code = device_data['device_code']
    
    while True:
        await asyncio.sleep(interval)
        
        try:
            token_response = await self._request("POST", "/api/v1/oauth/token",
                form_data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": "authly-cli"
                },
                authenticated=False
            )
            
            # Success! Process token response
            token_data = token_response.json()
            return self._process_token_response(token_data)
            
        except AdminAPIError as e:
            if e.status_code == 400:
                error_data = e.response_body
                if "authorization_pending" in error_data:
                    continue  # Keep polling
                elif "slow_down" in error_data:
                    interval += 5  # Increase polling interval
                else:
                    raise  # Fatal error
```

### Option 2: Authorization Code Flow with Copy-Paste (No Local Server)

**Important**: Traditional Authorization Code Flow requires an HTTP server to receive the callback. Since we want to eliminate the HTTPServer from the CLI, we must use a modified approach where the server displays the code for manual copying.

#### Why Standard Authorization Code Flow Won't Work Without HTTPServer

```
Standard OAuth 2.0 Authorization Code Flow:
1. CLI opens browser to: /authorize?redirect_uri=http://localhost:8899/callback
2. User authenticates
3. Server redirects to: http://localhost:8899/callback?code=ABC123
4. ❌ REQUIRES HTTPServer at localhost:8899 to receive this callback!
```

#### Modified Copy-Paste Flow (No HTTPServer Needed)

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   CLI User  │                    │  Authly CLI │                    │Authly Server│
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                   │                                   │
       │  1. authly admin auth login       │                                   │
       ├──────────────────────────────────►│                                   │
       │                                   │                                   │
       │                                   │  2. Generate state & PKCE         │
       │                                   ├───┐                               │
       │                                   │   │ verifier, challenge          │
       │                                   │◄──┘                               │
       │                                   │                                   │
       │  3. Display URL:                  │                                   │
       │  "Visit: https://authly/cli-auth? │                                   │
       │   client_id=authly-cli&           │                                   │
       │   state=xyz&challenge=abc"        │                                   │
       │◄──────────────────────────────────┤                                   │
       │                                   │                                   │
       │  4. Open browser, visit URL       │                                   │
       ├───────────────────────────────────┼──────────────────────────────────►│
       │                                   │                                   │
       │  5. Login page                    │                                   │
       │◄──────────────────────────────────┼───────────────────────────────────┤
       │                                   │                                   │
       │  6. Authenticate                  │                                   │
       ├───────────────────────────────────┼──────────────────────────────────►│
       │                                   │                                   │
       │                                   │                                   ├───┐
       │                                   │                                   │   │ 7. Generate
       │                                   │                                   │   │    auth code
       │                                   │                                   │◄──┘
       │                                   │                                   │
       │  8. Display code page:             │                                   │
       │  "Your authorization code:         │                                   │
       │   ABC-123-XYZ                      │                                   │
       │   Copy this code to your CLI"      │                                   │
       │◄──────────────────────────────────┼───────────────────────────────────┤
       │                                   │                                   │
       │  9. Copy code                     │                                   │
       ├──────────────────────────────────►│                                   │
       │                                   │                                   │
       │  10. Paste code in CLI:           │                                   │
       │      "Enter code: ABC-123-XYZ"    │                                   │
       ├──────────────────────────────────►│                                   │
       │                                   │                                   │
       │                                   │  11. POST /oauth/token            │
       │                                   │      {grant_type: "authorization_code",
       │                                   │       code: "ABC-123-XYZ",        │
       │                                   │       code_verifier: "...",      │
       │                                   │       client_id: "authly-cli"}   │
       │                                   ├──────────────────────────────────►│
       │                                   │                                   │
       │                                   │  12. Token Response               │
       │                                   │◄──────────────────────────────────┤
       │                                   │                                   │
       │  13. "✅ Authenticated!"           │                                   │
       │◄──────────────────────────────────┤                                   │
       │                                   │                                   │
       ▼                                   ▼                                   ▼
```

#### Server Implementation for Copy-Paste Flow

```python
@router.get("/cli-auth")
async def cli_auth_page(
    request: Request,
    client_id: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str = "S256"
):
    """Special CLI authentication page that displays code instead of redirecting."""
    # Check if user is authenticated
    if not request.user.is_authenticated:
        # Redirect to login with return URL
        return RedirectResponse(f"/login?next=/cli-auth?{request.url.query}")
    
    # Generate authorization code
    auth_code = await generate_authorization_code(
        user_id=request.user.id,
        client_id=client_id,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method
    )
    
    # Display code for copying (not redirect!)
    return templates.TemplateResponse("cli_auth_code.html", {
        "request": request,
        "authorization_code": auth_code,
        "state": state
    })
```

#### CLI Implementation (No HTTPServer!)

```python
async def login_copy_paste_flow(self, scope: str | None = None) -> TokenInfo:
    """OAuth flow with manual code copy - no local server needed."""
    
    # Generate PKCE
    code_verifier, code_challenge = self._generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    
    # Build auth URL for CLI-specific endpoint
    auth_params = {
        "client_id": "authly-cli",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": scope or "admin:*"
    }
    
    auth_url = f"{self.base_url}/cli-auth?{urlencode(auth_params)}"
    
    print(f"\n🔐 Authentication Required")
    print(f"1. Visit: {auth_url}")
    print(f"2. Login and copy the authorization code\n")
    
    # User manually enters code - NO HTTPServer needed!
    auth_code = input("Enter authorization code: ").strip()
    
    # Exchange code for token
    token_response = await self._request("POST", "/api/v1/oauth/token",
        form_data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": code_verifier,
            "client_id": "authly-cli"
        },
        authenticated=False
    )
    
    return self._process_token_response(token_response.json())
```

### Why This Approach Works Without HTTPServer

1. **No Redirect**: Server displays code instead of redirecting
2. **Manual Transfer**: User copies code from browser to CLI
3. **Still Secure**: PKCE protects against code interception
4. **Simple**: No network configuration, ports, or servers

```python
# Server-side: Recognize OOB redirect
if redirect_uri == "urn:ietf:wg:oauth:2.0:oob":
    # Display code instead of redirecting
    return templates.TemplateResponse("oob_code.html", {
        "authorization_code": auth_code
    })

# CLI: User copies code
auth_code = input("Enter authorization code: ")
```

### Option 3: Server-Assisted CLI Authentication

Create dedicated CLI authentication endpoint:

```python
# Server provides CLI-specific auth page
@router.get("/cli/auth")
async def cli_auth_page(session_id: str):
    """Dedicated page for CLI authentication."""
    return templates.TemplateResponse("cli_auth.html", {
        "session_id": session_id
    })

# CLI polls for completion
session_id = str(uuid4())
print(f"Visit: {base_url}/cli/auth?session={session_id}")
# Poll /cli/auth/status?session={session_id}
```

## Migration Strategy

### Phase 1: Implement Device Flow (Week 1-2)
1. Add device authorization endpoints to server
2. Create device verification template
3. Implement token polling endpoint
4. Add device flow to CLI alongside existing code

### Phase 2: Transition Period (Week 3-4)
1. Make device flow default for new installations
2. Keep HTTPServer as fallback with deprecation warning
3. Update documentation with migration guide
4. Test in Docker environments

### Phase 3: Remove HTTPServer (Week 5)
1. Remove HTTPServer and OAuthCallbackHandler from `api_client.py`
2. Update `setup-cli-client.py` to remove localhost callbacks
3. Update all documentation
4. Release as major version update

### Phase 4: Enhance and Optimize (Ongoing)
1. Add QR code support for device verification
2. Implement push notifications for completion
3. Add CLI session management
4. Optimize polling intervals

## Implementation Checklist

- [ ] Server-side device flow endpoints
- [ ] Device verification HTML template
- [ ] Update OAuth models for device flow
- [ ] CLI device flow implementation
- [ ] Remove HTTPServer from CLI
- [ ] Update Docker setup scripts
- [ ] Update CLI documentation
- [ ] Integration tests for device flow
- [ ] Migration guide for users
- [ ] Update API documentation

## Benefits of This Architecture

1. **Clean Separation**: CLI is pure client, server handles all HTTP
2. **Docker Compatible**: No localhost callback issues
3. **Scalable**: No port conflicts, works with multiple instances
4. **Secure**: No local HTTP server exposure
5. **SOLID Compliant**: Each component has single responsibility
6. **User-Friendly**: Simple code entry, works everywhere
7. **Future-Proof**: Aligns with OAuth 2.1 best practices

## Testing Strategy

```python
# Test device flow without any HTTP server
async def test_device_flow_authentication():
    """Test CLI authentication via device flow."""
    client = AdminAPIClient(base_url="http://localhost:8000")
    
    # Mock user interaction
    with patch('builtins.input', return_value='TEST123'):
        token_info = await client.login_device_flow()
    
    assert token_info.access_token
    assert client.is_authenticated
    # No HTTPServer threads to clean up!
```

## Security Considerations

1. **Device Code**: High entropy, short-lived (10 minutes)
2. **User Code**: Human-friendly, rate-limited verification
3. **No Redirect**: Eliminates redirect attack vectors
4. **Polling**: Rate-limited to prevent abuse
5. **PKCE**: Still supported for enhanced security

## Conclusion

The embedded HTTPServer in the CLI is an architectural anti-pattern that violates SOLID principles and creates deployment issues. The Device Authorization Grant (RFC 8628) provides the correct solution for CLI OAuth authentication without requiring a local server.

This migration will result in a cleaner, more maintainable, and properly architected OAuth 2.1 implementation that works seamlessly in all environments including Docker containers.