# Authly CLI Authentication - OAuth 2.1 Compliant Alternatives

## Current Issue
The authly CLI admin authentication is broken after removing password grant:
```
authly> authly admin auth login
Username: admin
Password: 
❌ Login failed: Bad request: The authorization grant type 'password' is not supported
```

## Analysis

### Current Implementation (Now Broken)
The CLI currently uses the Resource Owner Password Credentials (ROPC) grant:
- **File**: `src/authly/admin/api_client.py` line 221
- **Method**: `async def login()` uses `grant_type=password`
- **Why it worked**: Direct username/password exchange for tokens
- **Why removed**: OAuth 2.1 deprecates password grant due to security concerns

### OAuth 2.1 Compliant Alternatives

## Option 1: Device Authorization Grant (RFC 8628) - RECOMMENDED
**Best for CLI tools where browser interaction is acceptable**

### Pros:
- OAuth 2.1 compliant (explicitly allowed)
- Secure - no password handling in CLI
- User-friendly with modern auth experience
- Supports MFA/SSO if configured
- Standard flow used by GitHub CLI, Azure CLI, etc.

### Cons:
- Requires browser availability
- More complex implementation
- Slight UX change for users

### Implementation:
```python
# Workflow:
# 1. CLI requests device code from /oauth/device/code
# 2. Shows user a code and URL (e.g., http://localhost:8000/device)
# 3. User enters code in browser and authenticates
# 4. CLI polls /oauth/device/token until successful
# 5. Receives tokens when user completes auth

async def login_device_flow(self):
    # Step 1: Request device code
    response = await self._request(
        "POST", "/api/v1/oauth/device/code",
        form_data={"client_id": "authly-cli", "scope": scope}
    )
    device_data = response.json()
    
    # Step 2: Show user the code
    click.echo(f"Please visit: {device_data['verification_uri']}")
    click.echo(f"And enter code: {device_data['user_code']}")
    
    # Step 3: Poll for completion
    while True:
        response = await self._request(
            "POST", "/api/v1/oauth/device/token",
            form_data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_data['device_code'],
                "client_id": "authly-cli"
            }
        )
        if response.status_code == 200:
            return TokenInfo(...)
        await asyncio.sleep(device_data['interval'])
```

## Option 2: Authorization Code Flow with Local Callback
**Standard OAuth flow with temporary local server**

### Pros:
- OAuth 2.1 primary grant type
- Most secure option
- Works with existing OAuth infrastructure
- No new endpoints needed

### Cons:
- Requires available local port
- More complex than device flow
- Firewall/port issues possible

### Implementation:
```python
async def login_auth_code_flow(self):
    # Step 1: Start local callback server
    local_port = 8899
    redirect_uri = f"http://localhost:{local_port}/callback"
    
    # Step 2: Generate PKCE
    verifier, challenge = generate_pkce_pair()
    
    # Step 3: Open browser to auth URL
    auth_url = (
        f"{self.base_url}/oauth/authorize?"
        f"response_type=code&"
        f"client_id=authly-cli&"
        f"redirect_uri={redirect_uri}&"
        f"code_challenge={challenge}&"
        f"code_challenge_method=S256&"
        f"state={state}"
    )
    webbrowser.open(auth_url)
    
    # Step 4: Wait for callback with code
    code = await wait_for_callback(local_port)
    
    # Step 5: Exchange code for tokens
    response = await self._request(
        "POST", "/api/v1/oauth/token",
        form_data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_id": "authly-cli"
        }
    )
```

## Option 3: Client Credentials with Service Account
**For admin-to-admin operations only**

### Pros:
- Simple implementation
- No user interaction needed
- OAuth 2.1 compliant for M2M

### Cons:
- Not user-specific
- Requires secure credential storage
- Only for service accounts
- We removed client credentials grant

### Note:
This option is NOT viable since we removed client credentials grant for OAuth 2.1 compliance.

## Option 4: Personal Access Tokens (PAT)
**Non-OAuth alternative similar to GitHub PATs**

### Pros:
- Simple to implement
- No OAuth complexity
- Direct token usage
- Common pattern (GitHub, GitLab)

### Cons:
- Not OAuth-based
- Requires new token management system
- Manual token generation/rotation

### Implementation:
```python
# User generates PAT in web UI
# CLI accepts PAT directly
async def login_with_pat(self, token: str):
    # Validate token
    response = await self._request(
        "GET", "/api/v1/admin/validate",
        headers={"Authorization": f"Bearer {token}"}
    )
    if response.status_code == 200:
        self._token_info = TokenInfo(
            access_token=token,
            expires_at=...,
            token_type="Bearer"
        )
```

## Option 5: Admin-Specific Basic Auth Endpoint
**Special endpoint for admin CLI only**

### Pros:
- Maintains current UX
- Simple implementation
- Admin-only, not public OAuth

### Cons:
- Not OAuth 2.1
- Potential security concern
- Special case in codebase

### Implementation:
```python
# New admin-only endpoint (not OAuth)
@router.post("/api/v1/admin/auth/login")
async def admin_login(
    username: str = Form(),
    password: str = Form()
):
    # Verify admin credentials
    # Return admin session token (not OAuth)
    return {"token": admin_token, "expires_in": 3600}
```

## Recommendation

### Short-term (Quick Fix)
Implement **Option 5: Admin-Specific Basic Auth** to restore functionality immediately:
- Create `/api/v1/admin/auth/login` endpoint
- Returns non-OAuth admin tokens
- Minimal code changes
- Preserves current UX

### Long-term (Proper Solution)
Implement **Option 1: Device Authorization Grant**:
- Industry standard for CLI tools
- OAuth 2.1 compliant
- Better security
- Modern auth experience

## Implementation Priority

1. **Immediate**: Discuss with user which approach to take
2. **Phase 1**: Implement chosen quick fix to restore CLI functionality
3. **Phase 2**: Design and implement long-term OAuth 2.1 compliant solution
4. **Phase 3**: Migration path for existing users

## Examples from Other Tools

### GitHub CLI (gh)
- Uses Device Authorization Grant
- Command: `gh auth login`
- Shows code, opens browser
- Polls for completion

### Azure CLI (az)
- Uses Device Authorization Grant as default
- Falls back to browser-based auth code flow
- Command: `az login`

### Google Cloud CLI (gcloud)
- Uses Authorization Code Flow with local callback
- Opens browser automatically
- Command: `gcloud auth login`

## Decision Required

The user needs to decide:
1. **Quick fix approach**: Admin-specific endpoint vs temporary restore of password grant for admin only
2. **Long-term approach**: Device flow vs auth code flow
3. **Timeline**: When to implement each phase

## Security Considerations

- Password grant was removed for good security reasons
- Any alternative should maintain or improve security posture
- Admin authentication is critical infrastructure
- Consider rate limiting and audit logging for admin endpoints

---

**Status**: Awaiting user decision on approach
**Impact**: CLI admin authentication completely broken until resolved
**Priority**: HIGH - Core functionality affected