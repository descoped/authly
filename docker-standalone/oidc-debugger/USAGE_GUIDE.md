# OIDC Debugger Usage Guide with Authly

## Quick Start

1. **Reset your browser settings** (if you've used the debugger before):
   - Visit: http://localhost:8083/reset-to-authly.html
   - Click "Reset to Authly Defaults"

2. **Open the debugger**: http://localhost:8083/debugger.html

3. **Configure for Authly**:
   - Grant Type: Select "Authorization Code" or "OIDC Authorization Code Flow"
   - **IMPORTANT**: Check the "Use PKCE" checkbox (Authly requires PKCE for public clients)
   - Client ID: `client_q5IkUufL0c6CvzglVVZcIw` (or create your own)
   - Scope: `openid profile email`

4. **Test the flow**:
   - Click "Build Authorization URL"
   - Click "Authorize"
   - Login with: `admin` / your AUTHLY_ADMIN_PASSWORD
   - Approve the consent
   - You'll be redirected back with an authorization code
   - Click "Exchange Code for Tokens"
   - View your access token, ID token, and refresh token

## Why PKCE is Required

Authly enforces PKCE (Proof Key for Code Exchange) for public clients as a security best practice. This prevents authorization code interception attacks.

## Troubleshooting

### "Nothing happens when I click"
- Open Browser DevTools (F12) and check Console for errors
- Make sure JavaScript is enabled
- Try in an incognito/private window

### "invalid_request: code_challenge is required"
- Make sure "Use PKCE" is checked in the debugger
- The debugger will automatically generate code_verifier and code_challenge

### "Client not found"
- Create a client first:
```bash
docker exec authly-standalone authly admin client create \
  --name "My Test Client" \
  --type public \
  --redirect-uri "http://localhost:8083/callback" \
  --scope "openid profile email"
```

### Form shows old values
- Clear localStorage: In DevTools Console, run: `localStorage.clear(); location.reload();`
- Or visit: http://localhost:8083/reset-to-authly.html

## Testing Different Flows

### Authorization Code with PKCE (Recommended)
1. Select "Authorization Code Grant"
2. Check "Use PKCE"
3. Follow the flow

### Implicit Flow (Legacy, not recommended)
1. Select "Implicit Grant"
2. Note: Returns tokens directly in URL fragment

### Client Credentials
1. You'll need a confidential client with a secret
2. Create one with: `--type confidential` when creating client

### Refresh Token
1. Complete an authorization code flow first
2. Copy the refresh token
3. Select "Refresh Token Grant"
4. Paste the refresh token
5. Exchange for new tokens

## Endpoints Reference

All these are pre-configured when you reset to Authly defaults:

| Endpoint | URL |
|----------|-----|
| Authorization | `http://localhost:8000/api/v1/oauth/authorize` |
| Token | `http://localhost:8000/api/v1/oauth/token` |
| UserInfo | `http://localhost:8000/api/v1/userinfo` |
| Introspection | `http://localhost:8000/api/v1/oauth/introspect` |
| Discovery | `http://localhost:8000/.well-known/openid-configuration` |
| JWKS | `http://localhost:8000/.well-known/jwks.json` |