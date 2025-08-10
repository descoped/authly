# Authly High-Security Scope

## OAuth 2.1 + PKCE ONLY

Authly implements **ONLY** the OAuth 2.1 Authorization Code Flow with PKCE for maximum security.

### ✅ Supported (Required)

- **OAuth 2.1 Authorization Code Flow** - The only supported flow
- **PKCE with S256** - Mandatory for ALL requests
- **State Parameter** - Required for CSRF protection
- **Exact Redirect URI Match** - No wildcards or partial matches
- **OpenID Connect 1.0** - With authorization code flow only
- **Refresh Token Rotation** - Single-use refresh tokens

### ❌ NOT Supported (By Design)

These are intentionally NOT supported for security reasons:

- **Implicit Flow** (`response_type=token`) - Deprecated and insecure
- **Hybrid Flow** (`response_type=code token`) - Not needed
- **Plain PKCE Method** - Only S256 is secure
- **Resource Owner Password** - Anti-pattern for browser apps
- **Client Credentials** - Not for user authentication
- **Optional State** - State is mandatory for CSRF protection
- **Wildcard Redirects** - Security vulnerability

## Compliance Test Results

The compliance tester validates that Authly:

1. **Blocks all insecure flows** (implicit, hybrid, etc.)
2. **Enforces PKCE S256** on every request
3. **Requires state parameter** for CSRF protection
4. **Validates redirect URIs** exactly
5. **Supports ONLY** high-security patterns

## Current Compliance Status

| Feature | Status | Notes |
|---------|--------|-------|
| PKCE Required | ✅ | Working correctly |
| S256 Only | ❌ | Plain method needs to be blocked |
| No Implicit | ✅ | Correctly rejected |
| No Hybrid | ✅ | Correctly rejected |
| State Required | ❌ | Needs to be mandatory |
| Strict Redirect | ❌ | Needs exact matching |

## Security Philosophy

Authly's approach is:

- **No compromises** on security
- **No legacy support** for deprecated flows
- **Mandatory security** features (not optional)
- **Fail securely** - reject anything uncertain
- **High-security by default** - no insecure options

## Test Interpretation

When running the compliance tester:

- **Failed tests = Real security issues** that need fixing
- **Low pass rate = Security gaps** identified correctly
- **100% pass = Full OAuth 2.1 + PKCE compliance**

The tester is working correctly when it identifies these gaps!