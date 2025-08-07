# OIDC Conformance Test Results

## Date: 2025-08-06

## Summary
Successfully set up and tested the OpenID Connect conformance testing infrastructure. Several critical OIDC specification violations were identified that need immediate attention.

## Infrastructure Status ✅
- **Conformance Suite**: Built and running at https://localhost:9443
- **Authly**: Running at http://localhost:8000
- **Test Database**: PostgreSQL with test client configured
- **Docker Setup**: All services containerized and networked

## Critical Issues Found 🚨

### 1. Discovery Endpoint URL Specification Violation ❌
**Severity**: CRITICAL - Blocks OIDC certification
- **Current**: `/.well-known/openid_configuration` (underscore)
- **Required**: `/.well-known/openid-configuration` (hyphen)
- **File**: `/src/authly/api/oidc_router.py` line 55
- **Impact**: Violates OIDC Core 1.0 specification section 4

### 2. Missing OIDC Endpoints ❌
**Severity**: HIGH - Core functionality missing
- **JWKS Endpoint**: Not implemented (`/api/v1/oidc/jwks`)
- **UserInfo Endpoint**: Not implemented (`/api/v1/oidc/userinfo`)
- **Impact**: Cannot complete OIDC flows

### 3. Incomplete Discovery Metadata ⚠️
**Severity**: MEDIUM - Missing required fields
Missing fields in discovery document:
- `jwks_uri`
- `userinfo_endpoint`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`
- `scopes_supported`
- `claims_supported`

### 4. Authorization Endpoint Behavior ⚠️
**Severity**: MEDIUM - Non-standard behavior
- **Current**: Returns 401 Unauthorized
- **Expected**: Should redirect with error parameters
- **Impact**: Breaks standard OAuth/OIDC client flows

### 5. Token Endpoint Error Codes ⚠️
**Severity**: LOW - Incorrect HTTP status
- **Endpoint**: `/api/v1/auth/token` (correctly listed in discovery)
- **Current**: Returns 422 for validation errors
- **Expected**: Should return 400 Bad Request per OAuth 2.0 spec
- **Impact**: Minor spec compliance issue

## Positive Findings ✅
1. **PKCE Enforcement**: Correctly requires PKCE (OAuth 2.1 compliant)
2. **Discovery Endpoint**: Works (with underscore)
3. **Token Endpoint**: Exists and validates requests
4. **Authorization Endpoint**: Exists and validates requests

## Next Steps 🎯

### Immediate Actions (P0)
1. Fix discovery endpoint URL (underscore → hyphen)
2. Implement JWKS endpoint
3. Implement UserInfo endpoint

### Short-term Actions (P1)
1. Complete discovery metadata
2. Fix authorization endpoint redirect behavior
3. Fix token endpoint error codes

### Testing Actions
1. Run full conformance suite after fixes
2. Generate certification report
3. Address any additional findings

## Test Execution Commands

```bash
# Quick validation
cd tck
python scripts/quick-test.py

# Start conformance suite
make start

# Run automated tests (after fixes)
python scripts/run-conformance-tests.py

# View conformance suite UI
open https://localhost:9443
```

## Files to Fix

1. `/src/authly/api/oidc_router.py` - Discovery endpoint URL
2. `/src/authly/api/oauth_router.py` - Authorization redirect behavior
3. `/src/authly/api/auth_router.py` - Token endpoint error codes
4. Need to create JWKS and UserInfo endpoints

## Certification Path
Once the critical issues are resolved:
1. Run full conformance suite
2. Fix any additional issues found
3. Generate certification report
4. Submit for OIDC certification

## Resources
- [OIDC Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [Conformance Suite Docs](https://gitlab.com/openid/conformance-suite/-/wikis/home)