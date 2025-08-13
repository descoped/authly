# Test Plan Execution Report

## OIDC Basic Certification
**Executed**: 2025-08-13T19:47:29.562583
**Server**: http://host.docker.internal:8000

## Summary
- **Total Tests**: 17
- **Passed**: 8 ✅
- **Failed**: 2 ❌
- **Skipped**: 7 ⏭️
- **Pass Rate**: 47.1%

## Test Results

| Test Module | Status | Required | Description |
|-------------|--------|----------|-------------|
| oidcc-server | ✅ PASS | Yes | Server configuration validation |
| oidcc-discovery-issuer-not-matching-config | ❌ FAIL | Yes | Discovery endpoint issuer validation |
| oidcc-ensure-request-without-nonce-succeeds-for-code-flow | ⏭️ NOT_IMPLEMENTED | Yes |  |
| oidcc-ensure-registered-redirect-uri | ✅ PASS | Yes | Redirect URI exact match validation |
| oidcc-userinfo-get | ✅ PASS | Yes | UserInfo endpoint GET method |
| oidcc-userinfo-post-header | ❌ FAIL | Yes | UserInfo endpoint POST with Bearer token |
| oidcc-userinfo-post-body | ⏭️ NOT_IMPLEMENTED | No |  |
| oidcc-id-token-kid-absent-single-jwks | ⏭️ NOT_IMPLEMENTED | No |  |
| oidcc-id-token-aud-single-value | ✅ PASS | Yes | ID token aud as single value |
| oidcc-id-token-iat | ✅ PASS | Yes | ID token iat claim validation |
| oidcc-id-token-sub | ✅ PASS | Yes | ID token sub claim validation |
| oidcc-scope-profile | ✅ PASS | Yes | Profile scope claims in UserInfo |
| oidcc-scope-email | ✅ PASS | Yes | Email scope claims in UserInfo |
| oidcc-scope-address | ⏭️ NOT_IMPLEMENTED | No |  |
| oidcc-scope-phone | ⏭️ NOT_IMPLEMENTED | No |  |
| oidcc-nonce-invalid | ⏭️ NOT_IMPLEMENTED | Yes |  |
| oidcc-claims-essential | ⏭️ NOT_IMPLEMENTED | No |  |

## ⚠️ Required Tests Failed
- oidcc-discovery-issuer-not-matching-config
- oidcc-ensure-request-without-nonce-succeeds-for-code-flow
- oidcc-userinfo-post-header
- oidcc-nonce-invalid

## Certification Readiness
❌ **NOT READY** - Only 67% of required tests pass
