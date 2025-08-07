# OIDC Conformance Status Report v002
**Generated**: 2025-08-06 18:13:20  
**Version**: v002  
**Tag**: post_rebuild  

## Executive Summary
Automated conformance test run for OIDC/OAuth compliance validation.

## Compliance Scores
- **OIDC Core**: 87% compliant
- **OAuth 2.0**: 25% compliant  
- **OAuth 2.1**: 100% compliant

## Test Results

### Discovery Endpoint
- ✅ Works with underscore: True
- ❌ Works with hyphen (SPEC): False

### Token Endpoint
- Endpoint URL: `/api/v1/oauth/token`
- ❌ Accepts form-encoded: False
- ✅ Accepts JSON: True
- Error code: 422 ❌ (should be 400)

### Other Endpoints
- ✅ JWKS available: True
- ✅ UserInfo available: True
- ❌ Authorization redirects: False

### Security Features
- ✅ PKCE required: True

## Critical Issues for Certification
1. **Discovery endpoint uses underscore instead of hyphen**
2. **Token endpoint doesn't accept form-encoded data**
3. **Token endpoint returns 422 instead of 400**
4. **Authorization endpoint returns 401 instead of redirecting**

## Discovery Metadata Fields
Total fields: 25

Key fields present:
- issuer: ✅
- authorization_endpoint: ✅
- token_endpoint: ✅
- jwks_uri: ✅
- userinfo_endpoint: ✅
- scopes_supported: ✅
- response_types_supported: ✅

## Recommendations
1. **URGENT**: Fix discovery endpoint URL from underscore to hyphen
2. **URGENT**: Update token endpoint to accept application/x-www-form-urlencoded
3. **HIGH**: Fix token endpoint to return 400 for errors
4. **HIGH**: Fix authorization endpoint to redirect with errors

## Test Command Used
```bash
cd /Users/oranheim/PycharmProjects/descoped/authly/tck
python scripts/generate-conformance-report.py
```

## Raw Test Results
```json
{
  "discovery_underscore": true,
  "discovery_hyphen": false,
  "token_endpoint": "/api/v1/oauth/token",
  "token_form_encoded": false,
  "token_json": true,
  "token_error_code": 422,
  "jwks_available": true,
  "userinfo_available": true,
  "authorization_redirect": false,
  "pkce_required": true,
  "discovery_fields": {
    "issuer": "http://localhost:8000",
    "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
    "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
    "revocation_endpoint": "http://localhost:8000/api/v1/oauth/revoke",
    "response_types_supported": [
      "code"
    ],
    "grant_types_supported": [
      "authorization_code",
      "refresh_token"
    ],
    "code_challenge_methods_supported": [
      "S256"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_post",
      "none"
    ],
    "scopes_supported": [
      "address",
      "admin",
      "admin:clients:read",
      "admin:clients:write",
      "admin:scopes:read",
      "admin:scopes:write",
      "admin:system:read",
      "admin:system:write",
      "admin:users:read",
      "admin:users:write",
      "email",
      "openid",
      "phone",
      "profile",
      "read",
      "write",
      "openid",
      "profile",
      "email",
      "address",
      "phone"
    ],
    "userinfo_endpoint": "http://localhost:8000/oidc/userinfo",
    "end_session_endpoint": "http://localhost:8000/api/v1/oidc/logout",
    "check_session_iframe": "http://localhost:8000/api/v1/oidc/session/iframe",
    "frontchannel_logout_supported": true,
    "frontchannel_logout_session_supported": true,
    "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
    "id_token_signing_alg_values_supported": [
      "RS256",
      "HS256"
    ],
    "subject_types_supported": [
      "public"
    ],
    "claims_supported": [
      "address",
      "aud",
      "birthdate",
      "email",
      "email_verified",
      "exp",
      "family_name",
      "gender",
      "given_name",
      "iat",
      "iss",
      "locale",
      "middle_name",
      "name",
      "nickname",
      "phone_number",
      "phone_number_verified",
      "picture",
      "preferred_username",
      "profile",
      "sub",
      "updated_at",
      "website",
      "zoneinfo"
    ],
    "claims_parameter_supported": false,
    "request_parameter_supported": false,
    "request_uri_parameter_supported": false,
    "require_request_uri_registration": false,
    "ui_locales_supported": [
      "en"
    ],
    "require_pkce": true,
    "response_modes_supported": [
      "query"
    ]
  }
}
```

---
*Report v002 generated automatically by conformance test suite*
