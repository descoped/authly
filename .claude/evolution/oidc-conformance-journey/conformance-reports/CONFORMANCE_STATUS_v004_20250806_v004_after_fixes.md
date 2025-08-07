# OIDC Conformance Status Report v004
**Generated**: 2025-08-06 18:48:02  
**Version**: v004  
**Tag**: v004_after_fixes  

## Executive Summary
Automated conformance test run for OIDC/OAuth compliance validation.

## Compliance Scores
- **OIDC Core**: 37% compliant
- **OAuth 2.0**: 50% compliant  
- **OAuth 2.1**: 0% compliant

## Test Results

### Discovery Endpoint
- ✅ Works with underscore: False
- ✅ Works with hyphen (SPEC): True

### Token Endpoint
- Endpoint URL: `None`
- ✅ Accepts form-encoded: True
- ❌ Accepts JSON: False
- Error code: 400 ✅

### Other Endpoints
- ✅ JWKS available: True
- ✅ UserInfo available: True
- ❌ Authorization redirects: False

### Security Features
- ❌ PKCE required: False

## Critical Issues for Certification
1. **Authorization endpoint returns 401 instead of redirecting**

## Discovery Metadata Fields
Total fields: 0

Key fields present:
- issuer: ❌
- authorization_endpoint: ❌
- token_endpoint: ❌
- jwks_uri: ❌
- userinfo_endpoint: ❌
- scopes_supported: ❌
- response_types_supported: ❌

## Recommendations
4. **HIGH**: Fix authorization endpoint to redirect with errors

## Test Command Used
```bash
cd /Users/oranheim/PycharmProjects/descoped/authly/tck
python scripts/generate-conformance-report.py
```

## Raw Test Results
```json
{
  "discovery_underscore": false,
  "discovery_hyphen": true,
  "token_endpoint": null,
  "token_form_encoded": true,
  "token_json": false,
  "token_error_code": 400,
  "jwks_available": true,
  "userinfo_available": true,
  "authorization_redirect": false,
  "pkce_required": false,
  "discovery_fields": {}
}
```

---
*Report v004 generated automatically by conformance test suite*
