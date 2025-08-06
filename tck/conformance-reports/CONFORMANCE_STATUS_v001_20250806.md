# OIDC Conformance Status Report
**Date**: 2025-08-06  
**Authly Build**: Latest from source

## Executive Summary
After rebuilding with the latest codebase, the token endpoint URL issue has been fixed. However, several critical OIDC/OAuth specification violations remain that will block certification.

## Test Infrastructure ✅
- Conformance Suite: Running at https://localhost:9443
- Authly: Running at http://localhost:8000 (latest build)
- All Docker services operational

## Critical Issues for Certification 🚨

### 1. Discovery Endpoint URL ❌ BLOCKS CERTIFICATION
**Specification**: OIDC Core 1.0, Section 4  
**Current**: `/.well-known/openid_configuration` (underscore)  
**Required**: `/.well-known/openid-configuration` (hyphen)  
**File to Fix**: `/src/authly/api/oidc_router.py` line 55  
**Impact**: Automatic discovery will fail for all standard OIDC clients

### 2. Token Endpoint Content-Type ❌ BLOCKS CERTIFICATION  
**Specification**: OAuth 2.0 RFC 6749, Section 4.1.3  
**Current**: Only accepts `application/json`  
**Required**: Must accept `application/x-www-form-urlencoded`  
**Test Result**:
```
Form data: Returns 422 "Input should be a valid dictionary"
JSON: Returns 400 (works but non-standard)
```
**Impact**: Standard OAuth clients cannot exchange authorization codes

### 3. Token Endpoint Error Status ⚠️ SPEC VIOLATION
**Specification**: OAuth 2.0 RFC 6749, Section 5.2  
**Current**: Returns HTTP 422 for invalid requests  
**Required**: Must return HTTP 400 Bad Request  
**Impact**: Non-compliant error handling

### 4. Authorization Endpoint Behavior ⚠️ SPEC VIOLATION
**Specification**: OAuth 2.0 RFC 6749, Section 4.1.2.1  
**Current**: Returns HTTP 401 Unauthorized  
**Required**: Must redirect to client with error parameters  
**Impact**: Breaks standard OAuth flow error handling

## Fixed Issues ✅
1. **Token Endpoint URL**: Now correctly at `/api/v1/oauth/token` in discovery

## Positive Findings ✅
- JWKS endpoint working at `/.well-known/jwks.json`
- UserInfo endpoint working at `/oidc/userinfo`
- PKCE enforcement (OAuth 2.1 compliant)
- Discovery document has most required fields

## Action Items (Priority Order)

### P0 - Certification Blockers
1. **Fix discovery URL**: Change `openid_configuration` to `openid-configuration`
2. **Fix token endpoint**: Accept `application/x-www-form-urlencoded` content type
3. **Fix token errors**: Return 400 instead of 422

### P1 - Spec Compliance  
1. **Fix authorization errors**: Redirect instead of returning 401
2. **Verify all discovery fields**: Ensure complete metadata

## Test Commands
```bash
# Quick validation
cd tck
python scripts/simple-conformance-test.py

# Full discovery check
curl -s http://localhost:8000/.well-known/openid_configuration | jq

# Token endpoint test (should work but doesn't)
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=test"

# Token endpoint test (works but shouldn't be required)
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"authorization_code","code":"test"}'
```

## Conformance Suite Access
- URL: https://localhost:9443
- Ready for full test runs once blockers are fixed

## Certification Path
Cannot proceed with OIDC certification until P0 issues are resolved.