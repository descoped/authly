# 🚨 CRITICAL OIDC SPEC VIOLATIONS - MUST FIX

**Generated**: 2025-08-06  
**Priority**: HIGH - These issues WILL cause certification failure

---

## 1. ❌ CRITICAL: Discovery Endpoint URL Violation

### THE ISSUE:
**Authly uses**: `/.well-known/openid_configuration` (with underscore)  
**OIDC Spec requires**: `/.well-known/openid-configuration` (with hyphen)

### WHY THIS IS CRITICAL:
- **RFC 8414 Section 3** explicitly defines the path as `/.well-known/openid-configuration`
- This is a HARD REQUIREMENT for OIDC certification
- All OIDC clients expect the hyphenated version
- This WILL cause immediate certification failure

### FIX REQUIRED:
```python
# In src/authly/oidc/discovery.py or equivalent
# WRONG:
@router.get("/.well-known/openid_configuration")  # ❌ UNDERSCORE

# CORRECT:
@router.get("/.well-known/openid-configuration")  # ✅ HYPHEN
```

### FILES TO CHECK:
- Look for: `openid_configuration` 
- Replace with: `openid-configuration`
- Likely locations:
  - `src/authly/oidc/routes.py`
  - `src/authly/oidc/discovery.py`
  - Any router configuration files

### VERIFICATION:
```bash
# After fix, this MUST work:
curl http://localhost:8000/.well-known/openid-configuration

# This should return 404:
curl http://localhost:8000/.well-known/openid_configuration
```

---

## 2. ❌ Token Endpoint Error Response Code

### THE ISSUE:
**Authly returns**: HTTP 422 (Unprocessable Entity) for validation errors  
**OAuth 2.0 spec requires**: HTTP 400 (Bad Request)

### WHY THIS MATTERS:
- RFC 6749 Section 5.2 mandates 400 status code for token endpoint errors
- Conformance tests specifically check for 400 response
- This is an easy fix but will cause test failures

### FIX REQUIRED:
```python
# In token endpoint handler
# WRONG:
raise HTTPException(status_code=422, detail=error_detail)  # ❌

# CORRECT:
raise HTTPException(status_code=400, detail={
    "error": "invalid_request",
    "error_description": error_detail
})  # ✅
```

### FILES TO CHECK:
- `src/authly/oauth/token.py`
- `src/authly/api/auth/routes.py`
- Any token endpoint handlers

---

## 3. ⚠️ Authorization Endpoint Behavior

### THE ISSUE:
**Authly behavior**: Returns 401 JSON response for unauthenticated requests  
**OIDC spec expects**: Redirect to login page or show authorization UI

### WHY THIS MATTERS:
- Browser-based flows expect HTML/redirect responses
- Conformance suite uses browser automation
- API-first is fine but needs alternate flow for conformance

### FIX OPTIONS:

**Option 1: Add Accept header detection**
```python
# In authorization endpoint
if "text/html" in request.headers.get("Accept", ""):
    # Return redirect to login page
    return RedirectResponse(url="/login?redirect_uri=...")
else:
    # API response (current behavior)
    raise HTTPException(status_code=401, ...)
```

**Option 2: Add separate UI endpoint**
```python
@router.get("/oauth/authorize")  # Browser flow
@router.get("/api/v1/oauth/authorize")  # API flow
```

---

## 4. ⚠️ Missing UserInfo in Discovery Document

### THE ISSUE:
Discovery document missing `userinfo_endpoint` field

### CURRENT DISCOVERY:
```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "...",
  "token_endpoint": "...",
  // MISSING: "userinfo_endpoint": "http://localhost:8000/oidc/userinfo"
}
```

### FIX REQUIRED:
Add to discovery response:
```python
discovery_response = {
    "issuer": settings.ISSUER,
    "authorization_endpoint": f"{base_url}/api/v1/oauth/authorize",
    "token_endpoint": f"{base_url}/api/v1/auth/token",
    "userinfo_endpoint": f"{base_url}/oidc/userinfo",  # ADD THIS
    "jwks_uri": f"{base_url}/.well-known/jwks.json",
    # ... rest of response
}
```

---

## 5. ⚠️ Missing Required Discovery Fields

### MISSING FIELDS:
- `id_token_signing_alg_values_supported` (REQUIRED)
- `subject_types_supported` (REQUIRED)
- `userinfo_endpoint` (REQUIRED for OIDC)

### FIX:
```python
discovery_response.update({
    "id_token_signing_alg_values_supported": ["RS256"],
    "subject_types_supported": ["public"],
    "userinfo_endpoint": f"{base_url}/oidc/userinfo"
})
```

---

## 📋 Action Plan

### IMMEDIATE FIXES (Do First):
1. **Fix discovery endpoint URL** (openid_configuration → openid-configuration)
2. **Fix token endpoint error codes** (422 → 400)
3. **Add missing discovery fields**

### TEST AFTER EACH FIX:
```bash
# Quick test
cd tck
python3 scripts/quick-test.py

# Full test
make test
```

### VERIFICATION CHECKLIST:
- [ ] Discovery endpoint at `/.well-known/openid-configuration` (with hyphen)
- [ ] Token endpoint returns 400 for errors
- [ ] Discovery includes `userinfo_endpoint`
- [ ] Discovery includes `id_token_signing_alg_values_supported`
- [ ] Discovery includes `subject_types_supported`
- [ ] Authorization endpoint handles browser requests

---

## 🔍 How to Find and Fix

### Search for issues:
```bash
# Find discovery endpoint definition
grep -r "openid_configuration" src/

# Find token error handling
grep -r "422" src/ | grep -i token

# Find discovery response building
grep -r "issuer.*authorization_endpoint" src/
```

### After fixing, restart and test:
```bash
# Restart Authly
docker compose restart authly

# Run quick test
cd tck
python3 scripts/quick-test.py

# If all pass, run full suite
make test
```

---

## 🎯 Expected Outcome After Fixes

With these fixes, conformance test results should improve from:
- **Current**: ~70% pass rate with critical failures
- **After fixes**: >95% pass rate, certification-ready

**Time estimate**: 1-2 hours to fix all issues

---

**IMPORTANT**: Fix these issues in order, test after each fix, and document any additional issues discovered during testing.