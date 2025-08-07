# 🔴 IMMEDIATE FIXES REQUIRED FOR OIDC CERTIFICATION

**CRITICAL**: These are SPEC VIOLATIONS that WILL cause certification failure

## Fix #1: Discovery Endpoint URL ❌ SPEC VIOLATION

**File**: `/src/authly/api/oidc_router.py` line 55

```python
# CURRENT (WRONG):
@oidc_router.get(
    "/.well-known/openid_configuration",  # ❌ UNDERSCORE - VIOLATES SPEC
    
# CHANGE TO:
@oidc_router.get(
    "/.well-known/openid-configuration",  # ✅ HYPHEN - SPEC COMPLIANT
```

**Also update monitoring middleware**: `/src/authly/monitoring/middleware.py` line 28
```python
# CURRENT:
r"^/\.well-known/openid_configuration$": "/.well-known/openid_configuration",

# CHANGE TO:
r"^/\.well-known/openid-configuration$": "/.well-known/openid-configuration",
```

**Verify after fix**:
```bash
# This MUST work:
curl http://localhost:8000/.well-known/openid-configuration

# This should return 404:
curl http://localhost:8000/.well-known/openid_configuration
```

---

## Fix #2: Add Missing Required Discovery Fields

**File**: Look for the discovery response builder (likely in `get_oidc_discovery` function)

Add these REQUIRED fields:
```python
discovery_response.update({
    "userinfo_endpoint": f"{base_url}/oidc/userinfo",  # REQUIRED
    "id_token_signing_alg_values_supported": ["RS256"],  # REQUIRED
    "subject_types_supported": ["public"],  # REQUIRED
})
```

---

## Fix #3: Token Endpoint Error Codes

**File**: Find token endpoint error handling

Change ALL token endpoint validation errors from 422 to 400:
```python
# Search for any of these in token endpoint:
status.HTTP_422_UNPROCESSABLE_ENTITY  # ❌
status_code=422  # ❌

# Replace with:
status.HTTP_400_BAD_REQUEST  # ✅
status_code=400  # ✅
```

OAuth spec REQUIRES 400 for token endpoint errors with proper error response:
```python
raise HTTPException(
    status_code=400,  # NOT 422!
    detail={
        "error": "invalid_request",  # or invalid_grant, etc.
        "error_description": "Details about what went wrong"
    }
)
```

---

## Test After EACH Fix

```bash
# After each fix:
docker compose restart authly

# Quick test:
cd tck
python3 scripts/quick-test.py

# Should see improvement after each fix
```

---

## Expected Results After Fixes

Before fixes:
- Discovery endpoint: ⚠️ WARNING (works but wrong URL)
- Token errors: Will fail conformance tests
- Missing fields: Will fail discovery validation

After fixes:
- Discovery endpoint: ✅ PASSED (correct URL)
- Token errors: ✅ Proper 400 responses
- Discovery complete: ✅ All required fields present

---

## Commands to Find Issues:

```bash
# Find discovery endpoint:
grep -r "openid_configuration" src/ --include="*.py"

# Find token error handling:
grep -r "422\|HTTP_422" src/ --include="*.py" | grep -i token

# Find discovery response building:
grep -r "issuer.*authorization_endpoint" src/ --include="*.py"
```

---

## After ALL Fixes Complete:

```bash
# Full conformance test:
cd tck
make test

# Expected: >95% pass rate
```

**Time to fix: 30 minutes**
**Impact: Changes certification from FAIL to PASS**