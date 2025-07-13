# Docker Pipeline RFC 8414 Compliance Guide

## Problem Statement

The Docker pipeline is failing because the OAuth discovery endpoint is not RFC 8414 compliant. Current tests expect `.well-known` endpoints at root level, but the OAuth router is mounted with API prefix.

## Current State Analysis

### Working Endpoints (Root Level - RFC Compliant)
- `/.well-known/openid_configuration` ✅ (OIDC router - correctly mounted without prefix)
- `/.well-known/jwks.json` ✅ (OIDC router - correctly mounted without prefix)

### Broken Endpoint (API Prefixed - RFC Non-Compliant)
- `/.well-known/oauth-authorization-server` ❌ (Currently at `/api/v1/oauth/.well-known/oauth-authorization-server`)

## RFC 8414 Requirements

**Critical RFC 8414 Requirement:**
> The `.well-known` endpoints MUST be at the root level of the domain or issuer.
> API prefixes like `/api/v1/` MUST NOT be applied to `.well-known` endpoints.

**Standard Paths:**
- `/.well-known/oauth-authorization-server` (OAuth 2.1 server metadata)
- `/.well-known/openid_configuration` (OIDC discovery)
- `/.well-known/jwks.json` (JSON Web Key Set)

## Current Code Structure

### App Mounting Configuration (`src/authly/app.py`)
```python
# Include versioned API routers (WITH prefix)
app.include_router(oauth_router, prefix=api_prefix)  # ❌ This causes the issue

# Include OIDC router (no prefix - uses well-known paths)
app.include_router(oidc_router)  # ✅ This is correct
```

### OAuth Router (`src/authly/api/oauth_router.py`)
```python
# OAuth router with prefix="/oauth"
oauth_router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])

@oauth_router.get("/.well-known/oauth-authorization-server")  # This becomes /api/v1/oauth/.well-known/...
```

## Solution Strategy

### Option 1: Split OAuth Router (Recommended)
1. **Keep OAuth endpoints** (authorize, etc.) under API prefix: `/api/v1/oauth/authorize`
2. **Move discovery endpoint** to root level: `/.well-known/oauth-authorization-server`

**Implementation:**
- Create separate router for OAuth discovery endpoints (like OIDC router)
- Mount discovery router at root level (no prefix)
- Keep main OAuth router with API prefix for business endpoints

### Option 2: Mount OAuth Router at Root (Not Recommended)
- Would break API versioning for OAuth business endpoints
- Inconsistent with other API endpoints

## Implementation Plan

### Step 1: Create OAuth Discovery Router
```python
# File: src/authly/api/oauth_discovery_router.py
oauth_discovery_router = APIRouter(tags=["OAuth 2.1 Discovery"])

@oauth_discovery_router.get("/.well-known/oauth-authorization-server")
async def oauth_discovery(request: Request):
    # Same implementation as current oauth_discovery function
```

### Step 2: Update App Configuration
```python
# File: src/authly/app.py
from authly.api.oauth_discovery_router import oauth_discovery_router

# Include OAuth discovery router (no prefix - RFC 8414 compliance)
app.include_router(oauth_discovery_router)

# Include OAuth business endpoints (with prefix)
app.include_router(oauth_router, prefix=api_prefix)
```

### Step 3: Remove Discovery from OAuth Router
```python
# File: src/authly/api/oauth_router.py
# Remove @oauth_router.get("/.well-known/oauth-authorization-server") endpoint
# Keep only business endpoints: /authorize, etc.
```

### Step 4: Update Tests
- Verify existing tests expect `/api/v1/oauth/.well-known/oauth-authorization-server`
- Update any tests that should use root-level endpoint
- Ensure both endpoints work during transition

## Pipeline Configuration

### Environment Variables for CI
Current Docker workflow needs admin password configuration:
```bash
AUTHLY_BOOTSTRAP_DEV_MODE=true
AUTHLY_ADMIN_PASSWORD=ci_admin_test_password  # Added for CI
```

### Docker Compose Environment
The pipeline environment should match local development:
```yaml
AUTHLY_API_VERSION_PREFIX: "/api/v1"  # This is correct for business endpoints
# .well-known endpoints will be at root regardless of this setting
```

## Verification Commands

### Local Testing
```bash
# Start services
docker compose up -d

# Test all endpoints
curl -f http://localhost:8000/health
curl -f http://localhost:8000/.well-known/oauth-authorization-server
curl -f http://localhost:8000/.well-known/openid_configuration
curl -f http://localhost:8000/.well-known/jwks.json

# Test business endpoints still work
curl -f "http://localhost:8000/api/v1/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost"
```

### Pipeline Testing
The Docker workflow currently tests:
- `/.well-known/oauth-authorization-server` (should work after fix)
- `/.well-known/openid_configuration` (already working)
- `/.well-known/jwks.json` (already working)

## Expected Results

After implementation:
1. **Pipeline passes** ✅ - All `.well-known` endpoints accessible at root
2. **RFC 8414 compliance** ✅ - Discovery endpoints at correct paths
3. **API versioning preserved** ✅ - Business endpoints still under `/api/v1`
4. **Backward compatibility** ✅ - Existing OAuth flows continue working

## Admin Password Resolution

The admin password issue is resolved by:
1. Setting `AUTHLY_BOOTSTRAP_DEV_MODE=true`
2. Providing `AUTHLY_ADMIN_PASSWORD` environment variable
3. This disables password change requirement in CI environment

## Next Steps

1. Implement OAuth discovery router separation
2. Test locally to verify all endpoints work
3. Run Docker workflow to confirm pipeline passes
4. Update documentation to reflect RFC 8414 compliance

## Notes

- This maintains backward compatibility while achieving RFC compliance
- The OIDC router already follows this pattern correctly
- OAuth business endpoints remain properly versioned under API prefix
- Only discovery metadata endpoints move to root level as required by RFC