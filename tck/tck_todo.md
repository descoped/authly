# OIDC TCK Task List

**Created**: 2025-08-06  
**Updated**: 2025-08-07 (v003)  
**Purpose**: Track OIDC conformance testing tasks and implementation requirements  
**Status**: 🚧 Working towards 100% compliance

---

## 📊 Overall Progress

- [x] **Phase 1**: Infrastructure Setup ✅ COMPLETED
- [x] **Phase 2**: Basic Conformance Testing ✅ COMPLETED
- [x] **Phase 3**: CI/CD Integration ✅ COMPLETED
- [ ] **Phase 4**: Fix Identified Issues (IN PROGRESS - 90% → 100%)
- [ ] **Phase 5**: Official Certification

## 🎯 Compliance Scores (v003 - Latest Report)
- **Discovery**: 100% compliant (22/22) ✅
- **JWKS**: 100% compliant (7/7) ✅
- **Endpoints**: 67% compliant (4/6) ⚠️
- **Security**: 60% compliant (3/5) ⚠️
- **OVERALL**: 90% compliant (36/40) 🎯

---

## ✅ Completed Tasks

### Infrastructure Setup
- [x] Create TCK directory structure
- [x] Set up Docker Compose for conformance suite
- [x] Create test client configuration
- [x] Write initialization scripts
- [x] Create Python integration tests
- [x] Document setup procedures
- [x] Create quick-setup automation script
- [x] Implement external dependency management strategy
- [x] Build conformance suite from source with Docker
- [x] Configure networking between Authly and conformance suite

### Initial Testing
- [x] Start Authly with Docker Compose
- [x] Create OIDC test client in database
- [x] Run Python integration tests
- [x] Identify endpoint path issues (/api/v1/ prefix)
- [x] Document troubleshooting steps
- [x] Rebuild with latest codebase (fixed token endpoint URL)
- [x] Create versioned conformance reporting system
- [x] Generate automated compliance reports with scoring

---

## 🔄 In Progress Tasks

### Test Result Analysis
- [x] Run Python integration tests
- [x] Identify missing endpoints
- [ ] Fix endpoint path issues
- [ ] Document API differences

---

## 📋 Pending Tasks

### Test Profile Execution
- [ ] **Basic Profile** (Authorization Code Flow)
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results
  
- [ ] **Implicit Profile** (Legacy)
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results
  
- [ ] **Hybrid Profile**
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results
  
- [ ] **Session Management**
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results
  
- [ ] **Front-Channel Logout**
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results
  
- [ ] **Refresh Token**
  - [ ] Configure test plan
  - [ ] Run conformance tests
  - [ ] Document results

### 🔥 Current Issues to Fix (90% → 100% Compliance)

Based on the latest conformance report, we have **4 failing checks** to address:

#### Issue 1: Token Endpoint Error Response Format ❌ (2 failures)
- [ ] **Change HTTPException to return OAuth-compliant JSON**
  - Current: `HTTPException(detail="Invalid authorization code")` returns `{"detail": "..."}`
  - Required: Must return `{"error": "invalid_grant", "error_description": "Invalid authorization code"}`
  - Files to fix: `/src/authly/api/oauth_router.py` (lines 358, 708, 895)
  - OAuth error codes needed: 
    - Line 358: `invalid_request`
    - Line 708: `invalid_grant` 
    - Line 895: `unsupported_grant_type`
  
#### Issue 2: Authorization Endpoint Parameter Validation ❌ (1 failure)
- [ ] **Add comprehensive parameter validation**
  - Current: Basic validation only
  - Required: Validate all OAuth required parameters before processing
  - Files to fix: `/src/authly/api/oauth_router.py` (authorize endpoint ~line 300)
  - Must validate: `response_type`, `client_id`, `redirect_uri` match, `scope` format

#### Issue 3: Security - 'none' Algorithm Check ❌ (1 false positive in validator)
- [ ] **Fix validator logic bug**
  - Current: `Supports None Alg: False → ❌ FAIL` (incorrect logic)
  - Expected: NOT supporting 'none' should show as `✅ PASS`
  - File to fix: `/tck/scripts/conformance-validator.py`
  - This is a validator bug, Authly correctly rejects 'none' algorithm

#### Working Features ✅
- [x] PKCE is properly enforced (returns 401 without PKCE)
- [x] UserInfo endpoint requires authentication (401 for invalid tokens)
- [x] Discovery endpoints work correctly
- [x] JWKS endpoint provides signing keys

#### Missing Features
- [ ] Dynamic Client Registration
- [ ] Back-Channel Logout
- [ ] Request Object Support
- [ ] Additional Signing Algorithms (ES256, PS256)
- [ ] Encrypted ID Tokens (optional)
- [ ] Claim aggregation (optional)

### Documentation Tasks
- [ ] Create conformance test report
- [ ] Document implementation notes
- [ ] Update README with conformance status
- [ ] Create CI/CD integration guide

### Automation Tasks
- [ ] Create GitHub Actions workflow for conformance tests
- [ ] Set up automated test reporting
- [ ] Create status badges for README
- [ ] Implement nightly conformance test runs

---

## 🎯 Development Workflow (90% → 100% Compliance)

### Step 1: Understand Existing Test Coverage
```bash
# Review existing TCK tests that already check for these issues
cat tests/tck/test_conformance_fixes.py

# Check existing OAuth flow tests
grep -r "error" tests/oauth_flows/
grep -r "token.*error" tests/

# Run existing TCK tests to see current state
pytest tests/tck/ -v
```

### Step 2: Fix Token Endpoint Error Responses
```python
# In /src/authly/api/oauth_router.py
# Update error responses to return proper OAuth format:
# {"error": "invalid_grant", "error_description": "The provided authorization grant is invalid"}
# Standard error codes: invalid_request, invalid_client, invalid_grant, 
#                      unauthorized_client, unsupported_grant_type
```

### Step 3: Validate Code Quality & Run Tests
```bash
# Check code quality with ruff
ruff check src/authly/api/oauth_router.py

# Run existing TCK conformance tests
pytest tests/tck/test_conformance_fixes.py -v

# Run OAuth flow tests
pytest tests/oauth_flows/ -v

# No need to write new tests - use existing ones
```

### Step 4: Rebuild and Test Conformance
```bash
# Rebuild Docker image with fixes
docker compose build authly
docker compose up -d

# Run conformance validator
cd tck && make validate

# Check if we reached 100%
cat reports/latest/SPECIFICATION_CONFORMANCE.md
```

### Step 5: Review With Tech Lead
- Share the updated conformance report
- Review code changes together
- Ensure existing tests still pass
- Validate error handling matches OAuth 2.0 spec

### Step 6: Final Validation
```bash
# Run full test suite to ensure no regressions
pytest tests/ -v

# Clean rebuild and final conformance check
docker compose down -v
docker compose build authly --no-cache
docker compose up -d
cd tck && make validate

# Should show 40/40 checks passed (100%)
```

---

## 📝 Notes

### Test Client Details
- **Client ID**: oidc-conformance-test
- **Client Secret**: conformance-test-secret
- **Client Type**: confidential
- **Redirect URIs**: 
  - https://localhost:8443/test/a/authly/callback
  - https://localhost:8443/test/a/authly/callback/implicit
  - https://localhost:8443/test/a/authly/callback/hybrid

### Important URLs
- **Authly**: http://localhost:8000
- **Conformance Suite**: https://localhost:9443 (was 8443)
- **Discovery**: http://localhost:8000/.well-known/openid_configuration (⚠️ should be hyphen)
- **Authorization**: http://localhost:8000/api/v1/oauth/authorize
- **Token**: http://localhost:8000/api/v1/oauth/token ✅ (fixed in latest build)
- **UserInfo**: http://localhost:8000/oidc/userinfo
- **JWKS**: http://localhost:8000/.well-known/jwks.json

### Environment Details
- **Database**: PostgreSQL (Docker)
- **Cache**: Redis (Docker)
- **Server**: Authly in Docker with development configuration
- **Test Framework**: pytest with httpx

---

## 📈 Metrics

### Current Test Status

#### Python Integration Tests
- **Basic OIDC Tests**: 7/10 passing (70%)
  - ✅ Discovery endpoint validation
  - ✅ JWKS endpoint validation
  - ✅ UserInfo authentication required
  - ✅ Session management discovery
  - ✅ PKCE enforcement working
  - ❌ Authorization endpoint (returns 401, not redirect)
  - ❌ Token endpoint error codes (422 vs 400)

- **Full OAuth Flow Tests**: 2/4 passing (50%)
  - ✅ UserInfo requires valid token
  - ✅ PKCE is required
  - ❌ Complete authorization flow (missing user registration)
  - ❌ Token refresh flow (needs initial tokens)

#### Conformance Suite
- Status: ✅ Built from source and running
- JAR: `conformance-suite/target/fapi-test-suite.jar` (123MB)
- Web UI: https://localhost:8443
- Containers:
  - MongoDB: conformance-suite-mongodb-1
  - Server: conformance-suite-server-1  
  - HTTPD: conformance-suite-httpd-1

#### Endpoint Status
- **Discovery**: ✅ Working at `/.well-known/openid_configuration`
- **JWKS**: ✅ Working at `/.well-known/jwks.json`
- **Authorization**: ⚠️ Working but returns 401 (API-first behavior)
- **Token**: ⚠️ Working but returns 422 for validation errors
- **UserInfo**: ✅ Working at `/oidc/userinfo`
- **Registration**: ❌ Not found at `/api/v1/auth/register`
- **Login**: ❓ Not tested yet

---

## 🔗 References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite)
- [Certification Process](https://openid.net/certification/)
- [Authly OIDC Documentation](../docs/oidc-implementation.md)

---

*This document is actively maintained. Update after each testing session.*