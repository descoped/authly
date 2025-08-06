# OIDC TCK Task List

**Created**: 2025-08-06  
**Updated**: 2025-08-06 (v002)  
**Purpose**: Track OIDC conformance testing tasks and implementation requirements  
**Status**: 🚧 In Progress

---

## 📊 Overall Progress

- [x] **Phase 1**: Infrastructure Setup ✅ COMPLETED
- [x] **Phase 2**: Basic Conformance Testing ✅ COMPLETED
- [ ] **Phase 3**: Full Conformance Suite (IN PROGRESS)
- [ ] **Phase 4**: Fix Identified Issues
- [ ] **Phase 5**: Official Certification

## 🎯 Compliance Scores (v002)
- **OIDC Core**: 87% compliant ↑
- **OAuth 2.0**: 25% compliant ↓
- **OAuth 2.1**: 100% compliant ✅

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

### Known Issues to Fix (4 Critical for Certification)

#### 🚨 Critical Endpoint Issues
- [ ] **Discovery endpoint URL violation**
  - Current: `/.well-known/openid_configuration` (underscore)
  - Required: `/.well-known/openid-configuration` (hyphen)
  - File: `/src/authly/api/oidc_router.py` line 55
  - Impact: BLOCKS CERTIFICATION
  
- [ ] **Token endpoint content-type**
  - Current: Only accepts `application/json`
  - Required: Must accept `application/x-www-form-urlencoded`
  - Impact: BLOCKS CERTIFICATION
  
- [ ] **Token endpoint error codes**
  - Current: Returns 422 for malformed requests
  - Expected: Return 400 Bad Request per OAuth spec
  - Solution: Adjust validation error response codes
  
- [ ] **Authorization endpoint authentication**
  - Current: Returns 401 Unauthorized for unauthenticated requests
  - Expected: Redirect to login page (302/303) with error parameters
  - Note: This is API-first behavior, needs adjustment for OAuth flows

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

## 🎯 Next Immediate Actions

1. **Fix Critical OIDC Spec Violations** (BLOCKS CERTIFICATION)
   ```bash
   # Fix discovery endpoint URL in /src/authly/api/oidc_router.py
   # Change: /.well-known/openid_configuration
   # To:     /.well-known/openid-configuration
   ```

2. **Fix Token Endpoint Content-Type**
   ```bash
   # Update token endpoint to accept form-encoded data
   # Currently only accepts application/json
   # Must accept: application/x-www-form-urlencoded
   ```

3. **Generate New Conformance Report After Fixes**
   ```bash
   cd tck
   python scripts/generate-conformance-report.py post_fixes
   ```

4. **Access Conformance Suite Web UI**
   ```bash
   # Open in browser
   open https://localhost:9443
   # Or use curl to test
   curl -k https://localhost:9443
   ```

3. **Create Test User via Database**
   ```sql
   INSERT INTO users (username, email, password_hash, is_active)
   VALUES ('test_user', 'test@example.com', 
           '$2b$12$...', true);
   ```

3. **Test Login Endpoint**
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"test_user","password":"test123"}'
   ```

4. **Fix Critical Issues**
   - Implement user registration endpoint or document workaround
   - Adjust token endpoint error codes (422 → 400)
   - Consider adding redirect-based authorization flow

5. **Run Updated Tests**
   ```bash
   pytest tck/tests/ -v --tb=short
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