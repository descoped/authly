# OIDC Certification vs Integration Testing: Understanding the Boundaries

## Executive Summary
This document clarifies the distinction between OIDC Self-Certification requirements, the official OIDC Conformance Suite, and Authly's existing integration tests.

## 1. What is OIDC Self-Certification?

### Official OIDC Conformance Suite
The **OpenID Foundation Conformance Suite** is the official test harness for OIDC certification:
- **URL**: https://www.certification.openid.net/
- **Purpose**: Validate that an implementation correctly implements OIDC specifications
- **Result**: Official certification badge and listing on OpenID Foundation website
- **Cost**: Free for OpenID Foundation members, fee for non-members

### What It Tests
The official suite tests:
1. **Protocol Compliance**: Exact adherence to OIDC Core 1.0 specification
2. **Security Requirements**: Proper token validation, signature verification
3. **Interoperability**: Works with certified OIDC clients
4. **Error Handling**: Correct error responses per specification

### What It Does NOT Test
- Business logic
- Performance
- User experience
- Custom extensions
- Admin functionality

## 2. Current Test Architecture in Authly

### A. Integration Tests (`/scripts/integration-tests/`)
**Purpose**: End-to-end functional testing of Authly features

| Test File | Purpose | Scope |
|-----------|---------|-------|
| `oauth-flow.sh` | Complete OAuth 2.1 flow with PKCE | Business flow validation |
| `admin-auth.sh` | Admin authentication | Custom feature |
| `user-management.sh` | User CRUD operations | Custom feature |
| `client-management.sh` | OAuth client management | Custom feature |
| `scope-management.sh` | Scope administration | Custom feature |

**These tests validate that Authly WORKS as intended for users.**

### B. Unit Tests (`/tests/`)
**Purpose**: Component-level testing
- Model validation
- Service logic
- API endpoint responses
- Error handling

**These tests validate that code FUNCTIONS correctly.**

### C. TCK Conformance Tests (`/tck/`)
**Purpose**: Specification compliance validation
- OIDC Core 1.0 compliance
- OAuth 2.0/2.1 compliance
- Interoperability readiness

**These tests validate that Authly CONFORMS to standards.**

## 3. The Boundaries - What Goes Where?

### TCK/Conformance Tests Should Cover:
✅ **Specification Requirements**
- Discovery document format and fields
- Token endpoint behavior per RFC 6749
- JWKS format and cryptographic requirements
- ID token structure and claims
- Authorization endpoint responses
- Error response formats

✅ **Interoperability Concerns**
- Standard OIDC flows work with any certified client
- Proper CORS headers
- Content-Type handling
- Standard parameter names

❌ **Should NOT Cover:**
- Admin API functionality
- Custom user management
- Business-specific workflows
- Performance testing
- Database operations

### Integration Tests Should Cover:
✅ **Business Workflows**
- Complete user journeys
- Admin operations
- Multi-step processes
- Custom features

✅ **System Integration**
- Database interactions
- External service calls
- Docker deployment
- Environment configurations

❌ **Should NOT Cover:**
- OIDC specification minutiae
- Standard compliance
- Interoperability with external OIDC clients

## 4. Our Current Conformance Status

### What We've Tested (Basic Discovery):
```
✅ Discovery endpoint URL format
✅ Token endpoint content-type
✅ Error codes (400 vs 422)
✅ Authorization redirect behavior
✅ PKCE enforcement
✅ JWKS availability
```

### What OIDC Certification Would Additionally Require:

#### Essential Tests (MUST have for certification):
1. **ID Token Validation**
   - Signature verification (RS256)
   - Required claims (iss, sub, aud, exp, iat)
   - Audience validation
   - Expiration checking

2. **Authorization Code Flow**
   - State parameter validation
   - Nonce handling
   - Code exchange
   - Token response format

3. **UserInfo Endpoint**
   - Bearer token authentication
   - Scope-based claims
   - Content-Type negotiation

4. **Discovery Document**
   - All required fields present
   - Values match actual endpoints
   - Supported features accurately listed

#### Optional Tests (NICE to have):
- Refresh token rotation
- Token introspection
- Session management
- Dynamic client registration
- Request objects
- Hybrid flow

## 5. Recommended Approach

### Phase 1: Complete Current TCK Suite (What we're doing now)
Create `/tck/scripts/conformance-validator.py` that tests:
- [ ] ID token structure and signature
- [ ] Complete authorization code flow
- [ ] UserInfo with different scopes
- [ ] Token refresh flow
- [ ] Error response formats

**This is NOT duplicating integration tests because:**
- Focus is on SPECIFICATION compliance, not functionality
- Tests are client-agnostic (any OIDC client should work)
- Validates exact response formats, not business outcomes

### Phase 2: Run Official Conformance Suite (Future)
When ready for certification:
1. Deploy Authly to a public URL
2. Register at https://www.certification.openid.net/
3. Configure test plan for "Basic OP" profile
4. Run automated tests
5. Fix any failures
6. Submit for certification

### Phase 3: Maintain Compliance
- Run TCK tests in CI/CD
- Update when specifications change
- Re-certify annually

## 6. Key Differences Summary

| Aspect | Integration Tests | TCK/Conformance | Official Certification |
|--------|------------------|-----------------|------------------------|
| **Purpose** | Feature validation | Spec compliance | Official validation |
| **Scope** | Business flows | OIDC/OAuth standards | OIDC Core 1.0 |
| **Maintenance** | Per feature | Per specification | Annual |
| **Audience** | Developers | Standards compliance | Public proof |
| **Location** | `/scripts/integration-tests/` | `/tck/` | External service |

## 7. Why This Separation Matters

1. **Clear Responsibilities**: Each test suite has a specific job
2. **No Duplication**: Tests don't overlap unnecessarily  
3. **Easier Debugging**: Know where to look when something fails
4. **Certification Ready**: TCK tests prepare for official certification
5. **Business Flexibility**: Can change features without breaking standards

## 8. Next Steps

### Immediate (TCK Enhancement):
1. Create `conformance-validator.py` for deep OIDC validation
2. Test ID token generation and validation
3. Validate complete auth code flow
4. Test UserInfo endpoint compliance

### Do NOT:
- Duplicate existing integration tests
- Test admin APIs in conformance suite
- Mix business logic with spec compliance
- Test performance in conformance suite

### Future:
- Prepare for official OIDC certification
- Consider OAuth 2.1 certification when available
- Maintain compliance through automated testing

---

## Summary

**Your existing integration tests** = "Does Authly work for our users?"
**TCK conformance tests** = "Does Authly follow OIDC/OAuth specifications?"
**Official certification** = "Can we prove Authly is OIDC compliant?"

Each serves a different purpose. No duplication needed.