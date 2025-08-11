# Test Footprint Reduction Strategy

## Current State (28,000+ lines)
- admin_portal: 5,290 lines (12 files)
- oauth_flows: 5,230 lines (12 files) 
- oidc_scenarios: 3,880 lines → 2,000 lines ✅ (deleted 3 files)
- admin_user_management: 3,411 lines (8 files)
- oidc_features: 2,383 lines (8 files)
- infrastructure: 1,853 lines (10 files)
- authentication: 1,849 lines (8 files)
- auth_user_journey: 1,167 lines (9 files)

## Target State (14,000 lines - 50% reduction)

### Critical Tests to PRESERVE (Compliance & Standards)
1. **OAuth 2.1 Compliance**
   - Authorization code flow with PKCE
   - Client authentication methods
   - Token introspection (RFC 7662)
   - Token revocation (RFC 7009)
   - Discovery endpoints (RFC 8414)

2. **OIDC Compliance** 
   - ID token generation and validation
   - UserInfo endpoint
   - JWKS endpoint
   - Discovery (.well-known/openid-configuration)
   - Core scopes (openid, profile, email, phone, address)

3. **Security Critical**
   - Password hashing
   - JWT validation
   - PKCE verification
   - Client secret validation
   - Session management

## Reduction Strategy by Domain

### 1. admin_portal (5,290 → 2,500 lines) - 53% reduction
- Remove UI-specific tests (keep API tests only)
- Consolidate CRUD operations into single test classes
- Remove duplicate validation tests

### 2. admin_user_management (3,411 → 1,500 lines) - 56% reduction  
- Merge overlapping user management tests
- Keep only critical RBAC tests
- Remove redundant validation tests

### 3. oidc_features (2,383 → 1,000 lines) - 58% reduction
- Keep only compliance-critical features
- Remove duplicate scope tests
- Consolidate claim tests

### 4. oauth_flows (5,230 → 3,000 lines) - 43% reduction
- Already reduced by 178 lines
- Further consolidate service vs HTTP tests
- Keep only one test per flow type

### 5. infrastructure (1,853 → 900 lines) - 51% reduction
- Keep health checks and critical infra
- Remove redundant database tests
- Consolidate middleware tests

### 6. authentication (1,849 → 900 lines) - 51% reduction
- Keep password flow and session tests
- Remove duplicate auth tests
- Consolidate error handling

## Principles
1. **One test per feature** - No duplicate coverage
2. **HTTP over unit tests** - Test the actual API
3. **Compliance first** - Never remove standards tests
4. **Less is more** - Easier to maintain and understand
5. **Remove all skipped tests** - If it's skipped, delete it

## Implementation Order
1. Start with largest files first (admin_portal)
2. Remove all skipped/commented tests immediately
3. Consolidate overlapping test classes
4. Keep compliance tests intact
5. Document what was removed and why