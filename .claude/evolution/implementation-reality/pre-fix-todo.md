# Pre-Fix Todo List - Current State Before Codebase Cleanup

**Created**: 2025-08-10  
**Purpose**: Document all pending tasks before starting the critical codebase fix  
**Status**: Snapshot of technical debt and required fixes

---

## Critical Bugs (URGENT - Production Issues)

1. **[pending]** URGENT: Fix duplicate /introspect endpoint in oauth_router.py (lines 1013 & 1228)

## Blocking Issues (42 Tests Cannot Run)

2. **[pending]** Implement Authorization Endpoint GET/POST /api/v1/oauth/authorize (blocking 42 tests) - Tests: test_oauth_authorization.py

## Test Infrastructure Fixes

3. **[pending]** Create committed fixtures for test isolation (committed_user, committed_oauth_client)
4. **[pending]** Delete redundant test files: test_client_credentials_validation.py, test_id_token_generation.py, test_id_token_validation.py
5. **[pending]** Restructure test directories: unit/, integration/, e2e/, fixtures/
6. **[pending]** Merge 4 authorization test files into 1 comprehensive test
7. **[pending]** Consolidate 8 OIDC scenario files into 3 focused files

## OAuth 2.1 Compliance

8. **[pending]** Remove deprecated /users/me endpoint (line 71 users_router.py) and update tests to use /oidc/userinfo
9. **[pending]** Remove IMPLICIT flow support in oidc/validation.py (line 163) and oauth/models.py
10. **[pending]** Remove HYBRID flow support in oidc/validation.py (line 169) and oauth/models.py
11. **[pending]** Update compliance tester to reject implicit/hybrid flows

## Architecture Consolidation

12. **[pending]** Merge OAuth and OIDC discovery services into UnifiedDiscoveryService
13. **[pending]** Create BaseRepository and BaseService classes for consistent patterns
14. **[pending]** Consolidate authentication logic into UnifiedAuthenticationService

## Missing Features

15. **[pending]** Implement Refresh Token Rotation - NO CODE EXISTS - Test: test_refresh_token_rotation
16. **[pending]** Add authenticate_client() to ClientRepository - NOT EXISTS
17. **[pending]** Add X-RateLimit-* headers to rate limiter middleware
18. **[pending]** Fix auth code race condition with SELECT FOR UPDATE in AuthorizationCodeRepository
19. **[pending]** Add performance metrics to all OAuth/OIDC endpoints

---

## Summary Statistics

- **Total Tasks**: 19
- **Critical/Urgent**: 1 (production bug)
- **Blocking**: 1 (42 tests cannot run)
- **Test Fixes**: 5
- **OAuth 2.1 Compliance**: 4
- **Architecture**: 3
- **Missing Features**: 5

## Priority Order

### Phase 0 - Emergency (Day 1)
- Task #1: Fix duplicate endpoint bug
- Task #2: Implement authorization endpoint

### Phase 1 - Stop the Bleeding (Week 1)
- Task #3: Create committed fixtures
- Task #4: Delete redundant test files
- Task #9-11: Remove implicit/hybrid flows

### Phase 2 - Architecture (Week 2)
- Task #12-14: Consolidate services and patterns

### Phase 3 - Test Cleanup (Week 3)
- Task #5-7: Restructure and merge tests

### Phase 4 - Features (Week 4)
- Task #15-19: Add missing features

---

*This todo list represents the technical debt accumulated in the Authly project. Without addressing these items, especially the critical and blocking issues, the project cannot achieve OAuth 2.1 compliance or maintain a stable codebase.*