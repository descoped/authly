# OAuth 2.1 Compliance Restoration Instructions

## PERMANENT RULES
1. Always ask the user for confirmation before making changes and on all design decisions. Never assume implementation details or make autonomous decisions.
2. Always read `docs/testing-guide.md` - contains strict rules that MUST BE followed
3. Always read `.claude/instructions/authly-development-practices.md` - contains strict rules that MUST BE followed
4. Always follow this workflow:
   - Identify problem
   - Fix issue
   - Test
   - Ask user for confirmation to continue or get new instruction

## Critical Context
You are working on the `feature/oidc-debugger` branch where the AI assistant introduced non-compliant OAuth implementations that deviated from the strict OAuth 2.1 + PKCE compliance present in the master branch. This is a regression that MUST be fixed.

### Branch Strategy
- **Master branch**: Contains the source of truth - strict OAuth 2.1 + PKCE compliant code
- **Current branch**: `feature/oidc-debugger` - contains regressions and non-compliant code
- **Intended feature**: Add login and authorization page redirects (missing in master)

### Verification Method
When uncertain about the correct implementation:
1. Run `git diff HEAD master -- <file>` to compare with the original truth
2. If a file doesn't exist in master, it was created in this branch
3. Preserve only the login/authorization redirect functionality
4. Restore all OAuth compliance from master

## Objective
Remove all non-OAuth 2.1 compliant code introduced in `feature/oidc-debugger` while preserving only the login and authorization page redirect functionality.

## Required Actions

### 1. Identify and Remove Regressions
Compare with master branch to find and eliminate:
- Resource Owner Password Credentials (`grant_type=password`)
- Client Credentials (`grant_type=client_credentials`) 
- Implicit Grant (`response_type=token`)
- Authorization Code without PKCE
- Client secret handling
- Any custom grant types

### 2. Preserve Valid Additions
Keep ONLY these additions from the feature branch:
- Login page routing and templates
- Authorization consent page routing and templates
- Redirect logic for user authentication flow
- UI components for login/authorization

### 3. Database Cleanup
Revert any schema changes that introduced:
- `client_secret` columns
- Grant type configuration fields
- Password-based authentication tables
- Non-PKCE session storage

### 4. Endpoint Restoration

**Authorization Endpoint**
- Restore PKCE enforcement from master
- Keep redirect to login/consent pages
- Remove any non-PKCE code paths

**Token Endpoint**  
- Restore master's implementation (authorization_code with PKCE only)
- Remove any password or client_credentials handlers
- Ensure refresh token rotation is preserved

### 5. Test Suite Cleanup
Delete all NEW test files that test:
- Password grant flows
- Client credentials flows
- Implicit flows
- Client secret validation
- Basic authentication for clients

Keep tests for:
- Login page functionality
- Authorization consent flow
- User redirect logic

### 6. FastAPI Specific Restoration
- Remove any new OAuth models not present in master
- Delete client authentication dependencies added in this branch
- Restore OpenAPI documentation to OAuth 2.1 only
- Remove client_secret from any new request/response models

## Validation Checklist
- [x] All OAuth endpoints match OAuth 2.1 compliance level
- [x] No password grant code remains in current feature branch
- [x] Client_credentials code removed (was only in feature branch)
- [x] PKCE enforcement verified (S256 mandatory, plain rejected)
- [x] Login/authorization pages preserved and functional
- [x] Redirect flows work correctly
- [x] No client secrets in authorization code flow
- [x] Tests updated - 47 skipped, 385 passing, 0 failures

## Current Status (2025-01-14)
- [x] Analysis complete - oauth-compliance-findings.md created
- [x] Decisions made: Remove password grant from current branch, remove client credentials, keep introspection
- [x] Phase 1: Remove client credentials grant from current branch - COMPLETE
- [x] Phase 2: Remove password grant from current branch - COMPLETE
- [x] Phase 3: Validate and test in current branch - COMPLETE

## Final Status: ✅ COMPLETE
- **Test Results**: 385 passing, 47 skipped, 0 failures
- **OAuth 2.1 Compliance**: Fully achieved with no workarounds
- **Documentation**: See oauth21-compliance-final-status.md for full report

NOTE: All changes are made ONLY to the current feature/oidc-debugger branch. 
Master branch is NEVER modified. Git merge will be handled manually by the user.

## Priority Order
1. Use `git diff` to identify all OAuth-related changes from master
2. Revert non-compliant OAuth code to master's implementation
3. Remove non-compliant tests added in this branch
4. Verify login/authorization redirects still work
5. Clean up any database migrations that break compliance

## Git Commands for Verification
- `git diff master -- src/` - See all source changes
- `git diff master -- tests/` - See all test changes  
- `git diff master -- alembic/` - Check for schema regressions
- `git ls-files --others` - Find new files not in master

---
*The master branch is the source of truth for OAuth 2.1 compliance. Any deviation is a regression that must be fixed.*
