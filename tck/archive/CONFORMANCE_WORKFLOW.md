# OIDC/OAuth Conformance Testing Workflow

**Version**: 1.0  
**Date**: 2025-08-06  
**Purpose**: Document the standardized workflow for OIDC/OAuth conformance testing and issue resolution

## Overview

This document describes the agreed-upon workflow for:
1. Identifying conformance issues
2. Implementing fixes
3. Validating fixes through unit tests
4. Running TCK conformance verification
5. Documenting the fix trail

## Workflow Phases

### Phase 1: Issue Identification

#### 1.1 Generate Initial Conformance Report
```bash
cd tck
python scripts/generate-conformance-report.py v{XXX}_{identifier}
```

**Naming Convention**: `CONFORMANCE_STATUS_v{XXX}_YYYYMMDD_{identifier}.md`
- `XXX`: Three-digit version (001, 002, etc.)
- `YYYYMMDD`: Date in YYYYMMDD format
- `identifier`: Optional context (e.g., "initial", "post_fix")

#### 1.2 Analyze Critical Issues
Review the generated report in `tck/conformance-reports/` to identify:
- Critical certification blockers
- Specification violations
- Error codes and behaviors

### Phase 2: Pre-Fix Validation

#### 2.1 Write Comprehensive Tests FIRST
**IMPORTANT**: Before implementing any fixes, create tests that validate the expected behavior:

```python
# Create test file: tests/test_conformance_fixes.py
class TestConformanceFixes:
    async def test_discovery_endpoint_url_with_hyphen(self, test_server):
        """Test that discovery endpoint uses hyphen (not underscore)."""
        response = await test_server.client.get("/.well-known/openid-configuration")
        await response.expect_status(200)
    
    async def test_token_endpoint_accepts_form_encoded(self, test_server):
        """Test that token endpoint accepts application/x-www-form-urlencoded."""
        # Test implementation
    
    # Additional tests for each issue...
```

#### 2.2 Run Tests to Confirm Failures
```bash
uv run pytest tests/test_conformance_fixes.py -v --tb=short
```

These tests should FAIL initially, confirming the issues exist.

### Phase 3: Implementation

#### 3.1 Fix Issues in Code
Implement fixes in the appropriate source files:
- `src/authly/api/oidc_router.py` - OIDC endpoints
- `src/authly/api/oauth_router.py` - OAuth endpoints
- Other relevant files

#### 3.2 Update Existing Tests
If existing tests use incorrect patterns (e.g., `json=` instead of `data=` for token endpoint):
```bash
# Example: Update token endpoint tests to use form-encoded data
find tests -name "*.py" -exec grep -l '"/api/v1/oauth/token".*json=' {} \; | \
while read f; do 
    sed -i '' 's|/oauth/token", json=|/oauth/token", data=|g' "$f"
done
```

### Phase 4: Unit Test Validation

#### 4.1 Run Conformance Fix Tests
```bash
# Run the specific conformance fix tests
uv run pytest tests/test_conformance_fixes.py -v --tb=short
```

**REQUIREMENT**: All tests MUST pass before proceeding.

#### 4.2 Run Broader Test Suite
```bash
# Run OAuth flow tests
uv run pytest tests/oauth_flows/ -v --tb=short

# Run OIDC scenario tests
uv run pytest tests/oidc_scenarios/ -v --tb=short

# Run auth journey tests
uv run pytest tests/auth_user_journey/ -v --tb=short
```

**REQUIREMENT**: Aim for 100% pass rate. Document any infrastructure-related failures.

### Phase 5: TCK Conformance Verification

#### 5.1 Generate Post-Fix Report
```bash
cd tck
python scripts/generate-conformance-report.py v{XXX}_post_fixes
```

#### 5.2 Compare Results
Review improvements in:
- Critical issue count
- Compliance percentages
- Specific test results

### Phase 6: Documentation

#### 6.1 Create Fix Summary Report
Create a comprehensive fix summary with proper versioning:

**File**: `tck/conformance-reports/FIX_SUMMARY_v{XXX}_YYYYMMDD.md`

Include:
- Executive summary
- Issues fixed (with before/after)
- Code changes made
- Test results proving fixes
- Deployment instructions

#### 6.2 Update README
Update `tck/conformance-reports/README.md` with:
- New version entries in the table
- Current status summary
- Link to fix summary
- Next steps

### Phase 7: Deployment (If Applicable)

#### 7.1 Rebuild Docker Images
```bash
# Rebuild with fixes
docker compose build --no-cache authly

# Restart services
docker compose down
docker compose up -d
```

#### 7.2 Generate Post-Deployment Report
```bash
cd tck
python scripts/generate-conformance-report.py v{XXX}_post_deployment
```

## Best Practices

### 1. Test-First Development
- **ALWAYS** write tests before implementing fixes
- Tests should fail initially and pass after fixes
- Create a dedicated test file for conformance fixes

### 2. Incremental Validation
- Run unit tests after each fix
- Don't wait until all fixes are done to test
- Use `uv run pytest` for all test execution

### 3. Documentation Trail
- Use consistent version numbering (v001, v002, etc.)
- Include dates in all reports (YYYYMMDD format)
- Create fix summaries for audit trail
- Update README with each significant change

### 4. Test Coverage Requirements
- Critical conformance tests: 100% pass required
- OAuth flow tests: Aim for >95% pass rate
- OIDC scenario tests: Aim for >90% pass rate
- Document any known infrastructure issues

## Common Fix Patterns

### Discovery Endpoint URL
```python
# Wrong
@router.get("/.well-known/openid_configuration")

# Correct
@router.get("/.well-known/openid-configuration")
```

### Token Endpoint Content-Type
```python
# Add form-encoded support
from fastapi import Form

@router.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(None),
    # ... other parameters
):
    # Implementation
```

### Error Code Handling
```python
# Return 400 instead of 422
raise HTTPException(
    status_code=400,  # Not 422
    detail="Invalid request"
)
```

### Authorization Redirect
```python
from fastapi.responses import RedirectResponse

# Redirect with error instead of 401
if not authenticated:
    error_params = {"error": "login_required"}
    redirect_url = f"{client_redirect}?{urlencode(error_params)}"
    return RedirectResponse(url=redirect_url, status_code=302)
```

## Conformance Report Fields

### Critical Fields to Monitor
1. **Discovery Endpoint**: Must work with hyphen
2. **Token Endpoint**: Must accept form-encoded data
3. **Error Codes**: Must return proper OAuth error codes
4. **Authorization Flow**: Must redirect appropriately
5. **PKCE**: Should be enforced for security

### Compliance Score Targets
- **OIDC Core**: Target >90% for certification
- **OAuth 2.0**: Target >85% for compliance
- **OAuth 2.1**: Target 100% (PKCE enforcement)

## Quick Reference Commands

```bash
# Run conformance fix tests
uv run pytest tests/test_conformance_fixes.py -v

# Run all OAuth tests
uv run pytest tests/oauth_flows/ -v

# Generate conformance report
cd tck && python scripts/generate-conformance-report.py v{XXX}_{tag}

# Check specific test
uv run pytest tests/path/to/test.py::TestClass::test_method -vvs

# Run with specific markers
uv run pytest -m "not slow" tests/

# Parallel test execution
uv run pytest -n auto tests/
```

## Troubleshooting

### Tests Still Failing After Fixes
1. Check if tests are using correct patterns (form vs JSON)
2. Verify Docker containers are rebuilt with fixes
3. Ensure test fixtures are properly isolated
4. Check for cached responses or state

### Conformance Report Shows No Improvement
1. Verify TCK is testing against updated code
2. Check if Docker needs rebuilding
3. Ensure fixes are in the correct endpoints
4. Verify test client configuration

### Test Infrastructure Issues
Common infrastructure failures that can be ignored:
- Connection timeouts in template tests
- Docker container startup delays
- Test isolation issues with parallel execution

## References

- [Original Issues Report](./conformance-reports/CONFORMANCE_STATUS_v001_20250806.md)
- [Fix Summary Example](./conformance-reports/FIX_SUMMARY_v005_20250806.md)
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

---
*This workflow ensures systematic identification, resolution, and validation of conformance issues with proper documentation for audit trails.*