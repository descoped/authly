# OIDC/OAuth Test Conformance Kit (TCK)

## 🎯 Quick Start - Achieve 90% Conformance

```bash
# 1. Start Authly
docker compose up -d

# 2. Run conformance validator (90% compliance)
cd tck && make validate

# 3. View results
cat reports/latest/SPECIFICATION_CONFORMANCE.md
```

## Current Status: 90% Compliant ✅

| Category | Score | Status |
|----------|-------|--------|
| Discovery | 100% | ✅ All 22 checks pass |
| JWKS | 100% | ✅ All 7 checks pass |
| Endpoints | 50% | ⚠️ Token error format needs fixing |
| Security | 80% | ✅ PKCE enforced, RS256 supported |
| **OVERALL** | **90%** | **36/40 checks pass** |

## Directory Structure

```
tck/
├── Makefile              # Main automation commands
├── scripts/
│   ├── conformance-validator.py  # Core validator (90% compliance)
│   └── analyze_openapi_conformance.py  # API matrix analyzer
├── reports/              # Test results (gitignored)
│   └── latest/          # Symlink to most recent run
├── docs/
│   └── BOUNDARIES.md    # TCK vs Integration tests
└── conformance-reports/ # Historical reports
```

## Available Commands

```bash
make help          # Show all available commands
make validate      # Run spec validation (90% compliance)
make analyze       # Generate API conformance matrix  
make report        # Generate all reports
make clean         # Clean test artifacts
```

## Understanding Test Boundaries

| Test Type | Purpose | Location | What it Tests |
|-----------|---------|----------|---------------|
| **TCK Tests** | OIDC/OAuth spec compliance | `/tck/` | Response formats, required fields |
| **Integration Tests** | Business flow validation | `/scripts/integration-tests/` | Complete OAuth flows, user management |
| **Unit Tests** | Code functionality | `/tests/` | Models, services, utilities |

For detailed explanation, see [docs/BOUNDARIES.md](docs/BOUNDARIES.md)

## Fixing the Remaining 10%

### Issue 1: Token Endpoint Error Format
**Problem**: Missing 'error' field in JSON response  
**Fix**: Update `/api/v1/oauth/token` error responses to include `{"error": "invalid_grant"}`

### Issue 2: Authorization Endpoint Error Handling  
**Problem**: Returns 422 instead of redirecting with error  
**Fix**: Update `/api/v1/oauth/authorize` to redirect with `?error=invalid_request`

## CI/CD Integration

Tests run automatically via GitHub Actions:
- Every push to main/master
- All pull requests  
- Nightly at 2 AM UTC

See `.github/workflows/conformance-tests.yml`

## Next Steps

1. **Fix remaining 10%**: See issues above
2. **Official Certification**: Register at https://www.certification.openid.net/
3. **Maintain Compliance**: Keep tests in CI/CD

---

For more details, see [docs/](docs/) directory.