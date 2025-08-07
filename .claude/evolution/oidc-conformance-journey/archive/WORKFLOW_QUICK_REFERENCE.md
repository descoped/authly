# TCK Conformance Workflow - Quick Reference

## 🚀 Quick Start Checklist

### 1️⃣ Identify Issues
```bash
cd tck
python scripts/generate-conformance-report.py v001_initial
```
📄 Review: `conformance-reports/CONFORMANCE_STATUS_v001_*.md`

### 2️⃣ Write Tests FIRST
```python
# tests/test_conformance_fixes.py
class TestConformanceFixes:
    async def test_{issue_name}(self, test_server):
        # Test expected behavior
        await response.expect_status(200)  # Should fail initially
```

### 3️⃣ Run Tests (Expect Failures)
```bash
uv run pytest tests/test_conformance_fixes.py -v
# ❌ Tests should FAIL - confirming issues exist
```

### 4️⃣ Implement Fixes
- `src/authly/api/oidc_router.py` - OIDC endpoints
- `src/authly/api/oauth_router.py` - OAuth endpoints

### 5️⃣ Validate with Unit Tests
```bash
# Must pass 100%
uv run pytest tests/test_conformance_fixes.py -v
# ✅ All tests should PASS

# Run broader tests
uv run pytest tests/oauth_flows/ -v
uv run pytest tests/oidc_scenarios/ -v
```

### 6️⃣ Generate Post-Fix Report
```bash
cd tck
python scripts/generate-conformance-report.py v002_post_fixes
```

### 7️⃣ Document Fixes
Create: `conformance-reports/FIX_SUMMARY_v002_YYYYMMDD.md`
Update: `conformance-reports/README.md`

## 📝 Naming Conventions

### Reports
`CONFORMANCE_STATUS_v{XXX}_{YYYYMMDD}_{tag}.md`
- v001, v002, v003... (sequential)
- YYYYMMDD format
- Tags: initial, post_fixes, post_deployment

### Fix Summaries
`FIX_SUMMARY_v{XXX}_{YYYYMMDD}.md`

## 🎯 Key Requirements

| Step | Requirement | Command |
|------|-------------|---------|
| Unit Tests | 100% pass rate | `uv run pytest tests/test_conformance_fixes.py` |
| OAuth Tests | >95% pass rate | `uv run pytest tests/oauth_flows/` |
| OIDC Tests | >90% pass rate | `uv run pytest tests/oidc_scenarios/` |
| Documentation | Version + Date | `v005_20250806` format |

## 🔧 Common Fixes

### Discovery URL
```python
# ❌ Wrong
"/.well-known/openid_configuration"
# ✅ Correct
"/.well-known/openid-configuration"
```

### Token Endpoint
```python
# ✅ Accept form-encoded
from fastapi import Form
grant_type: str = Form(...)
```

### Error Codes
```python
# ✅ Return 400 (not 422)
status_code=400
```

### Authorization Redirect
```python
# ✅ Redirect (not 401)
return RedirectResponse(url=..., status_code=302)
```

## 🐳 Docker Deployment
```bash
# After all tests pass
docker compose build --no-cache authly
docker compose down && docker compose up -d

# Verify in Docker
cd tck
python scripts/generate-conformance-report.py v003_post_deployment
```

## 📊 Success Criteria

✅ **Ready for Deployment When:**
- All conformance fix tests pass (100%)
- OAuth/OIDC tests pass (>90%)
- Fix summary documented
- Version trail established

## 🔗 Key Files

| File | Purpose |
|------|---------|
| `tests/test_conformance_fixes.py` | Validation tests |
| `conformance-reports/README.md` | Version history |
| `CONFORMANCE_WORKFLOW.md` | Full workflow |
| `FIX_SUMMARY_v*_*.md` | Fix documentation |

---
*Always: Test First → Fix → Validate → Document*