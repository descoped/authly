# OIDC Conformance Status Reports

This directory contains versioned conformance status reports for tracking OIDC/OAuth compliance progress.

## Report Naming Convention
`CONFORMANCE_STATUS_v{version}_{date}_{optional_tag}.md`

- **version**: Three-digit incremental version (e.g., v001, v002)
- **date**: YYYYMMDD format
- **optional_tag**: Additional context (e.g., "initial", "post_fix", "final")

## Version History

| Version | Date | Status | Key Changes | Critical Issues |
|---------|------|--------|-------------|-----------------|
| [v000](./CONFORMANCE_STATUS_v000_20250806_initial.md) | 2025-08-06 | ❌ Failed | Initial assessment with old Docker image | Discovery URL, Missing endpoints, Wrong token endpoint in discovery |
| [v001](./CONFORMANCE_STATUS_v001_20250806.md) | 2025-08-06 | ⚠️ Partial | Rebuilt with latest code | Discovery URL, Token content-type, Error codes |
| [v002](./CONFORMANCE_STATUS_v002_20250806_post_rebuild.md) | 2025-08-06 | ⚠️ Partial | Automated testing after rebuild | Discovery URL, Token form-encoding, Error codes, Auth redirects |

## Current Status Summary (v002)

### 🚨 Certification Blockers (4 Critical Issues)
1. **Discovery endpoint URL** - Uses underscore instead of hyphen
2. **Token endpoint content-type** - Only accepts JSON, not form-encoded
3. **Token endpoint errors** - Returns 422 instead of 400
4. **Authorization endpoint** - Returns 401 instead of redirecting

### ✅ Fixed Issues
- Token endpoint URL now correct in discovery (`/api/v1/oauth/token`)
- JWKS endpoint available
- UserInfo endpoint available

### 📊 Compliance Score
- **OIDC Core**: 87% compliant ↑
- **OAuth 2.0**: 25% compliant ↓ (form-encoding issue identified)
- **OAuth 2.1**: 100% compliant ↑ (PKCE enforced)

## Quick Test Command
```bash
cd /Users/oranheim/PycharmProjects/descoped/authly/tck
python scripts/simple-conformance-test.py
```

## Next Report
Version v002 will be created after fixing the discovery endpoint URL issue.

## Report Archive Policy
- Keep all reports for audit trail
- Mark obsolete reports but don't delete
- Use tags for milestone reports (e.g., "pre_certification", "certified")