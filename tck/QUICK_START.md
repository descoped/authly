# Quick Start: Achieve 90% OIDC Conformance

## Three Simple Steps

```bash
# Step 1: Start Authly
docker compose up -d

# Step 2: Run conformance test
cd tck && ./run-conformance.sh

# Step 3: View results (90% compliance achieved!)
cat reports/latest/SPECIFICATION_CONFORMANCE.md
```

## What You Get

✅ **90% OIDC/OAuth Compliance** (36/40 checks pass)
- Discovery: 100% ✅
- JWKS: 100% ✅  
- Endpoints: 50% ⚠️
- Security: 80% ✅

## Known Issues (10% gap)

1. **Token endpoint**: Missing 'error' field in error responses
2. **Authorization endpoint**: Returns 422 instead of redirecting

## Alternative Methods

### Using Make
```bash
cd tck
make validate        # Run conformance test
make test-quick     # Quick health check
make report         # Generate all reports
```

### Using Python directly
```bash
cd tck
python scripts/conformance-validator.py
```

### In CI/CD
```yaml
- name: Run Conformance
  run: |
    cd tck
    make validate
```

## Success Criteria

- **Target**: 90% compliance ✅
- **Current**: 90% compliance ✅
- **Ready for**: Development and testing
- **Goal**: Self-certification for OIDC compliance (100%)

---

For full documentation, see [README.md](README.md)