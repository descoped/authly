# TCK Migration Recommendations

**Date**: August 7, 2025  
**Purpose**: Document what should be migrated from tck/ folder and what should remain  

## Migration Complete ✅

### What Was Migrated to `.claude/evolution/oidc-conformance-journey/`

1. **Historical Documentation** (MIGRATED)
   - `archive/` - Historical workflow documents
   - `conformance-reports/` - All versioned conformance status reports (v000-v007)
   - `results/` - Initial test results and summaries
   - `CONSOLIDATION_SUMMARY.md` - Summary of TCK consolidation work
   - `docs/BOUNDARIES.md` - Test boundaries documentation
   - `docs/OFFICIAL_CONFORMANCE_REQUIREMENTS.md` - Official requirements

2. **Journey Documentation** (CREATED)
   - `README.md` - The 90-100% journey (previously created)
   - `initial-journey-0-to-90.md` - The 0-90% journey (newly created)
   - `migration-recommendations.md` - This document

## What Should Remain in `tck/` ⚠️

### Active Test Infrastructure (DO NOT MIGRATE)
1. **Core Testing Files**
   - `Makefile` - Active build and test commands
   - `run-conformance.sh` - Active test runner
   - `docker-compose-*.yml` - Docker configurations
   - `scripts/*.py` - Active test scripts (conformance-validator.py, simple-conformance-test.py, etc.)

2. **Configuration Files**
   - `config/` - Test client and profile configurations
   - `conformance-suite/` - OpenID conformance suite source
   - `docker/` - Docker-specific configurations
   - `httpd-ci/` - CI/CD specific configurations

3. **Active Documentation**
   - `README.md` - Current TCK usage instructions
   - `QUICK_START.md` - Quick start guide for developers
   - `tck_todo.md` - Current task tracking (shows 100% completion)
   - `docs/TEST_PLAN_SUPPORT.md` - Active test plan documentation
   - `docs/troubleshooting.md` - Active troubleshooting guide

4. **Test Code**
   - `tests/` - Active test files
   - `scripts/test_*.py` - Test implementations

## Files That Could Be Archived (Optional)

These files in `tck/` are historical but might still have reference value:

1. **Old Makefiles**
   - `Makefile.old` - Previous version of Makefile
   - `Makefile.old2` - Even older version
   - `README.old` - Previous README version
   
   **Recommendation**: These could be deleted or moved to evolution if you want a cleaner tck/ folder

2. **Legacy Reports**
   - `reports/` - Contains generated test reports
   - `test_output.log` - Test execution logs
   
   **Recommendation**: Keep in tck/ as they may be regenerated during testing

## What's NOT Relevant for Next Steps

The following are NOT relevant for "advanced OIDC test scenarios not fully implemented":

1. **Infrastructure Setup** - Already complete
2. **Basic Conformance** - Already at 100%
3. **CI/CD Configuration** - Already working
4. **Docker Setup** - Already configured
5. **Historical Issues** - Already resolved

## What IS Relevant for Next Steps

For implementing "advanced OIDC test scenarios not fully implemented":

1. **Keep in tck/**:
   - All active test scripts
   - Configuration files
   - Docker compositions
   - Current documentation

2. **Reference from evolution/**:
   - Journey documentation (for context)
   - Conformance reports (for baseline)

## Summary of Migration

### ✅ Migrated (Historical/Journey)
```
.claude/evolution/oidc-conformance-journey/
├── README.md                           # 90-100% journey
├── initial-journey-0-to-90.md         # 0-90% journey
├── migration-recommendations.md        # This document
├── archive/                           # Historical workflows
├── conformance-reports/               # All v000-v007 reports
├── results/                           # Initial test results
├── docs/                              # Historical documentation
└── CONSOLIDATION_SUMMARY.md           # TCK consolidation work
```

### ⚠️ Kept in Place (Active/Operational)
```
tck/
├── README.md                          # Active usage docs
├── QUICK_START.md                     # Developer guide
├── Makefile                           # Active commands
├── run-conformance.sh                 # Test runner
├── scripts/*.py                       # Active test scripts
├── config/                            # Configurations
├── conformance-suite/                 # Test suite
├── docker/                            # Docker configs
├── tests/                             # Test implementations
└── tck_todo.md                        # Shows 100% complete
```

## Recommendations

1. **DO NOT MOVE**: Any code, scripts, or configurations that are actively used
2. **ALREADY MOVED**: Historical documentation and journey artifacts
3. **OPTIONAL CLEANUP**: Remove `*.old` files if you want a cleaner structure
4. **NEXT FOCUS**: Advanced OIDC test scenarios should be implemented in `tests/` directory

## For Advanced OIDC Test Scenarios

When implementing advanced OIDC test scenarios:

1. **Add new tests to**: `tck/tests/`
2. **Update configurations in**: `tck/config/`
3. **Document in**: `tck/README.md` or create new docs in `tck/docs/`
4. **Do NOT modify**: The evolution folder (it's for historical record)

---

*This completes the migration of historical OIDC conformance journey documentation while preserving all active testing infrastructure.*