# TCK Architecture Clarification

## Script Execution Context

### Current Architecture

The TCK has **THREE distinct execution contexts**:

```
┌─────────────────────────────────────────────────────────────┐
│                    TCK Execution Contexts                     │
├──────────────────┬────────────────┬─────────────────────────┤
│  TCK Container   │  Host/CI Shell │  Conformance Suite     │
│  (Dockerfile.tck)│  (bash scripts)│  (Java container)       │
├──────────────────┼────────────────┼─────────────────────────┤
│ validator.py     │ run-suite-     │ Full OIDC suite        │
│ test_plans.py    │   tests.sh     │ MongoDB backend        │
│ test_summary.py  │ generate-      │ HTTPS frontend         │
│ actionable_      │   reports.sh   │                        │
│   items.py       │ setup.sh       │                        │
└──────────────────┴────────────────┴─────────────────────────┘
```

## Script Purposes and Execution

### 1. Scripts in TCK Container (`src/*.py`)
**Execution**: Inside `authly-tck` container via `docker compose --profile validator run`
**Purpose**: Lightweight validation and reporting
**Config Used**: `config/test-plans/*.json`

```bash
# These run INSIDE the container:
make validate      # Runs src/validator.py
make test-plans    # Runs src/test_plans.py
make summary       # Runs src/test_summary.py
make actionable    # Runs src/actionable_items.py
```

### 2. Shell Scripts (`scripts/*.sh`)
**Execution**: On host machine or CI runner
**Purpose**: Orchestration and suite integration

#### `scripts/run-suite-tests.sh`
- **Does NOT run in TCK container**
- Runs on **host machine** (or CI runner)
- Orchestrates the **full conformance suite** containers
- Creates config files in `config/suite-*.json` (dynamically)
- Calls conformance suite API endpoints
- **Value**: Bridges gap between lightweight tests and full certification

#### `scripts/generate-reports.sh`
- Runs on host machine
- Aggregates results from multiple sources
- Creates unified reports

#### `scripts/setup.sh`
- Runs on host machine
- Sets up initial environment

## Configuration Files

### Static Configs (checked into git)
```
config/
├── conformance-profiles.json  # Profile definitions
├── profiles.json              # Test profiles
├── test-client.json          # Test client configuration
└── test-plans/
    ├── basic-certification.json  # Basic OIDC tests
    └── pkce-certification.json   # PKCE tests
```

### Dynamic Configs (created at runtime)
```
config/
└── suite-*.json  # Created by run-suite-tests.sh
```

## Value of `run-suite-tests.sh`

### What It Does
1. **Starts full conformance suite** if not running (MongoDB + HTTPD + Java suite)
2. **Creates test configurations** dynamically based on current Authly URL
3. **Calls suite API** to execute comprehensive tests
4. **Generates reports** in `reports/suite-tests/`

### Why It's Valuable
- **No manual UI interaction** - Automates suite testing
- **CI/CD friendly** - Can run in pipelines
- **Comprehensive testing** - 1000+ tests vs 40 in validator
- **Certification path** - Uses actual certification test modules

### What It Tests That Others Don't
```
Lightweight Validator (src/validator.py):
  ✓ Discovery format
  ✓ JWKS structure
  ✓ Basic endpoints
  = 40 checks

Test Plan Runner (src/test_plans.py):
  ✓ Some test modules
  ✗ No flow simulation
  = 11/25 modules

Full Suite (run-suite-tests.sh):
  ✓ Complete OAuth flows
  ✓ Security attacks
  ✓ Token lifecycle
  ✓ Session management
  ✓ Error scenarios
  = 1000+ test cases
```

## Correct Usage

### For Development (Fast Feedback)
```bash
# Uses TCK container - 2 seconds
make validate
make actionable
```

### For Pre-Commit (Deeper Testing)
```bash
# Uses TCK container - 10 seconds
make test-plans
make report
```

### For Certification Readiness (Complete Testing)
```bash
# Uses full suite - 5-10 minutes
make suite-start
make suite-test
make suite-test-pkce
```

## Why This Architecture?

1. **Separation of Concerns**
   - TCK container: Fast, lightweight checks
   - Shell scripts: Orchestration and integration
   - Conformance suite: Full certification testing

2. **Performance Optimization**
   - Developers get 2-second feedback
   - CI gets 10-second validation
   - Certification gets complete coverage

3. **Infrastructure Flexibility**
   - TCK container needs nothing
   - Suite needs MongoDB + Java
   - Scripts bridge the gap

## Summary

- `Dockerfile.tck` = Lightweight Python testing environment
- `scripts/run-suite-tests.sh` = Host script to orchestrate full suite
- `config/` = Both static test plans and dynamic suite configs
- **Value**: Provides path from 98% compliance to 100% certification