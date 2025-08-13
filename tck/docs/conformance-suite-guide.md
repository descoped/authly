# Understanding and Utilizing the OIDC Conformance Suite

## What is the Conformance Suite?

The **OpenID Foundation Conformance Suite** is the official, comprehensive testing framework for validating OpenID Connect and OAuth 2.x implementations. It's the gold standard for certification and ensures interoperability between identity providers and clients.

### Current Setup: Two-Tier Testing

We have a **hybrid approach** combining lightweight validation with full suite capability:

```
┌──────────────────────────────────────────────────────┐
│                  TCK Architecture                    │
├───────────────────────────┬──────────────────────────┤
│   Lightweight Validator   │   Full Conformance Suite │
│   (98% coverage)          │   (100% coverage)        │
├───────────────────────────┼──────────────────────────┤
│ • Python-based            │ • Java-based             │
│ • 40 spec checks          │ • 1000+ test cases       │
│ • Runs in seconds         │ • Runs in minutes        │
│ • No infrastructure       │ • Needs MongoDB + HTTPD  │
│ • Good for development    │ • Required for cert      │
└───────────────────────────┴──────────────────────────┘
```

## What the Conformance Suite Actually Tests

### 1. Complete OAuth/OIDC Flows
Unlike our lightweight validator that checks endpoints individually, the suite simulates **real client-server interactions**:

- **Authorization Code Flow**: Full redirect chain with state management
- **Implicit Flow**: Token delivery via fragments
- **Hybrid Flow**: Combination of code and token
- **Client Credentials**: Service-to-service authentication
- **Device Flow**: For input-constrained devices
- **Refresh Token**: Token renewal lifecycle

### 2. Security Attack Scenarios
The suite actively tests **security vulnerabilities**:

- **Code Injection**: Attempts to inject malicious authorization codes
- **Token Substitution**: Tries to use tokens from different sessions
- **CSRF Attacks**: Tests state parameter validation
- **Replay Attacks**: Attempts to reuse authorization codes
- **Downgrade Attacks**: Tries to force weaker security
- **Key Confusion**: Tests algorithm verification

### 3. Edge Cases and Error Handling
Tests **specification-mandated error responses**:

- Missing required parameters
- Invalid parameter combinations
- Malformed requests
- Expired tokens
- Revoked credentials
- Wrong content types

### 4. Interoperability Testing
Ensures your implementation works with **any compliant client**:

- Different signing algorithms (RS256, ES256, PS256)
- Various client authentication methods
- Multiple response types and modes
- Different scope combinations
- Request objects (JAR)
- Encrypted tokens (JWE)

## Current Utilization (What We Have)

### Lightweight Validator (`src/validator.py`)
```python
# Currently testing:
✅ Discovery document format (22 checks)
✅ JWKS structure and keys (7 checks)
✅ Endpoint availability (6 checks)
✅ Security requirements (5 checks)
= 40 total checks → 98% compliance
```

### Test Plan Runner (`src/test_plans.py`)
```python
# Executing official test modules:
✅ Basic certification: 8/17 tests (47%)
✅ PKCE certification: 3/8 tests (38%)
= 11/25 tests implemented
```

### Full Suite (Docker Profile `github-ci`)
```yaml
# Available but underutilized:
- MongoDB for test storage
- HTTPD for TLS termination
- Conformance suite API
- But NOT running actual test plans!
```

## How to Better Utilize the Conformance Suite

### Step 1: Enable Full Suite Testing Locally

```bash
# Start the full conformance suite
cd tck
export CONFORMANCE_IMAGE=ghcr.io/descoped/oidc-conformance-suite:latest
docker compose --profile github-ci up -d

# Wait for services (takes ~30 seconds)
sleep 30

# Access the suite UI
open https://localhost:8443
```

### Step 2: Create Test Configuration

Create `tck/config/conformance-test-config.json`:
```json
{
  "alias": "authly-local",
  "description": "Authly Local Testing",
  "server": {
    "discoveryUrl": "http://host.docker.internal:8000/.well-known/openid-configuration"
  },
  "client": {
    "client_id": "conformance-test",
    "client_secret": "test-secret",
    "redirect_uri": "https://localhost:8443/test/a/authly/callback"
  },
  "test_plan": "oidcc-basic-certification-test-plan",
  "variant": {
    "client_auth_type": "client_secret_basic",
    "response_type": "code",
    "response_mode": "query",
    "request_type": "plain_http_request"
  }
}
```

### Step 3: Run Tests via API

Create `tck/scripts/run-conformance-suite.py`:
```python
#!/usr/bin/env python3
"""
Run full OIDC conformance suite tests via API
"""
import requests
import json
import time
from typing import Dict, Any

class ConformanceSuiteRunner:
    def __init__(self, base_url="https://localhost:8443"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # Self-signed cert
    
    def create_test_plan(self, config: Dict[str, Any]) -> str:
        """Create a new test plan"""
        resp = self.session.post(
            f"{self.base_url}/api/plan",
            json=config
        )
        resp.raise_for_status()
        return resp.json()["id"]
    
    def run_test_module(self, plan_id: str, module: str) -> Dict:
        """Run a specific test module"""
        resp = self.session.post(
            f"{self.base_url}/api/plan/{plan_id}/test/{module}/start"
        )
        resp.raise_for_status()
        test_id = resp.json()["id"]
        
        # Wait for completion
        while True:
            status = self.session.get(
                f"{self.base_url}/api/plan/{plan_id}/test/{test_id}"
            ).json()
            
            if status["status"] in ["FINISHED", "FAILED", "WARNING"]:
                return status
            
            time.sleep(1)
    
    def run_all_tests(self, config_file: str):
        """Run all tests in a test plan"""
        with open(config_file) as f:
            config = json.load(f)
        
        # Create test plan
        plan_id = self.create_test_plan(config)
        print(f"Created test plan: {plan_id}")
        
        # Get test modules for this plan
        modules = self.get_test_modules(config["test_plan"])
        
        results = {"passed": 0, "failed": 0, "warnings": 0}
        
        for module in modules:
            print(f"Running {module}...")
            result = self.run_test_module(plan_id, module)
            
            if result["status"] == "FINISHED":
                results["passed"] += 1
                print(f"  ✅ PASSED")
            elif result["status"] == "WARNING":
                results["warnings"] += 1
                print(f"  ⚠️ WARNING: {result.get('message', '')}")
            else:
                results["failed"] += 1
                print(f"  ❌ FAILED: {result.get('message', '')}")
        
        # Generate report
        self.generate_report(plan_id, results)
        return results
    
    def get_test_modules(self, test_plan: str) -> list:
        """Get modules for a test plan"""
        # These are the actual test modules from OpenID certification
        if "basic" in test_plan:
            return [
                "oidcc-server",
                "oidcc-discovery-openid-configuration",
                "oidcc-discovery-jwks",
                "oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
                "oidcc-ensure-registered-redirect-uri",
                "oidcc-userinfo-get",
                "oidcc-userinfo-post-header",
                "oidcc-userinfo-post-body",
                "oidcc-id-token-kid-absent-single-jwks",
                "oidcc-id-token-aud",
                "oidcc-id-token-iat",
                "oidcc-id-token-sub",
                "oidcc-scope-profile",
                "oidcc-scope-email",
                "oidcc-scope-address",
                "oidcc-scope-phone",
                "oidcc-nonce-invalid",
            ]
        elif "pkce" in test_plan:
            return [
                "oidcc-codereuse-30seconds",
                "oidcc-codereuse",
                "oidcc-ensure-pkce-required",
                "oidcc-ensure-pkce-code-verifier-required",
                "oidcc-ensure-pkce-code-challenge-method-s256",
                "oidcc-ensure-pkce-plain-not-supported",
                "oidcc-ensure-pkce-invalid-code-verifier",
                "oidcc-ensure-pkce-missing-code-verifier",
            ]
        return []
    
    def generate_report(self, plan_id: str, results: Dict):
        """Generate detailed test report"""
        report = f"""
# Conformance Suite Test Results

Plan ID: {plan_id}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- ✅ Passed: {results['passed']}
- ⚠️ Warnings: {results['warnings']}
- ❌ Failed: {results['failed']}
- **Pass Rate**: {results['passed']/(results['passed']+results['failed']+results['warnings'])*100:.1f}%

## Detailed Results
[View in UI](https://localhost:8443/plan-detail.html?plan={plan_id})
"""
        
        with open(f"reports/conformance-suite-{plan_id}.md", "w") as f:
            f.write(report)
        
        print(f"\n📄 Report saved: reports/conformance-suite-{plan_id}.md")

if __name__ == "__main__":
    runner = ConformanceSuiteRunner()
    results = runner.run_all_tests("config/conformance-test-config.json")
    
    # Exit with error if not meeting threshold
    pass_rate = results["passed"] / (results["passed"] + results["failed"] + results["warnings"])
    if pass_rate < 0.9:
        print(f"❌ Pass rate {pass_rate*100:.1f}% below 90% threshold")
        exit(1)
    
    print(f"✅ Pass rate {pass_rate*100:.1f}% meets threshold")
```

### Step 4: Integrate Dynamic Testing

Create `tck/src/dynamic_tester.py`:
```python
"""
Dynamic flow testing using conformance suite infrastructure
"""
import asyncio
from playwright.async_api import async_playwright

class DynamicFlowTester:
    """Simulates real browser-based OAuth flows"""
    
    async def test_authorization_code_flow(self):
        """Complete authorization code flow with browser automation"""
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            
            # Start authorization
            await page.goto(
                "http://localhost:8000/api/v1/oauth/authorize?"
                "response_type=code&"
                "client_id=test&"
                "redirect_uri=https://localhost:8443/callback&"
                "scope=openid profile email&"
                "state=random123"
            )
            
            # Handle login (if redirected)
            if "login" in page.url:
                await page.fill("#username", "testuser")
                await page.fill("#password", "testpass")
                await page.click("#login-button")
            
            # Handle consent (if shown)
            if "consent" in page.url:
                await page.click("#approve-button")
            
            # Extract authorization code
            await page.wait_for_url("**/callback?code=**")
            url = page.url
            code = url.split("code=")[1].split("&")[0]
            
            # Exchange for token
            # ... token exchange logic
            
            await browser.close()
            return {"status": "passed", "code": code}
```

## Practical Improvements to Make

### 1. Add Suite-Based Integration Tests

```python
# tck/tests/test_conformance_suite.py
def test_basic_certification():
    """Run basic certification test plan"""
    runner = ConformanceSuiteRunner()
    results = runner.run_all_tests("config/basic-cert.json")
    assert results["passed"] >= 15  # 15/17 minimum

def test_pkce_certification():
    """Run PKCE certification test plan"""
    runner = ConformanceSuiteRunner()
    results = runner.run_all_tests("config/pkce-cert.json")
    assert results["passed"] >= 7  # 7/8 minimum

def test_security_scenarios():
    """Test security attack scenarios"""
    runner = ConformanceSuiteRunner()
    results = runner.run_security_tests()
    assert results["blocked_attacks"] == results["total_attacks"]
```

### 2. Create Makefile Targets

```makefile
# Add to tck/Makefile
suite-start: ## Start full conformance suite
	docker compose --profile github-ci up -d
	@echo "Suite available at https://localhost:8443"

suite-test: ## Run conformance suite tests
	python scripts/run-conformance-suite.py

suite-report: ## Generate suite test report
	python scripts/generate-suite-report.py

suite-stop: ## Stop conformance suite
	docker compose --profile github-ci down
```

### 3. Add Profile-Specific Testing

```yaml
# tck/config/test-profiles.yml
profiles:
  basic:
    name: "Basic OpenID Provider"
    required_score: 90
    test_modules:
      - discovery
      - jwks
      - authorization
      - token
      - userinfo
  
  advanced:
    name: "Advanced Features"
    required_score: 80
    test_modules:
      - request_objects
      - encrypted_tokens
      - session_management
      - frontchannel_logout
  
  security:
    name: "Security Best Practices"
    required_score: 100
    test_modules:
      - pkce_required
      - nonce_validation
      - state_validation
      - code_replay_prevention
```

## Benefits of Full Suite Utilization

### What We're Missing Now
1. **Flow Testing**: Only testing individual endpoints, not complete flows
2. **Security Validation**: Not testing attack scenarios
3. **Interoperability**: Not testing with different client configurations
4. **Edge Cases**: Missing malformed request handling
5. **Performance**: No load testing or timing attacks

### What Full Suite Provides
1. **Certification Path**: Exact tests used for official certification
2. **Comprehensive Coverage**: 1000+ test cases vs our 40
3. **Client Simulation**: Acts like real-world OIDC clients
4. **Security Assurance**: Tests against known vulnerabilities
5. **Detailed Reports**: Pinpoints exact specification violations

## Recommended Implementation Plan

### Phase 1: Immediate (1 day)
- [ ] Add `suite-test` command to Makefile
- [ ] Create basic test configuration
- [ ] Run first full suite test locally
- [ ] Document gaps found

### Phase 2: Integration (1 week)
- [ ] Create `run-conformance-suite.py` script
- [ ] Add suite tests to CI pipeline
- [ ] Create profile-based testing
- [ ] Generate actionable reports from suite results

### Phase 3: Comprehensive (2 weeks)
- [ ] Implement dynamic flow testing
- [ ] Add security scenario testing
- [ ] Create interoperability test matrix
- [ ] Build dashboard for tracking progress

### Phase 4: Certification Ready (1 month)
- [ ] Fix all failing test modules
- [ ] Achieve 100% pass rate on basic certification
- [ ] Document conformance profile
- [ ] Submit for official certification

## Key Metrics to Track

```python
# What to measure from suite tests
metrics = {
    "test_modules_passed": 0,  # Target: 25/25
    "security_tests_passed": 0,  # Target: 100%
    "interop_configs_tested": 0,  # Target: 10+
    "response_time_p95": 0,  # Target: <500ms
    "error_format_compliance": 0,  # Target: 100%
}
```

## Conclusion

We have the infrastructure but are **underutilizing** it. The conformance suite can provide:
- **10x more test coverage** than our current validator
- **Real-world client simulation** vs static checks
- **Security validation** against actual attacks
- **Certification readiness** assessment

By better utilizing the suite, we can move from **98% basic compliance** to **100% certification readiness**.