# Requirements for Official Conformance Test Support

## What It Takes to Support test-plans/*.json

### Option 1: Full OpenID Foundation Suite (Complex)

This is the official path, requiring significant infrastructure:

#### Infrastructure Requirements
```yaml
Services Needed:
- MongoDB: Store test results and configurations
- HTTPD: Proxy for test callbacks  
- Java Server: Run conformance suite (300MB+ JAR)
- Browser Automation: Selenium for UI tests
- Memory: 4GB+ RAM minimum
```

#### Implementation Steps
1. **Build Conformance Suite** (~30 min)
   ```bash
   git clone https://gitlab.com/openid/conformance-suite.git
   mvn clean package -DskipTests  # Requires Maven, Java 17
   # Produces 300MB+ JAR file
   ```

2. **Start Infrastructure** (docker-compose-tck.yml)
   ```yaml
   - MongoDB (27017)
   - Conformance Server (9443)
   - HTTPD Proxy (8443)
   - Selenium Grid (4444) - optional
   ```

3. **Configure Test Plans**
   - Upload JSON test plans via API or UI
   - Create test instances
   - Run each test module

4. **Handle Callbacks**
   - Suite acts as OAuth client
   - Needs public URL or proxy setup
   - Complex redirect handling

**Effort: 2-3 weeks** to fully integrate and debug

### Option 2: Lightweight Test Runner (Recommended)

Build a Python-based runner that interprets the test plans directly:

#### Implementation Approach
```python
# conformance_runner.py
class ConformanceTestRunner:
    def __init__(self, test_plan_path):
        self.plan = json.load(open(test_plan_path))
        self.results = {}
    
    def run_test_module(self, module_name):
        """Map test modules to Python implementations"""
        tests = {
            "oidcc-server": self.test_server_config,
            "oidcc-userinfo-get": self.test_userinfo_get,
            "oidcc-ensure-pkce-required": self.test_pkce_required,
            # ... map all modules
        }
        return tests[module_name]()
    
    def run_all(self):
        for module in self.plan["test_modules"]:
            if module["required"]:
                self.results[module["name"]] = self.run_test_module(module["name"])
```

#### What We'd Need to Build

1. **Test Module Implementations** (~50 test cases)
   ```python
   def test_userinfo_get(self):
       """OIDCC-USERINFO-GET: Test UserInfo with GET method"""
       # 1. Get access token
       token = self.get_access_token()
       
       # 2. Call UserInfo endpoint
       response = requests.get(
           f"{self.base_url}/oidc/userinfo",
           headers={"Authorization": f"Bearer {token}"}
       )
       
       # 3. Validate response
       assert response.status_code == 200
       assert "sub" in response.json()
       return "PASS"
   ```

2. **OAuth Flow Simulator**
   ```python
   class OAuthFlowSimulator:
       def authorization_code_flow(self, pkce=False):
           # 1. Generate PKCE if needed
           # 2. Build authorization URL
           # 3. Simulate authorization
           # 4. Exchange code for token
           # 5. Return tokens
   ```

3. **Token Validator**
   ```python
   class TokenValidator:
       def validate_id_token(self, token):
           # Decode JWT
           # Verify signature
           # Check claims (iss, aud, exp, etc.)
           # Validate against JWKS
   ```

4. **Report Generator**
   ```python
   def generate_certification_report(results):
       # Format results per OpenID specs
       # Calculate pass/fail rates
       # Generate certification evidence
   ```

**Effort: 1 week** for basic implementation covering critical tests

### Option 3: Hybrid Approach (Pragmatic)

Extend our existing `conformance-validator.py` to read test plans:

```python
# Enhanced conformance-validator.py
class OIDCConformanceValidator:
    def run_from_test_plan(self, plan_path):
        """Run tests defined in JSON test plan"""
        plan = json.load(open(plan_path))
        
        # Map test modules to our existing methods
        module_mapping = {
            "oidcc-server": self.validate_discovery_document,
            "oidcc-userinfo-get": lambda: self.test_userinfo("GET"),
            "oidcc-ensure-pkce-required": self.validate_pkce_enforcement,
            # Add more mappings
        }
        
        results = {}
        for module in plan["test_modules"]:
            if module["name"] in module_mapping:
                results[module["name"]] = module_mapping[module["name"]]()
        
        return results
```

**Effort: 2-3 days** to extend existing validator

## Comparison Matrix

| Approach | Effort | Complexity | Maintenance | Certification Valid |
|----------|--------|------------|-------------|-------------------|
| **Official Suite** | 2-3 weeks | High | High | ✅ Yes |
| **Python Runner** | 1 week | Medium | Medium | ⚠️ Unofficial |
| **Hybrid Extension** | 2-3 days | Low | Low | ⚠️ Unofficial |

## Missing Pieces for Full Support

Regardless of approach, we need to fix:

### 1. Authorization Flow Simulation
Currently missing:
- Browser automation or API simulation
- Session handling
- Redirect capture
- State management

### 2. Token Generation & Validation
Need to implement:
- ID token generation with correct claims
- Signature validation against JWKS
- Token introspection endpoint
- Refresh token rotation

### 3. Advanced Test Cases
Not yet covered:
- Request object support
- Hybrid flow
- Client authentication methods
- Logout/session management
- Dynamic client registration

## Recommended Path Forward

### Phase 1: Extend Current Validator (2-3 days)
```python
# Add to conformance-validator.py
def run_basic_certification(self):
    """Run basic-certification.json tests"""
    return self.run_from_test_plan("config/test-plans/basic-certification.json")
```

### Phase 2: Add Missing Tests (1 week)
- Implement OAuth flow simulation
- Add token validation
- Cover required test modules

### Phase 3: Generate Certification Report (2 days)
- Format results per OpenID requirements
- Include all test evidence
- Generate submission package

## Quick Implementation Example

Here's how to start supporting test plans today:

```python
#!/usr/bin/env python3
# enhanced_conformance.py

import json
from pathlib import Path
from conformance_validator import OIDCConformanceValidator

class TestPlanRunner(OIDCConformanceValidator):
    def __init__(self, test_plan_path):
        super().__init__()
        self.test_plan = json.load(open(test_plan_path))
        
    def run(self):
        results = {
            "plan": self.test_plan["name"],
            "modules": {}
        }
        
        # Run basic tests we already have
        basic_tests = {
            "oidcc-server": lambda: self.validate_discovery_document(),
            "oidcc-discovery-issuer-not-matching-config": lambda: self.check_issuer_match(),
            "oidcc-userinfo-get": lambda: self.test_userinfo_requires_auth(),
        }
        
        for module in self.test_plan["test_modules"]:
            name = module["name"]
            if name in basic_tests:
                try:
                    basic_tests[name]()
                    results["modules"][name] = "PASS"
                except:
                    results["modules"][name] = "FAIL"
            else:
                results["modules"][name] = "NOT_IMPLEMENTED"
        
        return results

# Usage
runner = TestPlanRunner("config/test-plans/basic-certification.json")
results = runner.run()
print(json.dumps(results, indent=2))
```

## Summary

**Current Gap**: We have 90% spec compliance but 0% test plan support

**To Support Test Plans**:
- **Minimum**: 2-3 days to extend current validator
- **Recommended**: 1 week for lightweight Python runner
- **Full Official**: 2-3 weeks for complete suite integration

**Business Decision**: 
- If you need official certification → Use official suite (complex but valid)
- If you need testing only → Build Python runner (simpler, good enough)
- If you need quick progress → Extend current validator (fastest path)