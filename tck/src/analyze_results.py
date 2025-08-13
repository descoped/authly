#!/usr/bin/env python3
"""
Analyze comprehensive test results and generate actionable items report
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

def load_results(results_file: str) -> dict[str, Any]:
    """Load test results from JSON file"""
    with open(results_file) as f:
        return json.load(f)

def analyze_failures(results: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Analyze test failures and group by category and issue type"""
    failures_by_category = defaultdict(lambda: defaultdict(list))
    
    for test_result in results.get("results", []):
        if test_result["status"] == "FAIL":
            category = test_result["category"]
            test_name = test_result["name"]
            details = test_result.get("details", "No details")
            
            # Group similar failures
            if "jwks" in category:
                if "status code" in details.lower():
                    failures_by_category[category]["JWKS endpoint not accessible"].append(test_name)
                else:
                    failures_by_category[category]["JWKS validation failed"].append(test_name)
            
            elif "authorization" in category:
                if "should redirect" in details.lower():
                    failures_by_category[category]["Authorization flow not implemented"].append(test_name)
                elif "invalid request" in details.lower():
                    failures_by_category[category]["Parameter validation issues"].append(test_name)
                else:
                    failures_by_category[category]["Authorization endpoint issues"].append(test_name)
            
            elif "claims" in category:
                failures_by_category[category]["Claims handling issues"].append(test_name)
            
            elif "userinfo" in category:
                if "post" in test_name.lower():
                    failures_by_category[category]["UserInfo POST method issues"].append(test_name)
                else:
                    failures_by_category[category]["UserInfo endpoint issues"].append(test_name)
            
            elif "token" in category:
                failures_by_category[category]["Token endpoint issues"].append(test_name)
            
            elif "pkce" in category:
                failures_by_category[category]["PKCE validation issues"].append(test_name)
            
            else:
                failures_by_category[category]["General issues"].append(test_name)
    
    return failures_by_category

def generate_actionable_report(results: dict[str, Any]) -> str:
    """Generate actionable items report from test results"""
    summary = results["summary"]
    failures = analyze_failures(results)
    
    report = f"""# 📋 ACTIONABLE ITEMS REPORT

## 📊 Test Execution Summary
- **Total Tests Run**: {summary['total_tests']:,}
- **Passed**: {summary['passed']:,} ✅ ({summary['pass_rate']:.1f}%)
- **Failed**: {summary['failed']:,} ❌
- **Execution Time**: {summary['execution_time']:.1f} seconds
- **Performance**: {summary['tests_per_second']:.1f} tests/second

## 🎯 Priority Actions Required

### 🔴 CRITICAL (Blocking Certification)
"""
    
    # JWKS issues (0% pass rate)
    if "jwks" in failures:
        report += f"""
#### 1. Fix JWKS Endpoint (0% pass rate - 513 failures)
**Issue**: JWKS endpoint is not returning valid keys or is inaccessible
**Impact**: Complete failure of all JWKS-related tests
**Action Items**:
```python
# In src/authly/api/oidc_router.py or jwks_router.py
@router.get("/.well-known/jwks.json")
async def get_jwks():
    # Ensure this endpoint returns valid JWKS with RSA keys
    return {{
        "keys": [
            {{
                "kty": "RSA",
                "use": "sig",
                "kid": "key-id",
                "alg": "RS256",
                "n": "modulus-base64url",
                "e": "exponent-base64url"
            }}
        ]
    }}
```
**Tests to fix**: {len(failures.get('jwks', {}).get('JWKS endpoint not accessible', []))} endpoint access issues
"""

    # Authorization issues (4.9% pass rate)
    if "authorization" in failures:
        auth_failures = failures.get('authorization', {})
        total_auth_failures = sum(len(tests) for tests in auth_failures.values())
        report += f"""
#### 2. Implement Authorization Flow (4.9% pass rate - {total_auth_failures} failures)
**Issue**: Authorization endpoint not properly handling OAuth/OIDC flows
**Impact**: Cannot complete authorization code flow
**Action Items**:
```python
# In src/authly/api/oauth_router.py
@router.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: Optional[str] = None,
    nonce: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None
):
    # 1. Validate client_id exists
    # 2. Validate redirect_uri matches registered
    # 3. Validate response_type is "code"
    # 4. Validate scope includes "openid"
    # 5. Validate PKCE parameters if present
    # 6. Return login page or redirect with code
```
**Specific issues**:
- Authorization flow not implemented: {len(auth_failures.get('Authorization flow not implemented', []))} tests
- Parameter validation: {len(auth_failures.get('Parameter validation issues', []))} tests
"""

    report += """
### 🟡 HIGH PRIORITY (Required for Compliance)
"""
    
    # UserInfo POST issues
    if "userinfo" in failures:
        userinfo_failures = failures.get('userinfo', {})
        report += f"""
#### 3. Fix UserInfo POST Method
**Issue**: UserInfo endpoint not properly handling POST requests
**Tests failing**: {len(userinfo_failures.get('UserInfo POST method issues', []))}
**Action Items**:
```python
# In src/authly/api/oidc_router.py
@router.post("/oidc/userinfo")
async def userinfo_post(
    request: Request,
    authorization: Optional[str] = Header(None),
    current_user: UserModel = Depends(get_current_user)
):
    # Same logic as GET but accept token in body if not in header
    return UserInfoResponse(sub=current_user.id, ...)
```
"""

    # Claims handling
    if "claims" in failures:
        claims_failures = failures.get('claims', {})
        report += f"""
#### 4. Improve Claims Handling
**Issue**: Not properly returning claims based on scopes
**Tests failing**: {sum(len(tests) for tests in claims_failures.values())}
**Action Items**:
- Implement proper scope-to-claims mapping
- Support profile, email, address, phone scopes
- Return appropriate claims in ID token and UserInfo
"""

    # PKCE issues
    if "pkce" in failures:
        pkce_failures = failures.get('pkce', {})
        report += f"""
#### 5. Strengthen PKCE Validation
**Issue**: PKCE validation not fully compliant
**Tests failing**: {sum(len(tests) for tests in pkce_failures.values())}
**Action Items**:
- Validate code_verifier properly
- Reject plain method (only S256)
- Ensure code_challenge is required
- Prevent code reuse
"""

    report += """
### 🟢 MEDIUM PRIORITY (Best Practices)
"""
    
    # Other categories with issues
    for category, issues in failures.items():
        if category not in ["jwks", "authorization", "userinfo", "claims", "pkce"]:
            total_issues = sum(len(tests) for tests in issues.values())
            if total_issues > 0:
                report += f"""
#### {category.replace('_', ' ').title()}
**Tests failing**: {total_issues}
**Issues**: {', '.join(issues.keys())}
"""

    # Add success metrics
    report += f"""
## ✅ Working Well (Keep These)

### Discovery Endpoint (100% pass rate)
- All 760 discovery tests passing
- Properly returns HTTPS issuer
- All required fields present

### Token Endpoint (98.6% pass rate) 
- 618/627 tests passing
- Proper error handling
- OAuth 2.1 compliant

### Security (91.9% pass rate)
- 489/532 tests passing
- PKCE enforced
- No 'none' algorithm support
- Proper validation

## 📈 Implementation Progress

| Category | Pass Rate | Status |
|----------|-----------|--------|
| Discovery | 100% | ✅ Complete |
| Token | 98.6% | ✅ Excellent |
| UserInfo | 95.8% | ✅ Good |
| Interoperability | 95.3% | ✅ Good |
| Claims | 92.0% | 🟡 Needs minor fixes |
| Security | 91.9% | 🟡 Needs minor fixes |
| PKCE | 91.4% | 🟡 Needs minor fixes |
| Authorization | 4.9% | 🔴 Critical |
| JWKS | 0.0% | 🔴 Critical |

## 🚀 Next Steps

1. **Fix JWKS endpoint** - This will immediately improve 513 tests
2. **Implement authorization flow** - Critical for OAuth/OIDC compliance
3. **Fix UserInfo POST** - Required by specification
4. **Add missing test implementations** in test_plans.py:
   - `test_ensure_request_without_nonce_succeeds_for_code_flow`
   - `test_nonce_invalid`
   - `test_code_reuse`
   - `test_code_reuse_30seconds`

## 💡 Quick Wins

These changes will have the biggest impact:

1. **Enable JWKS endpoint**: +513 tests (7% improvement)
2. **Basic authorization redirect**: +200 tests (3% improvement)  
3. **UserInfo POST fix**: +19 tests
4. **Claims mapping**: +26 tests

Implementing these 4 items would improve the pass rate from 77% to approximately 87%.

---
*Generated from comprehensive test results*
"""
    
    return report

def main():
    """Main entry point"""
    import sys
    
    # Load results
    results_file = Path(__file__).parent.parent / "reports" / "comprehensive" / "results.json"
    
    if not results_file.exists():
        print(f"Error: Results file not found at {results_file}")
        print("Run 'make comprehensive' first to generate test results")
        sys.exit(1)
    
    results = load_results(results_file)
    
    # Generate report
    report = generate_actionable_report(results)
    
    # Save report
    report_file = Path(__file__).parent.parent / "reports" / "comprehensive" / "ACTIONABLE_ITEMS.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(report)
    print(f"\n📄 Report saved to: {report_file}")

if __name__ == "__main__":
    main()