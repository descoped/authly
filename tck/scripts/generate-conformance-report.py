#!/usr/bin/env python3
"""
Generate versioned OIDC Conformance Status Report
Automatically increments version and runs tests
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path
import requests

# Disable SSL warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_next_version():
    """Get the next version number based on existing reports"""
    reports_dir = Path(__file__).parent.parent / "conformance-reports"
    if not reports_dir.exists():
        reports_dir.mkdir(parents=True)
        return "001"

    # Find all existing reports
    existing = [f for f in reports_dir.glob("CONFORMANCE_STATUS_v*.md")]
    if not existing:
        return "001"

    # Extract version numbers
    versions = []
    for f in existing:
        try:
            # Extract version from filename like CONFORMANCE_STATUS_v001_...
            parts = f.stem.split("_")
            for part in parts:
                if part.startswith("v") and part[1:].isdigit():
                    versions.append(int(part[1:]))
        except:
            continue

    return f"{max(versions) + 1:03d}" if versions else "001"


def run_tests():
    """Run conformance tests and collect results"""
    results = {
        "discovery_underscore": False,
        "discovery_hyphen": False,
        "token_endpoint": None,
        "token_form_encoded": False,
        "token_json": False,
        "token_error_code": None,
        "jwks_available": False,
        "userinfo_available": False,
        "authorization_redirect": False,
        "pkce_required": False,
        "discovery_fields": {},
    }

    # Test discovery with underscore
    try:
        resp = requests.get("http://localhost:8000/.well-known/openid_configuration")
        if resp.status_code == 200:
            results["discovery_underscore"] = True
            discovery = resp.json()
            results["token_endpoint"] = discovery.get("token_endpoint", "").replace("http://localhost:8000", "")
            results["discovery_fields"] = discovery
    except:
        pass

    # Test discovery with hyphen (spec-compliant)
    try:
        resp = requests.get("http://localhost:8000/.well-known/openid-configuration")
        results["discovery_hyphen"] = resp.status_code == 200
    except:
        pass

    # Test token endpoint with form-encoded
    try:
        resp = requests.post(
            "http://localhost:8000/api/v1/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="grant_type=invalid",
        )
        results["token_form_encoded"] = resp.status_code in [400, 401]
        if resp.status_code == 422:
            results["token_error_code"] = 422
        elif resp.status_code == 400:
            results["token_error_code"] = 400
    except:
        pass

    # Test token endpoint with JSON
    try:
        resp = requests.post(
            "http://localhost:8000/api/v1/oauth/token",
            headers={"Content-Type": "application/json"},
            json={"grant_type": "invalid"},
        )
        results["token_json"] = resp.status_code in [400, 401]
    except:
        pass

    # Test JWKS
    try:
        resp = requests.get("http://localhost:8000/.well-known/jwks.json")
        results["jwks_available"] = resp.status_code == 200
    except:
        pass

    # Test UserInfo
    try:
        resp = requests.get("http://localhost:8000/oidc/userinfo")
        results["userinfo_available"] = resp.status_code == 401  # Should require auth
    except:
        pass

    # Test Authorization endpoint
    try:
        resp = requests.get(
            "http://localhost:8000/api/v1/oauth/authorize",
            params={"client_id": "test", "response_type": "code", "redirect_uri": "http://localhost/callback"},
        )
        results["authorization_redirect"] = resp.status_code in [302, 303]
    except:
        pass

    # Check PKCE requirement
    results["pkce_required"] = results["discovery_fields"].get("require_pkce", False)

    return results


def calculate_compliance_score(results):
    """Calculate compliance scores"""
    oidc_checks = [
        results["discovery_hyphen"],  # Correct discovery URL
        results["jwks_available"],
        results["userinfo_available"],
        len(results["discovery_fields"]) > 10,  # Has substantial metadata
        "issuer" in results["discovery_fields"],
        "authorization_endpoint" in results["discovery_fields"],
        "token_endpoint" in results["discovery_fields"],
        "jwks_uri" in results["discovery_fields"],
    ]

    oauth_checks = [
        results["token_form_encoded"],  # Accepts form-encoded
        results["token_error_code"] == 400,  # Correct error code
        results["authorization_redirect"],  # Redirects on error
        results["token_endpoint"] == "/api/v1/oauth/token",  # Correct endpoint
    ]

    oauth21_checks = [
        results["pkce_required"],  # PKCE enforcement
    ]

    oidc_score = int(sum(oidc_checks) / len(oidc_checks) * 100)
    oauth_score = int(sum(oauth_checks) / len(oauth_checks) * 100)
    oauth21_score = int(sum(oauth21_checks) / len(oauth21_checks) * 100)

    return oidc_score, oauth_score, oauth21_score


def generate_report(version, tag=None):
    """Generate the conformance report"""
    print(f"🔍 Running conformance tests...")
    results = run_tests()

    print(f"📊 Calculating compliance scores...")
    oidc_score, oauth_score, oauth21_score = calculate_compliance_score(results)

    date_str = datetime.now().strftime("%Y%m%d")
    date_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    filename = f"CONFORMANCE_STATUS_v{version}_{date_str}"
    if tag:
        filename += f"_{tag}"
    filename += ".md"

    # Determine critical issues
    critical_issues = []
    if not results["discovery_hyphen"]:
        critical_issues.append("Discovery endpoint uses underscore instead of hyphen")
    if not results["token_form_encoded"]:
        critical_issues.append("Token endpoint doesn't accept form-encoded data")
    if results["token_error_code"] == 422:
        critical_issues.append("Token endpoint returns 422 instead of 400")
    if not results["authorization_redirect"]:
        critical_issues.append("Authorization endpoint returns 401 instead of redirecting")

    # Build report content
    report = f"""# OIDC Conformance Status Report v{version}
**Generated**: {date_human}  
**Version**: v{version}  
**Tag**: {tag or "standard"}  

## Executive Summary
Automated conformance test run for OIDC/OAuth compliance validation.

## Compliance Scores
- **OIDC Core**: {oidc_score}% compliant
- **OAuth 2.0**: {oauth_score}% compliant  
- **OAuth 2.1**: {oauth21_score}% compliant

## Test Results

### Discovery Endpoint
- ✅ Works with underscore: {results["discovery_underscore"]}
- {"✅" if results["discovery_hyphen"] else "❌"} Works with hyphen (SPEC): {results["discovery_hyphen"]}

### Token Endpoint
- Endpoint URL: `{results["token_endpoint"]}`
- {"✅" if results["token_form_encoded"] else "❌"} Accepts form-encoded: {results["token_form_encoded"]}
- {"✅" if results["token_json"] else "❌"} Accepts JSON: {results["token_json"]}
- Error code: {results["token_error_code"]} {"✅" if results["token_error_code"] == 400 else "❌ (should be 400)"}

### Other Endpoints
- {"✅" if results["jwks_available"] else "❌"} JWKS available: {results["jwks_available"]}
- {"✅" if results["userinfo_available"] else "❌"} UserInfo available: {results["userinfo_available"]}
- {"✅" if results["authorization_redirect"] else "❌"} Authorization redirects: {results["authorization_redirect"]}

### Security Features
- {"✅" if results["pkce_required"] else "❌"} PKCE required: {results["pkce_required"]}

## Critical Issues for Certification
"""

    if critical_issues:
        for i, issue in enumerate(critical_issues, 1):
            report += f"{i}. **{issue}**\n"
    else:
        report += "✅ No critical issues found - ready for certification!\n"

    report += f"""
## Discovery Metadata Fields
Total fields: {len(results["discovery_fields"])}

Key fields present:
- issuer: {"✅" if "issuer" in results["discovery_fields"] else "❌"}
- authorization_endpoint: {"✅" if "authorization_endpoint" in results["discovery_fields"] else "❌"}
- token_endpoint: {"✅" if "token_endpoint" in results["discovery_fields"] else "❌"}
- jwks_uri: {"✅" if "jwks_uri" in results["discovery_fields"] else "❌"}
- userinfo_endpoint: {"✅" if "userinfo_endpoint" in results["discovery_fields"] else "❌"}
- scopes_supported: {"✅" if "scopes_supported" in results["discovery_fields"] else "❌"}
- response_types_supported: {"✅" if "response_types_supported" in results["discovery_fields"] else "❌"}

## Recommendations
"""

    if not results["discovery_hyphen"]:
        report += "1. **URGENT**: Fix discovery endpoint URL from underscore to hyphen\n"
    if not results["token_form_encoded"]:
        report += "2. **URGENT**: Update token endpoint to accept application/x-www-form-urlencoded\n"
    if results["token_error_code"] != 400:
        report += "3. **HIGH**: Fix token endpoint to return 400 for errors\n"
    if not results["authorization_redirect"]:
        report += "4. **HIGH**: Fix authorization endpoint to redirect with errors\n"

    report += f"""
## Test Command Used
```bash
cd /Users/oranheim/PycharmProjects/descoped/authly/tck
python scripts/generate-conformance-report.py
```

## Raw Test Results
```json
{json.dumps(results, indent=2)}
```

---
*Report v{version} generated automatically by conformance test suite*
"""

    # Save report
    reports_dir = Path(__file__).parent.parent / "conformance-reports"
    report_path = reports_dir / filename

    with open(report_path, "w") as f:
        f.write(report)

    print(f"✅ Report saved to: {report_path}")
    print(f"\n📊 Compliance Summary:")
    print(f"   OIDC Core: {oidc_score}%")
    print(f"   OAuth 2.0: {oauth_score}%")
    print(f"   OAuth 2.1: {oauth21_score}%")
    print(f"\n🚨 Critical Issues: {len(critical_issues)}")

    return report_path, len(critical_issues)


def main():
    """Main entry point"""
    tag = None
    if len(sys.argv) > 1:
        tag = sys.argv[1]

    version = get_next_version()
    print(f"📝 Generating Conformance Report v{version}")

    report_path, issues = generate_report(version, tag)

    # Update README index
    update_readme(version, issues)

    if issues == 0:
        print("\n🎉 Congratulations! No critical issues found.")
    else:
        print(f"\n⚠️  {issues} critical issue(s) need to be fixed for certification.")

    return 0 if issues == 0 else 1


def update_readme(version, issues):
    """Update the README with new report entry"""
    readme_path = Path(__file__).parent.parent / "conformance-reports" / "README.md"

    # This is simplified - in production you'd parse and update the table properly
    print(f"📝 Remember to update {readme_path} with v{version} results")


if __name__ == "__main__":
    sys.exit(main())
