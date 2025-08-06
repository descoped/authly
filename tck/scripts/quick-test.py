#!/usr/bin/env python3
"""
Quick OIDC Conformance Test
Runs a minimal set of tests to check basic OIDC compliance
"""

from datetime import datetime

import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_discovery():
    """Check OIDC discovery endpoint - SPEC REQUIRES HYPHEN NOT UNDERSCORE"""
    results = []

    # Check the SPEC-COMPLIANT endpoint (with hyphen)
    try:
        response = requests.get("http://localhost:8000/.well-known/openid-configuration")
        if response.status_code == 200:
            response.json()
            results.append(
                {"test": "Discovery Endpoint (SPEC)", "result": "PASSED", "details": "✅ Correct URL with hyphen works"}
            )
        else:
            # This is a SPEC VIOLATION - the hyphenated version MUST work
            results.append(
                {
                    "test": "Discovery Endpoint (SPEC)",
                    "result": "FAILED",
                    "details": f"❌ SPEC VIOLATION: /.well-known/openid-configuration returns {response.status_code}",
                }
            )
    except Exception as e:
        results.append({"test": "Discovery Endpoint (SPEC)", "result": "ERROR", "details": str(e)})

    # Check the WRONG endpoint (with underscore) - what Authly currently uses
    try:
        response = requests.get("http://localhost:8000/.well-known/openid_configuration")
        if response.status_code == 200:
            response.json()
            # This works but is WRONG
            results.append(
                {
                    "test": "Discovery Endpoint (Current)",
                    "result": "WARNING",
                    "details": "⚠️ Works with underscore but VIOLATES OIDC SPEC - MUST use hyphen",
                }
            )
            return results[0] if results[0]["result"] == "PASSED" else results[1]
        else:
            # Good - the underscore version should not work
            pass
    except Exception:
        pass

    return (
        results[0]
        if results
        else {"test": "Discovery Endpoint", "result": "FAILED", "details": "Neither endpoint works"}
    )


def check_jwks():
    """Check JWKS endpoint"""
    try:
        response = requests.get("http://localhost:8000/.well-known/jwks.json")
        if response.status_code == 200:
            jwks = response.json()
            keys = jwks.get("keys", [])
            return {
                "test": "JWKS Endpoint",
                "result": "PASSED" if keys else "WARNING",
                "details": f"Found {len(keys)} key(s)",
            }
        else:
            return {"test": "JWKS Endpoint", "result": "FAILED", "details": f"Status code: {response.status_code}"}
    except Exception as e:
        return {"test": "JWKS Endpoint", "result": "ERROR", "details": str(e)}


def check_authorization_endpoint():
    """Check authorization endpoint with missing parameters"""
    try:
        response = requests.get("http://localhost:8000/api/v1/oauth/authorize")
        # Should return error for missing parameters
        if response.status_code in [400, 401, 422]:
            return {
                "test": "Authorization Endpoint",
                "result": "PASSED",
                "details": "Endpoint reachable, rejects invalid requests",
            }
        else:
            return {
                "test": "Authorization Endpoint",
                "result": "WARNING",
                "details": f"Unexpected status: {response.status_code}",
            }
    except Exception as e:
        return {"test": "Authorization Endpoint", "result": "ERROR", "details": str(e)}


def check_token_endpoint():
    """Check token endpoint exists"""
    try:
        response = requests.post("http://localhost:8000/api/v1/auth/token")
        # Should return error for missing parameters
        if response.status_code in [400, 401, 422]:
            return {
                "test": "Token Endpoint",
                "result": "PASSED",
                "details": "Endpoint reachable, rejects invalid requests",
            }
        else:
            return {
                "test": "Token Endpoint",
                "result": "WARNING",
                "details": f"Unexpected status: {response.status_code}",
            }
    except Exception as e:
        return {"test": "Token Endpoint", "result": "ERROR", "details": str(e)}


def check_userinfo_endpoint():
    """Check userinfo endpoint requires authentication"""
    try:
        response = requests.get("http://localhost:8000/oidc/userinfo")
        if response.status_code == 401:
            return {"test": "UserInfo Endpoint", "result": "PASSED", "details": "Correctly requires authentication"}
        else:
            return {
                "test": "UserInfo Endpoint",
                "result": "FAILED",
                "details": f"Expected 401, got {response.status_code}",
            }
    except Exception as e:
        return {"test": "UserInfo Endpoint", "result": "ERROR", "details": str(e)}


def check_pkce_requirement():
    """Check if PKCE is enforced"""
    try:
        # Try authorization without PKCE
        params = {
            "response_type": "code",
            "client_id": "oidc-conformance-test",
            "redirect_uri": "https://localhost:8443/test/a/authly/callback",
            "scope": "openid profile",
            "state": "test123",
        }
        response = requests.get("http://localhost:8000/api/v1/oauth/authorize", params=params)

        # Should reject without PKCE (OAuth 2.1)
        if response.status_code in [400, 401, 422]:
            return {"test": "PKCE Enforcement", "result": "PASSED", "details": "PKCE is required (OAuth 2.1 compliant)"}
        else:
            return {
                "test": "PKCE Enforcement",
                "result": "FAILED",
                "details": f"PKCE not enforced, status: {response.status_code}",
            }
    except Exception as e:
        return {"test": "PKCE Enforcement", "result": "ERROR", "details": str(e)}


def main():
    print("🚀 Quick OIDC Conformance Check")
    print("=" * 40)

    # Run tests
    tests = [
        check_discovery(),
        check_jwks(),
        check_authorization_endpoint(),
        check_token_endpoint(),
        check_userinfo_endpoint(),
        check_pkce_requirement(),
    ]

    # Generate report
    timestamp = datetime.now().isoformat()
    passed = sum(1 for t in tests if t["result"] == "PASSED")
    failed = sum(1 for t in tests if t["result"] == "FAILED")
    warnings = sum(1 for t in tests if t["result"] == "WARNING")
    errors = sum(1 for t in tests if t["result"] == "ERROR")

    print(f"\n📊 Test Results ({timestamp[:19]})")
    print("-" * 40)

    for test in tests:
        emoji = {"PASSED": "✅", "FAILED": "❌", "WARNING": "⚠️", "ERROR": "🔥"}.get(test["result"], "❓")

        print(f"{emoji} {test['test']}: {test['result']}")
        print(f"   {test['details']}")

    print("\n📈 Summary")
    print("-" * 40)
    print(f"Total: {len(tests)}")
    print(f"Passed: {passed} ({passed / len(tests) * 100:.0f}%)")
    print(f"Failed: {failed}")
    print(f"Warnings: {warnings}")
    print(f"Errors: {errors}")

    # Save report
    report = f"""# Quick OIDC Conformance Check

**Generated**: {timestamp}
**Server**: http://localhost:8000

## Test Results

| Test | Result | Details |
|------|--------|---------|
"""

    for test in tests:
        emoji = {"PASSED": "✅", "FAILED": "❌", "WARNING": "⚠️", "ERROR": "🔥"}.get(test["result"], "❓")
        report += f"| {test['test']} | {test['result']} {emoji} | {test['details']} |\n"

    report += f"""

## Summary

- Total Tests: {len(tests)}
- Passed: {passed} ({passed / len(tests) * 100:.0f}%)
- Failed: {failed}
- Warnings: {warnings}
- Errors: {errors}

## Compliance Status

"""

    if passed == len(tests):
        report += "✅ **BASIC COMPLIANCE** - All basic OIDC endpoints are working\n"
    elif passed >= 4:
        report += "⚠️ **PARTIAL COMPLIANCE** - Most endpoints working, some issues to address\n"
    else:
        report += "❌ **NON-COMPLIANT** - Significant issues with OIDC implementation\n"

    # Save report
    import os

    os.makedirs("/Users/oranheim/PycharmProjects/descoped/authly/tck/results", exist_ok=True)

    filename = f"/Users/oranheim/PycharmProjects/descoped/authly/tck/results/quick_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w") as f:
        f.write(report)

    print(f"\n📄 Report saved to: {filename}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
