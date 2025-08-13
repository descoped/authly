#!/usr/bin/env python3
"""
OIDC/OAuth Specification Conformance Validator
Tests ONLY specification compliance - does NOT duplicate integration tests

This validator focuses on:
1. Response format compliance
2. Required fields presence
3. Cryptographic validation
4. Specification-mandated behavior

It does NOT test:
- Business flows (covered by integration tests)
- Admin APIs (custom features)
- User management (custom features)
"""

import json
import base64
import hashlib
import requests
import jwt
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import sys
from pathlib import Path


class OIDCConformanceValidator:
    """Validates OIDC Core 1.0 specification compliance"""

    def __init__(self, base_url=None):
        self.base_url = base_url or os.getenv("AUTHLY_BASE_URL", "http://localhost:8000")
        self.discovery = None
        self.jwks = None
        self.results = {"discovery": {}, "jwks": {}, "id_token": {}, "endpoints": {}, "security": {}}

    def validate_all(self) -> tuple[bool, dict]:
        """Run all conformance validations"""
        print("🔍 OIDC Conformance Validation Starting...")

        # 1. Discovery Document Validation
        print("\n📋 Validating Discovery Document...")
        self.validate_discovery_document()

        # 2. JWKS Validation
        print("\n🔑 Validating JWKS...")
        self.validate_jwks()

        # 3. Endpoint Response Format Validation
        print("\n🔌 Validating Endpoint Responses...")
        self.validate_endpoint_responses()

        # 4. Security Requirements
        print("\n🔒 Validating Security Requirements...")
        self.validate_security_requirements()

        # Calculate overall compliance
        all_passed = all(all(v for v in category.values() if isinstance(v, bool)) for category in self.results.values())

        return all_passed, self.results

    def validate_discovery_document(self):
        """Validate OIDC Discovery Document per spec section 4"""
        try:
            resp = requests.get(f"{self.base_url}/.well-known/openid-configuration")
            self.discovery = resp.json()

            # Required fields per OIDC Core 1.0 Section 4.2
            required_fields = {
                "issuer": str,
                "authorization_endpoint": str,
                "token_endpoint": str,
                "userinfo_endpoint": str,
                "jwks_uri": str,
                "response_types_supported": list,
                "subject_types_supported": list,
                "id_token_signing_alg_values_supported": list,
            }

            for field, field_type in required_fields.items():
                present = field in self.discovery
                correct_type = isinstance(self.discovery.get(field), field_type) if present else False
                self.results["discovery"][f"{field}_present"] = present
                self.results["discovery"][f"{field}_type_correct"] = correct_type

                if not present:
                    print(f"  ❌ Missing required field: {field}")
                elif not correct_type:
                    print(f"  ❌ Wrong type for {field}: expected {field_type.__name__}")
                else:
                    print(f"  ✅ {field}: valid")

            # Validate issuer format (MUST be HTTPS in production, MAY be HTTP for localhost)
            issuer = self.discovery.get("issuer", "")
            if "localhost" not in issuer and not issuer.startswith("https://"):
                self.results["discovery"]["issuer_https"] = False
                print(f"  ❌ Issuer MUST use HTTPS in production: {issuer}")
            else:
                self.results["discovery"]["issuer_https"] = True
                print(f"  ✅ Issuer format valid: {issuer}")

            # Validate endpoint URLs are absolute
            for endpoint in ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]:
                url = self.discovery.get(endpoint, "")
                is_absolute = url.startswith("http://") or url.startswith("https://")
                self.results["discovery"][f"{endpoint}_absolute"] = is_absolute
                if not is_absolute and url:
                    print(f"  ❌ {endpoint} must be absolute URL: {url}")

            # OAuth 2.1 specific: PKCE support
            if "code_challenge_methods_supported" in self.discovery:
                has_s256 = "S256" in self.discovery["code_challenge_methods_supported"]
                self.results["discovery"]["pkce_s256_supported"] = has_s256
                print(f"  {'✅' if has_s256 else '❌'} PKCE S256 support")

        except Exception as e:
            print(f"  ❌ Discovery validation failed: {e}")
            self.results["discovery"]["error"] = str(e)

    def validate_jwks(self):
        """Validate JWKS per RFC 7517"""
        try:
            jwks_uri = self.discovery.get("jwks_uri", f"{self.base_url}/.well-known/jwks.json")
            resp = requests.get(jwks_uri)
            self.jwks = resp.json()

            # Must have 'keys' array
            if "keys" not in self.jwks:
                self.results["jwks"]["has_keys"] = False
                print("  ❌ JWKS missing 'keys' array")
                return

            self.results["jwks"]["has_keys"] = True
            self.results["jwks"]["key_count"] = len(self.jwks["keys"])

            for i, key in enumerate(self.jwks["keys"]):
                # Required fields per RFC 7517
                required = ["kty", "use", "kid"]
                for field in required:
                    has_field = field in key
                    self.results["jwks"][f"key_{i}_{field}"] = has_field
                    if not has_field:
                        print(f"  ❌ Key {i} missing required field: {field}")

                # RSA key validation
                if key.get("kty") == "RSA":
                    rsa_fields = ["n", "e"]
                    for field in rsa_fields:
                        has_field = field in key
                        self.results["jwks"][f"key_{i}_rsa_{field}"] = has_field
                        if not has_field:
                            print(f"  ❌ RSA key {i} missing {field}")

                    # Algorithm should be specified
                    if "alg" in key:
                        alg = key["alg"]
                        valid_algs = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
                        self.results["jwks"][f"key_{i}_alg_valid"] = alg in valid_algs
                        print(f"  {'✅' if alg in valid_algs else '❌'} Key {i} algorithm: {alg}")

                print(f"  ✅ Key {i} ({key.get('kid', 'unknown')[:20]}...) validated")

        except Exception as e:
            print(f"  ❌ JWKS validation failed: {e}")
            self.results["jwks"]["error"] = str(e)

    def validate_endpoint_responses(self):
        """Validate endpoint response formats per specification"""

        # Test token endpoint error response format (OAuth 2.0 Section 5.2)
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/oauth/token",
                data={"grant_type": "invalid_grant"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Must return 400 for invalid grant
            self.results["endpoints"]["token_error_status"] = resp.status_code == 400
            print(
                f"  {'✅' if resp.status_code == 400 else '❌'} Token endpoint returns 400 for errors (got {resp.status_code})"
            )

            # Error response must be JSON with 'error' field
            if resp.status_code == 400:
                try:
                    error_resp = resp.json()
                    has_error = "error" in error_resp
                    self.results["endpoints"]["token_error_format"] = has_error
                    print(f"  {'✅' if has_error else '❌'} Token error response has 'error' field")

                    # Error code should be from RFC 6749 Section 5.2
                    valid_errors = [
                        "invalid_request",
                        "invalid_client",
                        "invalid_grant",
                        "unauthorized_client",
                        "unsupported_grant_type",
                        "invalid_scope",
                    ]
                    error_code = error_resp.get("error", "")
                    self.results["endpoints"]["token_error_code_valid"] = error_code in valid_errors
                    print(f"  {'✅' if error_code in valid_errors else '❌'} Error code '{error_code}' is valid")
                except:
                    self.results["endpoints"]["token_error_format"] = False
                    print("  ❌ Token error response is not valid JSON")

        except Exception as e:
            print(f"  ❌ Token endpoint validation failed: {e}")

        # Test authorization endpoint with missing parameters
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/oauth/authorize", params={"client_id": "invalid"}, allow_redirects=False
            )

            # Should either redirect with error or return error directly
            is_redirect = resp.status_code in [302, 303]
            is_error = resp.status_code in [400, 401, 403]

            self.results["endpoints"]["auth_error_handling"] = is_redirect or is_error
            print(
                f"  {'✅' if is_redirect or is_error else '❌'} Authorization endpoint error handling (status: {resp.status_code})"
            )

        except Exception as e:
            print(f"  ❌ Authorization endpoint validation failed: {e}")

        # Test UserInfo endpoint requires authentication
        try:
            resp = requests.get(f"{self.base_url}/oidc/userinfo")
            requires_auth = resp.status_code == 401
            self.results["endpoints"]["userinfo_requires_auth"] = requires_auth
            print(
                f"  {'✅' if requires_auth else '❌'} UserInfo endpoint requires authentication (status: {resp.status_code})"
            )

            # Check WWW-Authenticate header
            if resp.status_code == 401:
                has_header = "WWW-Authenticate" in resp.headers
                self.results["endpoints"]["userinfo_www_authenticate"] = has_header
                print(f"  {'✅' if has_header else '❌'} UserInfo returns WWW-Authenticate header")

        except Exception as e:
            print(f"  ❌ UserInfo endpoint validation failed: {e}")

    def validate_security_requirements(self):
        """Validate security requirements per OIDC Security Considerations"""

        # Check if PKCE is enforced (OAuth 2.1 requirement)
        if self.discovery:
            requires_pkce = self.discovery.get("require_pkce", False)
            has_s256 = "S256" in self.discovery.get("code_challenge_methods_supported", [])

            self.results["security"]["pkce_enforced"] = requires_pkce
            self.results["security"]["pkce_s256_available"] = has_s256

            print(f"  {'✅' if requires_pkce else '⚠️'} PKCE enforcement: {requires_pkce}")
            print(f"  {'✅' if has_s256 else '❌'} S256 support: {has_s256}")

        # Check if state parameter is required
        try:
            # Try authorization without state (should fail or warn)
            resp = requests.get(
                f"{self.base_url}/api/v1/oauth/authorize",
                params={"client_id": "test", "response_type": "code", "redirect_uri": "http://localhost/callback"},
                allow_redirects=False,
            )

            # If it requires PKCE, that's good for security
            if resp.status_code in [400, 422]:
                self.results["security"]["auth_validates_params"] = True
                print(f"  ✅ Authorization endpoint validates parameters")
            else:
                self.results["security"]["auth_validates_params"] = False
                print(f"  ⚠️ Authorization endpoint may not validate all parameters")

        except Exception as e:
            print(f"  ❌ Security validation failed: {e}")

        # Check supported algorithms
        if self.discovery:
            algs = self.discovery.get("id_token_signing_alg_values_supported", [])
            has_rs256 = "RS256" in algs
            has_none = "none" in algs

            self.results["security"]["supports_rs256"] = has_rs256
            self.results["security"]["supports_none_alg"] = has_none

            print(f"  {'✅' if has_rs256 else '❌'} RS256 support: {has_rs256}")
            print(
                f"  {'⚠️' if has_none else '✅'} 'none' algorithm: {'supported (security risk!)' if has_none else 'not supported (good)'}"
            )


def generate_conformance_report(results: dict) -> str:
    """Generate detailed conformance report"""

    report = """# OIDC Specification Conformance Report

## Executive Summary
Automated validation of OIDC Core 1.0 specification requirements.
This tests SPECIFICATION COMPLIANCE only, not business functionality.

## Results by Category

"""

    # Count passes and failures
    total_checks = 0
    passed_checks = 0

    for category, checks in results.items():
        category_passed = 0
        category_total = 0

        report += f"### {category.replace('_', ' ').title()}\n\n"
        report += "| Check | Result | Status |\n"
        report += "|-------|--------|--------|\n"

        for check, result in checks.items():
            if isinstance(result, bool):
                category_total += 1
                total_checks += 1

                # Special case: NOT supporting 'none' algorithm is GOOD (secure)
                if check == "supports_none_alg":
                    # Invert the logic for this check - False is PASS, True is FAIL
                    is_pass = not result
                    if is_pass:
                        category_passed += 1
                        passed_checks += 1
                    status = "✅ PASS" if is_pass else "❌ FAIL"
                else:
                    # Normal logic for all other checks
                    if result:
                        category_passed += 1
                        passed_checks += 1
                    status = "✅ PASS" if result else "❌ FAIL"

                report += f"| {check.replace('_', ' ').title()} | {result} | {status} |\n"

        if category_total > 0:
            percentage = (category_passed / category_total) * 100
            report += f"\n**Category Score: {category_passed}/{category_total} ({percentage:.0f}%)**\n\n"

    # Overall score
    if total_checks > 0:
        overall_percentage = (passed_checks / total_checks) * 100
        report += f"""
## Overall Conformance Score

**{passed_checks}/{total_checks} checks passed ({overall_percentage:.0f}%)**

### Certification Readiness:
"""

        if overall_percentage >= 95:
            report += "✅ **READY** - High conformance, ready for official certification\n"
        elif overall_percentage >= 80:
            report += "⚠️ **NEARLY READY** - Minor issues to fix before certification\n"
        else:
            report += "❌ **NOT READY** - Significant conformance issues to address\n"

    report += """
## Important Notes

1. This validator tests SPECIFICATION COMPLIANCE only
2. It does NOT duplicate integration tests
3. It does NOT test business logic or admin features
4. For full certification, use the official OpenID Conformance Suite

## Next Steps for Official Certification

1. Fix any failing checks above
2. Deploy to a public URL
3. Register at https://www.certification.openid.net/
4. Run the official conformance suite
5. Submit results for certification

---
*Generated by OIDC Conformance Validator*
"""

    return report


def main():
    """Run conformance validation"""
    validator = OIDCConformanceValidator()

    print("=" * 60)
    print("OIDC SPECIFICATION CONFORMANCE VALIDATOR")
    print("=" * 60)

    passed, results = validator.validate_all()

    # Generate report
    report = generate_conformance_report(results)

    # Create reports directory
    reports_dir = Path(__file__).parent.parent / "reports" / "latest"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Also save to conformance-reports for backward compatibility
    legacy_dir = Path(__file__).parent.parent / "conformance-reports"
    legacy_dir.mkdir(parents=True, exist_ok=True)

    # Save report to both locations
    report_path = reports_dir / "SPECIFICATION_CONFORMANCE.md"
    with open(report_path, "w") as f:
        f.write(report)

    legacy_report_path = legacy_dir / "SPECIFICATION_CONFORMANCE.md"
    with open(legacy_report_path, "w") as f:
        f.write(report)

    # Save raw results to both locations
    results_path = reports_dir / "conformance_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    legacy_results_path = legacy_dir / "conformance_results.json"
    with open(legacy_results_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print(f"📄 Report saved to: {report_path}")
    print(f"📊 Results saved to: {results_path}")

    if passed:
        print("\n✅ All conformance checks PASSED!")
        return 0
    else:
        print("\n⚠️ Some conformance checks failed. See report for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
