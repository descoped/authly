#!/usr/bin/env python3
"""
Automated OIDC Conformance Test Runner for Authly
Runs conformance tests using the OpenID Foundation conformance suite API
"""

import sys
import time
from datetime import datetime

import requests
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ConformanceTestRunner:
    """Automates running OIDC conformance tests against Authly"""

    def __init__(
        self,
        conformance_url: str = "https://localhost:9443",
        authly_url: str = "http://localhost:8000",
        client_id: str = "oidc-conformance-test",
        client_secret: str = "conformance-test-secret",
    ):
        self.conformance_url = conformance_url
        self.authly_url = authly_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for local testing

    def wait_for_services(self, max_attempts: int = 30) -> bool:
        """Wait for conformance suite and Authly to be ready"""
        print("⏳ Waiting for services to be ready...")

        for attempt in range(max_attempts):
            try:
                # Check conformance suite
                conf_response = self.session.get(f"{self.conformance_url}/api/runner/available")
                if conf_response.status_code != 200:
                    raise Exception("Conformance suite not ready")

                # Check Authly
                authly_response = requests.get(f"{self.authly_url}/.well-known/openid-configuration")
                if authly_response.status_code != 200:
                    raise Exception("Authly not ready")

                print("✅ Services are ready")
                return True

            except Exception as e:
                if attempt < max_attempts - 1:
                    time.sleep(2)
                else:
                    print(f"❌ Services not ready after {max_attempts} attempts: {e}")
                    return False

        return False

    def create_test_plan(self, plan_name: str, test_module: str) -> str | None:
        """Create a test plan in the conformance suite"""
        print(f"\n📋 Creating test plan: {plan_name}")

        # Test plan configuration
        config = {
            "alias": plan_name,
            "description": f"Automated test plan for {test_module}",
            "publish": "private",
            "test_modules": [test_module],
            "variant": {
                "server_metadata": "discovery",
                "client_auth_type": "client_secret_basic",
                "response_type": "code",
                "response_mode": "query",
                "jwks_uri": "no",
                "request_object_method": "none",
            },
            "test_configuration": {
                "alias": plan_name,
                "description": f"Test configuration for {plan_name}",
                "client": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "openid profile email",
                    "jwks": {"keys": []},
                },
                "server": {"discoveryUrl": f"{self.authly_url}/.well-known/openid-configuration"},
                "browser": {
                    "ignore_browser": True  # Run without browser interaction
                },
            },
        }

        response = self.session.post(
            f"{self.conformance_url}/api/plan", json=config, headers={"Content-Type": "application/json"}
        )

        if response.status_code == 201:
            plan_id = response.json().get("_id")
            print(f"✅ Test plan created: {plan_id}")
            return plan_id
        else:
            print(f"❌ Failed to create test plan: {response.status_code} - {response.text}")
            return None

    def run_test_module(self, module_name: str, config: dict) -> dict:
        """Run a specific test module"""
        print(f"\n🧪 Running test module: {module_name}")

        # Create test instance
        response = self.session.post(
            f"{self.conformance_url}/api/runner",
            json={
                "test": module_name,
                "variant": config.get("variant", {}),
                "config": config.get("test_configuration", {}),
            },
        )

        if response.status_code != 201:
            return {"module": module_name, "status": "error", "error": f"Failed to create test: {response.text}"}

        test_id = response.json().get("id")
        print(f"   Test ID: {test_id}")

        # Start the test
        self.session.post(f"{self.conformance_url}/api/runner/{test_id}/start")

        # Poll for test completion
        max_attempts = 60
        for _attempt in range(max_attempts):
            time.sleep(2)

            status_response = self.session.get(f"{self.conformance_url}/api/runner/{test_id}")
            if status_response.status_code != 200:
                continue

            status = status_response.json()
            test_status = status.get("status")

            if test_status in ["FINISHED", "INTERRUPTED"]:
                result = status.get("result", "UNKNOWN")
                print(f"   Result: {result}")

                # Get detailed logs
                logs_response = self.session.get(f"{self.conformance_url}/api/log/{test_id}")
                logs = logs_response.json() if logs_response.status_code == 200 else []

                return {
                    "module": module_name,
                    "status": test_status,
                    "result": result,
                    "test_id": test_id,
                    "logs": logs,
                }

        return {"module": module_name, "status": "timeout", "error": "Test did not complete within timeout"}

    def run_basic_certification_tests(self) -> list[dict]:
        """Run the basic OIDC certification test suite"""
        print("\n🎯 Running Basic OIDC Certification Tests")
        print("=" * 50)

        # Basic certification test modules

        # Simplified test modules for initial testing
        basic_tests = [
            {"name": "oidcc-server", "description": "Basic OIDC server configuration validation"},
            {"name": "oidcc-discovery-issuer-not-matching-config", "description": "Discovery endpoint validation"},
            {
                "name": "oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
                "description": "Authorization code flow without nonce",
            },
            {"name": "oidcc-ensure-registered-redirect-uri", "description": "Redirect URI validation"},
            {"name": "oidcc-userinfo-get", "description": "UserInfo endpoint GET request"},
            {"name": "oidcc-userinfo-post-header", "description": "UserInfo endpoint POST with Bearer header"},
        ]

        results = []

        # Common test configuration
        config = {
            "variant": {
                "server_metadata": "discovery",
                "client_auth_type": "client_secret_basic",
                "response_type": "code",
                "response_mode": "query",
            },
            "test_configuration": {
                "client": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "openid profile email",
                    "redirect_uri": f"{self.conformance_url}/test/a/authly/callback",
                },
                "server": {"discoveryUrl": f"{self.authly_url}/.well-known/openid-configuration"},
            },
        }

        for test in basic_tests:
            result = self.run_test_module(test["name"], config)
            result["description"] = test["description"]
            results.append(result)

            # Add delay between tests
            time.sleep(2)

        return results

    def generate_report(self, results: list[dict]) -> str:
        """Generate a conformance test report"""
        timestamp = datetime.now().isoformat()

        # Count results
        passed = sum(1 for r in results if r.get("result") == "PASSED")
        failed = sum(1 for r in results if r.get("result") == "FAILED")
        warnings = sum(1 for r in results if r.get("result") == "WARNING")
        errors = sum(1 for r in results if r.get("status") == "error" or r.get("status") == "timeout")

        total = len(results)
        pass_rate = (passed / total * 100) if total > 0 else 0

        report = f"""# OIDC Conformance Test Report

**Generated**: {timestamp}
**Authly URL**: {self.authly_url}
**Conformance Suite**: {self.conformance_url}

## Summary

- **Total Tests**: {total}
- **Passed**: {passed} ✅
- **Failed**: {failed} ❌
- **Warnings**: {warnings} ⚠️
- **Errors**: {errors} 🔥
- **Pass Rate**: {pass_rate:.1f}%

## Test Results

| Test Module | Description | Result | Status |
|------------|-------------|---------|---------|
"""

        for result in results:
            module = result.get("module", "Unknown")
            description = result.get("description", "")
            test_result = result.get("result", "N/A")
            status = result.get("status", "N/A")

            # Add emoji for result
            if test_result == "PASSED":
                emoji = "✅"
            elif test_result == "FAILED":
                emoji = "❌"
            elif test_result == "WARNING":
                emoji = "⚠️"
            else:
                emoji = "❓"

            report += f"| {module} | {description} | {test_result} {emoji} | {status} |\n"

        # Add detailed errors for failed tests
        failed_tests = [r for r in results if r.get("result") == "FAILED" or r.get("status") == "error"]
        if failed_tests:
            report += "\n## Failed Test Details\n\n"
            for test in failed_tests:
                report += f"### {test.get('module', 'Unknown')}\n"
                if test.get("error"):
                    report += f"**Error**: {test['error']}\n\n"
                # Could add log analysis here if needed

        # Add recommendations
        report += "\n## Recommendations\n\n"
        if failed > 0:
            report += "- Fix failed tests to achieve OIDC compliance\n"
            report += "- Review error logs for specific issues\n"
        if warnings > 0:
            report += "- Address warnings to improve implementation\n"
        if pass_rate == 100:
            report += "- ✅ All tests passed! Ready for certification\n"

        return report

    def save_report(self, report: str, filename: str = None):
        """Save the report to a file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"conformance_report_{timestamp}.md"

        filepath = f"/Users/oranheim/PycharmProjects/descoped/authly/tck/results/{filename}"

        # Ensure results directory exists
        import os

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w") as f:
            f.write(report)

        print(f"\n📄 Report saved to: {filepath}")
        return filepath


def main():
    """Main function to run conformance tests"""
    print("🚀 OIDC Conformance Test Automation")
    print("=" * 50)

    runner = ConformanceTestRunner()

    # Wait for services
    if not runner.wait_for_services():
        print("❌ Services not ready. Please ensure Docker containers are running.")
        sys.exit(1)

    # Run basic certification tests
    results = runner.run_basic_certification_tests()

    # Generate report
    report = runner.generate_report(results)

    # Save report
    runner.save_report(report)

    # Print summary
    print("\n" + "=" * 50)
    print("📊 Test Execution Complete")
    print("=" * 50)

    # Print report to console
    print(report)

    # Exit with appropriate code
    failed_count = sum(1 for r in results if r.get("result") == "FAILED" or r.get("status") == "error")
    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()
