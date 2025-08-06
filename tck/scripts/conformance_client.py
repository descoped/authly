#!/usr/bin/env python3
"""
Advanced OIDC Conformance Test Client
Uses the conformance suite API to run comprehensive test plans
"""

import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import urllib3

# Disable SSL warnings for local testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ConformanceClient:
    """Client for interacting with the OpenID conformance suite"""

    def __init__(self, base_url: str = "https://localhost:8443"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    def create_test_plan(self, config: dict[str, Any]) -> str | None:
        """Create a test plan"""
        response = self.session.post(f"{self.base_url}/api/plan", json=config)

        if response.status_code == 201:
            plan_data = response.json()
            return plan_data.get("_id")
        else:
            logger.error(f"Failed to create test plan: {response.status_code}")
            logger.error(response.text)
            return None

    def create_test(self, test_name: str, config: dict[str, Any]) -> str | None:
        """Create a test instance"""
        payload = {"test": test_name, "variant": config.get("variant", {}), "config": config.get("config", {})}

        response = self.session.post(f"{self.base_url}/api/runner", json=payload)

        if response.status_code == 201:
            test_data = response.json()
            return test_data.get("id")
        else:
            logger.error(f"Failed to create test {test_name}: {response.status_code}")
            logger.error(response.text)
            return None

    def start_test(self, test_id: str) -> bool:
        """Start a test"""
        response = self.session.post(f"{self.base_url}/api/runner/{test_id}/start")
        return response.status_code == 200

    def get_test_status(self, test_id: str) -> dict[str, Any]:
        """Get test status"""
        response = self.session.get(f"{self.base_url}/api/runner/{test_id}")

        if response.status_code == 200:
            return response.json()
        return {}

    def get_test_logs(self, test_id: str) -> list[dict[str, Any]]:
        """Get test logs"""
        response = self.session.get(f"{self.base_url}/api/log/{test_id}")

        if response.status_code == 200:
            return response.json()
        return []

    def wait_for_test_completion(self, test_id: str, timeout: int = 120) -> dict[str, Any]:
        """Wait for a test to complete"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_test_status(test_id)
            test_status = status.get("status")

            if test_status in ["FINISHED", "INTERRUPTED", "FAILED"]:
                return status

            time.sleep(2)

        logger.warning(f"Test {test_id} timed out after {timeout} seconds")
        return {"status": "TIMEOUT", "result": "TIMEOUT"}


class TestPlanRunner:
    """Runs test plans from configuration files"""

    def __init__(self, client: ConformanceClient, authly_url: str = "http://localhost:8000"):
        self.client = client
        self.authly_url = authly_url
        self.results = []

    def load_test_plan(self, plan_file: str) -> dict[str, Any]:
        """Load a test plan from JSON file"""
        plan_path = Path(plan_file)
        if not plan_path.exists():
            # Try in config directory
            plan_path = Path(__file__).parent.parent / "config" / "test-plans" / plan_file
            if not plan_path.suffix:
                plan_path = plan_path.with_suffix(".json")

        with open(plan_path) as f:
            return json.load(f)

    def run_test_plan(self, plan_config: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all tests in a test plan"""
        plan_name = plan_config.get("name", "Unknown Plan")
        logger.info(f"Running test plan: {plan_name}")

        results = []
        test_modules = plan_config.get("test_modules", [])

        for test_module in test_modules:
            test_name = test_module.get("name")
            description = test_module.get("description", "")
            required = test_module.get("required", False)

            logger.info(f"Running test: {test_name} - {description}")

            # Prepare test configuration
            test_config = self.prepare_test_config(plan_config, test_module)

            # Create and run test
            test_id = self.client.create_test(test_name, test_config)

            if not test_id:
                result = {
                    "test": test_name,
                    "description": description,
                    "required": required,
                    "status": "ERROR",
                    "result": "FAILED",
                    "error": "Failed to create test",
                }
            else:
                # Start test
                if self.client.start_test(test_id):
                    # Wait for completion
                    status = self.client.wait_for_test_completion(test_id)

                    result = {
                        "test": test_name,
                        "description": description,
                        "required": required,
                        "status": status.get("status"),
                        "result": status.get("result"),
                        "test_id": test_id,
                    }

                    # Get logs for failed tests
                    if result["result"] in ["FAILED", "WARNING"]:
                        logs = self.client.get_test_logs(test_id)
                        result["logs"] = self.analyze_logs(logs)
                else:
                    result = {
                        "test": test_name,
                        "description": description,
                        "required": required,
                        "status": "ERROR",
                        "result": "FAILED",
                        "error": "Failed to start test",
                    }

            results.append(result)
            logger.info(f"Test {test_name} result: {result['result']}")

            # Short delay between tests
            time.sleep(1)

        return results

    def prepare_test_config(self, plan_config: dict[str, Any], test_module: dict[str, Any]) -> dict[str, Any]:
        """Prepare configuration for a specific test"""
        client_config = plan_config.get("client", {})
        server_config = plan_config.get("server", {})
        test_configuration = plan_config.get("test_configuration", {})

        # Override with test-specific configuration if provided
        test_overrides = test_module.get("configuration", {})

        return {
            "variant": {**test_configuration, **test_overrides.get("variant", {})},
            "config": {
                "client": {**client_config, **test_overrides.get("client", {})},
                "server": {**server_config, **test_overrides.get("server", {})},
            },
        }

    def analyze_logs(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze test logs to extract key information"""
        errors = []
        warnings = []

        for log in logs:
            if log.get("result") == "FAILURE":
                errors.append({"message": log.get("msg", ""), "details": log.get("requirements", [])})
            elif log.get("result") == "WARNING":
                warnings.append({"message": log.get("msg", ""), "details": log.get("requirements", [])})

        return {"errors": errors, "warnings": warnings, "total_logs": len(logs)}

    def generate_report(self, results: list[dict[str, Any]], plan_name: str = "OIDC Conformance") -> str:
        """Generate a detailed test report"""
        timestamp = datetime.now().isoformat()

        # Statistics
        total = len(results)
        passed = sum(1 for r in results if r["result"] == "PASSED")
        failed = sum(1 for r in results if r["result"] == "FAILED")
        warnings = sum(1 for r in results if r["result"] == "WARNING")
        required_passed = sum(1 for r in results if r["required"] and r["result"] == "PASSED")
        required_total = sum(1 for r in results if r["required"])

        pass_rate = (passed / total * 100) if total > 0 else 0
        required_pass_rate = (required_passed / required_total * 100) if required_total > 0 else 0

        report = f"""# {plan_name} Test Report

**Generated**: {timestamp}
**Conformance Suite**: {self.client.base_url}
**Authly Server**: {self.authly_url}

## Executive Summary

- **Total Tests**: {total}
- **Passed**: {passed} ({pass_rate:.1f}%)
- **Failed**: {failed}
- **Warnings**: {warnings}
- **Required Tests Pass Rate**: {required_pass_rate:.1f}% ({required_passed}/{required_total})

## Compliance Status

"""

        if required_pass_rate == 100:
            report += "✅ **COMPLIANT** - All required tests passed\n"
        elif required_pass_rate >= 90:
            report += "⚠️ **MOSTLY COMPLIANT** - Most required tests passed, minor issues to address\n"
        else:
            report += "❌ **NON-COMPLIANT** - Significant issues need to be resolved\n"

        report += """
## Test Results

| Test | Description | Required | Result |
|------|-------------|----------|--------|
"""

        for result in results:
            test_name = result["test"]
            description = result["description"]
            required = "Yes" if result["required"] else "No"
            test_result = result["result"]

            # Result emoji
            if test_result == "PASSED":
                emoji = "✅"
            elif test_result == "FAILED":
                emoji = "❌"
            elif test_result == "WARNING":
                emoji = "⚠️"
            else:
                emoji = "❓"

            report += f"| {test_name} | {description} | {required} | {test_result} {emoji} |\n"

        # Add detailed failure analysis
        failed_tests = [r for r in results if r["result"] == "FAILED"]
        if failed_tests:
            report += "\n## Failed Test Analysis\n\n"

            for test in failed_tests:
                report += f"### {test['test']}\n\n"
                report += f"**Description**: {test['description']}\n"
                report += f"**Required**: {'Yes' if test['required'] else 'No'}\n\n"

                if "error" in test:
                    report += f"**Error**: {test['error']}\n\n"

                if "logs" in test and test["logs"].get("errors"):
                    report += "**Error Details**:\n"
                    for error in test["logs"]["errors"]:
                        report += f"- {error['message']}\n"
                        for detail in error.get("details", []):
                            report += f"  - {detail}\n"
                    report += "\n"

        # Add recommendations
        report += "\n## Recommendations\n\n"

        if failed > 0:
            report += "### High Priority (Failed Tests)\n\n"
            for test in failed_tests:
                if test["required"]:
                    report += f"- **{test['test']}**: {test['description']}\n"

        if warnings > 0:
            report += "\n### Medium Priority (Warnings)\n\n"
            warning_tests = [r for r in results if r["result"] == "WARNING"]
            for test in warning_tests:
                report += f"- **{test['test']}**: {test['description']}\n"

        if required_pass_rate == 100 and pass_rate == 100:
            report += "### Certification Ready\n\n"
            report += "✅ All tests passed! The implementation is ready for OpenID certification.\n"

        return report


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Run OIDC conformance tests")
    parser.add_argument("--plan", default="basic-certification.json", help="Test plan configuration file")
    parser.add_argument("--conformance-url", default="https://localhost:8443", help="Conformance suite URL")
    parser.add_argument("--authly-url", default="http://localhost:8000", help="Authly server URL")
    parser.add_argument("--output", help="Output file for the report")

    args = parser.parse_args()

    # Initialize client
    client = ConformanceClient(args.conformance_url)
    runner = TestPlanRunner(client, args.authly_url)

    # Load and run test plan
    try:
        plan_config = runner.load_test_plan(args.plan)
        results = runner.run_test_plan(plan_config)

        # Generate report
        plan_name = plan_config.get("name", "OIDC Conformance")
        report = runner.generate_report(results, plan_name)

        # Save report
        if args.output:
            output_path = Path(args.output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"conformance_report_{timestamp}.md")

        output_path.write_text(report)
        logger.info(f"Report saved to: {output_path}")

        # Print report
        print("\n" + "=" * 80)
        print(report)
        print("=" * 80)

        # Exit with appropriate code
        required_failed = sum(1 for r in results if r["required"] and r["result"] == "FAILED")
        return 0 if required_failed == 0 else 1

    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
