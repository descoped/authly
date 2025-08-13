#!/usr/bin/env python3
"""
Full OIDC Conformance Suite Runner
Executes comprehensive certification tests using the OpenID Foundation conformance suite
"""

import requests
import json
import time
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ConformanceSuiteRunner:
    """Runs full OIDC conformance suite tests via API"""
    
    # Official test modules for different certification profiles
    TEST_MODULES = {
        "basic": [
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
        ],
        "pkce": [
            "oidcc-codereuse-30seconds",
            "oidcc-codereuse",
            "oidcc-ensure-pkce-required",
            "oidcc-ensure-pkce-code-verifier-required",
            "oidcc-ensure-pkce-code-challenge-method-s256",
            "oidcc-ensure-pkce-plain-not-supported",
            "oidcc-ensure-pkce-invalid-code-verifier",
            "oidcc-ensure-pkce-missing-code-verifier",
        ],
        "security": [
            "oidcc-ensure-pkce-required",
            "oidcc-codereuse-30seconds",
            "oidcc-codereuse",
            "oidcc-nonce-invalid",
            "oidcc-state-invalid",
            "oidcc-redirect-uri-query-added",
            "oidcc-redirect-uri-query-missing",
        ],
        "implicit": [
            "oidcc-implicit-flow-id-token",
            "oidcc-implicit-flow-id-token-token",
            "oidcc-implicit-flow-nonce-required",
        ],
        "hybrid": [
            "oidcc-hybrid-flow-code-id-token",
            "oidcc-hybrid-flow-code-token",
            "oidcc-hybrid-flow-code-id-token-token",
        ]
    }
    
    def __init__(self, suite_url: str = None, authly_url: str = None):
        """Initialize the conformance suite runner"""
        self.suite_url = suite_url or os.getenv("CONFORMANCE_SUITE_URL", "https://localhost:8443")
        self.authly_url = authly_url or os.getenv("AUTHLY_BASE_URL", "http://host.docker.internal:8000")
        self.session = requests.Session()
        self.session.verify = False  # Self-signed certificate
        self.reports_dir = Path(__file__).parent.parent / "reports" / "conformance-suite"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def check_suite_availability(self) -> bool:
        """Check if the conformance suite is running and accessible"""
        try:
            resp = self.session.get(f"{self.suite_url}/api/runner/available", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def check_authly_availability(self) -> bool:
        """Check if Authly is running and accessible"""
        try:
            resp = requests.get(f"{self.authly_url}/health", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def create_test_plan(self, config: dict[str, Any]) -> str | None:
        """Create a new test plan in the conformance suite"""
        try:
            # Update discovery URL with current Authly URL
            if "server" in config:
                config["server"]["discoveryUrl"] = f"{self.authly_url}/.well-known/openid-configuration"
            
            resp = self.session.post(
                f"{self.suite_url}/api/plan",
                json=config,
                timeout=30
            )
            
            if resp.status_code == 200:
                plan_data = resp.json()
                return plan_data.get("id")
            else:
                print(f"❌ Failed to create test plan: {resp.status_code}")
                print(f"   Response: {resp.text}")
                return None
        except Exception as e:
            print(f"❌ Error creating test plan: {e}")
            return None
    
    def run_test_module(self, plan_id: str, module: str) -> dict[str, Any]:
        """Run a specific test module"""
        try:
            # Start the test
            resp = self.session.post(
                f"{self.suite_url}/api/plan/{plan_id}/test/{module}/start",
                timeout=30
            )
            
            if resp.status_code != 200:
                return {
                    "status": "SKIPPED",
                    "message": f"Module not applicable or not found: {module}"
                }
            
            test_data = resp.json()
            test_id = test_data.get("id")
            
            if not test_id:
                return {
                    "status": "ERROR",
                    "message": "No test ID returned"
                }
            
            # Wait for test completion (max 60 seconds)
            start_time = time.time()
            while time.time() - start_time < 60:
                resp = self.session.get(
                    f"{self.suite_url}/api/plan/{plan_id}/test/{test_id}",
                    timeout=10
                )
                
                if resp.status_code == 200:
                    result = resp.json()
                    status = result.get("status", "UNKNOWN")
                    
                    if status in ["FINISHED", "FAILED", "WARNING", "INTERRUPTED"]:
                        return result
                
                time.sleep(1)
            
            return {
                "status": "TIMEOUT",
                "message": "Test execution timed out after 60 seconds"
            }
            
        except Exception as e:
            return {
                "status": "ERROR",
                "message": str(e)
            }
    
    def get_test_modules(self, config: dict[str, Any]) -> list[str]:
        """Get the list of test modules based on configuration"""
        # Check if specific modules are defined in config
        if "test_modules" in config:
            return config["test_modules"]
        
        # Otherwise, determine from test plan name
        test_plan = config.get("test_plan", "")
        
        if "basic" in test_plan:
            modules = self.TEST_MODULES["basic"].copy()
        elif "pkce" in test_plan:
            modules = self.TEST_MODULES["pkce"].copy()
        elif "security" in test_plan:
            modules = self.TEST_MODULES["security"].copy()
        elif "implicit" in test_plan:
            modules = self.TEST_MODULES["implicit"].copy()
        elif "hybrid" in test_plan:
            modules = self.TEST_MODULES["hybrid"].copy()
        else:
            # Default to basic certification
            modules = self.TEST_MODULES["basic"].copy()
        
        # Remove skipped modules if specified
        if "skip_test_modules" in config:
            skip_modules = config["skip_test_modules"]
            modules = [m for m in modules if m not in skip_modules]
        
        return modules
    
    def run_test_plan(self, config_file: str) -> dict[str, Any]:
        """Run a complete test plan from configuration file"""
        # Load configuration
        config_path = Path(config_file)
        if not config_path.exists():
            # Try relative to TCK directory
            config_path = Path(__file__).parent.parent / "config" / config_file
        
        if not config_path.exists():
            print(f"❌ Configuration file not found: {config_file}")
            return {"error": "Config file not found"}
        
        with open(config_path) as f:
            config = json.load(f)
        
        print(f"🚀 Running Test Plan: {config.get('description', 'Unknown')}")
        print(f"   Alias: {config.get('alias', 'Unknown')}")
        
        # Check services
        if not self.check_suite_availability():
            print("❌ Conformance suite is not accessible")
            print("   Run: make suite-start")
            return {"error": "Suite not available"}
        
        if not self.check_authly_availability():
            print("❌ Authly is not accessible")
            print("   Check that Authly is running")
            return {"error": "Authly not available"}
        
        # Create test plan
        plan_id = self.create_test_plan(config)
        if not plan_id:
            return {"error": "Failed to create test plan"}
        
        print(f"✅ Created test plan: {plan_id}")
        print(f"   View in UI: {self.suite_url}/plan-detail.html?plan={plan_id}")
        print("")
        
        # Get test modules
        modules = self.get_test_modules(config)
        print(f"📋 Running {len(modules)} test modules...")
        print("")
        
        # Run each module
        results = {
            "plan_id": plan_id,
            "config": config.get("alias", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "modules": {},
            "summary": {
                "total": len(modules),
                "passed": 0,
                "failed": 0,
                "warnings": 0,
                "skipped": 0,
                "errors": 0
            }
        }
        
        for i, module in enumerate(modules, 1):
            print(f"[{i}/{len(modules)}] Testing {module}...", end=" ")
            
            result = self.run_test_module(plan_id, module)
            status = result.get("status", "UNKNOWN")
            
            # Store result
            results["modules"][module] = {
                "status": status,
                "message": result.get("message", ""),
                "error": result.get("error", "")
            }
            
            # Update summary
            if status == "FINISHED":
                print("✅ PASSED")
                results["summary"]["passed"] += 1
            elif status == "WARNING":
                print("⚠️  WARNING")
                results["summary"]["warnings"] += 1
            elif status == "FAILED":
                print("❌ FAILED")
                results["summary"]["failed"] += 1
                if result.get("message"):
                    print(f"     → {result['message']}")
            elif status == "SKIPPED":
                print("⏭️  SKIPPED")
                results["summary"]["skipped"] += 1
            else:
                print(f"⚠️  {status}")
                results["summary"]["errors"] += 1
        
        # Calculate pass rate
        total_run = results["summary"]["total"] - results["summary"]["skipped"]
        if total_run > 0:
            pass_rate = (results["summary"]["passed"] / total_run) * 100
            results["summary"]["pass_rate"] = round(pass_rate, 1)
        else:
            results["summary"]["pass_rate"] = 0
        
        # Generate report
        self.generate_report(results)
        
        return results
    
    def generate_report(self, results: dict[str, Any]):
        """Generate a detailed test report"""
        summary = results["summary"]
        
        report = f"""# Conformance Suite Test Report

## Test Information
- **Configuration**: {results['config']}
- **Plan ID**: {results['plan_id']}
- **Timestamp**: {results['timestamp']}
- **Suite URL**: {self.suite_url}
- **Authly URL**: {self.authly_url}

## Results Summary
- **Total Modules**: {summary['total']}
- **Passed**: {summary['passed']} ✅
- **Failed**: {summary['failed']} ❌
- **Warnings**: {summary['warnings']} ⚠️
- **Skipped**: {summary['skipped']} ⏭️
- **Errors**: {summary['errors']} 🔥
- **Pass Rate**: {summary.get('pass_rate', 0)}%

## Detailed Results

| Module | Status | Details |
|--------|--------|---------|
"""
        
        for module, result in results["modules"].items():
            status_icon = {
                "FINISHED": "✅",
                "FAILED": "❌",
                "WARNING": "⚠️",
                "SKIPPED": "⏭️",
                "ERROR": "🔥",
                "TIMEOUT": "⏱️"
            }.get(result["status"], "❓")
            
            details = result.get("message", "") or result.get("error", "")
            if details:
                details = details.replace("\n", " ").replace("|", "\\|")[:100]
            
            report += f"| {module} | {status_icon} {result['status']} | {details} |\n"
        
        report += f"""

## View in Conformance Suite UI
[Open Test Plan Details]({self.suite_url}/plan-detail.html?plan={results['plan_id']})

## Next Steps
"""
        
        if summary["failed"] > 0:
            report += """
1. Review failed tests in the UI for detailed error messages
2. Check `make actionable` for specific fixes
3. Fix issues and re-run this test plan
"""
        elif summary["pass_rate"] == 100:
            report += """
🎉 **Perfect Score!** All tests passed.
Consider running additional test profiles for comprehensive coverage.
"""
        else:
            report += """
1. Review warnings in the UI for potential issues
2. Consider implementing skipped test modules
3. Run `make actionable` for improvement suggestions
"""
        
        # Save report
        report_file = self.reports_dir / f"suite-{results['config']}-{results['plan_id'][:8]}.md"
        with open(report_file, "w") as f:
            f.write(report)
        
        # Also save JSON results
        json_file = self.reports_dir / f"suite-{results['config']}-{results['plan_id'][:8]}.json"
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        
        print("")
        print("=" * 60)
        print(f"📊 Test Results Summary")
        print("=" * 60)
        print(f"Pass Rate: {summary.get('pass_rate', 0)}%")
        print(f"Status: {'✅ PASSED' if summary.get('pass_rate', 0) >= 90 else '❌ FAILED'}")
        print("")
        print(f"📄 Reports saved:")
        print(f"   - {report_file}")
        print(f"   - {json_file}")
        print("")
        print(f"🌐 View in UI: {self.suite_url}/plan-detail.html?plan={results['plan_id']}")


def main():
    """Main entry point for conformance suite testing"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python conformance_suite.py <config-file>")
        print("")
        print("Available configs:")
        print("  - conformance-basic.json    # Basic OIDC certification")
        print("  - conformance-pkce.json     # OAuth 2.1 PKCE certification")
        print("  - conformance-security.json # Security best practices")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    # Create runner
    runner = ConformanceSuiteRunner()
    
    # Run test plan
    results = runner.run_test_plan(config_file)
    
    # Exit with appropriate code
    if "error" in results:
        sys.exit(2)
    elif results["summary"].get("pass_rate", 0) < 90:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()