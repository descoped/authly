#!/usr/bin/env python3
"""
Generate comprehensive test summary combining all TCK test results
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


class TestSummaryGenerator:
    """Generate comprehensive test summary from all test results"""

    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.reports_path = self.base_path / "reports"
        self.summary = {
            "generated": datetime.now().isoformat(),
            "spec_compliance": {},
            "test_plans": {},
            "api_coverage": {},
            "overall_status": {},
        }

    def load_spec_compliance(self) -> dict[str, Any]:
        """Load specification compliance results"""
        try:
            with open(self.reports_path / "latest" / "conformance_results.json") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def load_test_plan_results(self) -> dict[str, Any]:
        """Load test plan results"""
        results = {}
        # Test plans are in reports/test-plans, not reports/latest/test-plans
        test_plans_dir = self.base_path / "reports" / "test-plans"

        if test_plans_dir.exists():
            for report_file in test_plans_dir.glob("*report.md"):
                plan_name = report_file.stem.replace("_report", "")
                with open(report_file) as f:
                    content = f.read()
                    # Extract summary metrics from markdown
                    for line in content.split("\n"):
                        if "**Pass Rate**:" in line:
                            rate = line.split(":")[-1].strip()
                            results[plan_name] = {"pass_rate": rate}
                        elif "**Total Tests**:" in line:
                            total = line.split(":")[-1].strip().split()[0]
                            results.setdefault(plan_name, {})["total"] = total
                        elif "**Passed**:" in line:
                            # Extract number before emoji
                            parts = line.split(":")[-1].strip().split()
                            if parts:
                                passed = parts[0]
                                results.setdefault(plan_name, {})["passed"] = passed
                        elif "**Failed**:" in line:
                            # Extract number before emoji
                            parts = line.split(":")[-1].strip().split()
                            if parts:
                                failed = parts[0]
                                results.setdefault(plan_name, {})["failed"] = failed
                        elif "**Skipped**:" in line:
                            # Extract number before emoji
                            parts = line.split(":")[-1].strip().split()
                            if parts:
                                skipped = parts[0]
                                results.setdefault(plan_name, {})["skipped"] = skipped

        return results

    def load_api_matrix(self) -> dict[str, Any]:
        """Load API matrix data"""
        try:
            with open(self.reports_path / "latest" / "api_matrix.json") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def calculate_overall_metrics(self) -> dict[str, Any]:
        """Calculate overall test metrics"""
        spec_data = self.load_spec_compliance()
        test_plans = self.load_test_plan_results()
        api_data = self.load_api_matrix()

        # Count spec compliance
        spec_passed = 0
        spec_total = 0
        for category in spec_data.values():
            if isinstance(category, dict):
                for _test, result in category.items():
                    if isinstance(result, bool):
                        spec_total += 1
                        if result:
                            spec_passed += 1

        # Count test plan results
        plan_passed = 0
        plan_total = 0
        plan_skipped = 0
        for plan in test_plans.values():
            if "passed" in plan:
                plan_passed += int(plan["passed"])
            if "total" in plan:
                plan_total += int(plan["total"])
            if "skipped" in plan:
                plan_skipped += int(plan["skipped"])

        # Count API endpoints
        api_endpoints = 0
        oidc_count = 0
        oauth_count = 0
        custom_count = 0

        if isinstance(api_data, list):
            # Handle list format from analyze_openapi_conformance.py
            api_endpoints = len(api_data)
            for endpoint in api_data:
                if endpoint.get("category") == "OIDC Core":
                    oidc_count += 1
                elif endpoint.get("category") == "OAuth 2.0":
                    oauth_count += 1
                elif endpoint.get("category") in ["Admin", "Custom"]:
                    custom_count += 1
        elif isinstance(api_data, dict) and "openapi_analysis" in api_data:
            # Handle alternative dict format if it exists
            analysis = api_data["openapi_analysis"]
            if isinstance(analysis, dict):
                api_endpoints = analysis.get("total_endpoints", 0)
                oidc_count = analysis.get("oidc_endpoints", {}).get("count", 0)
                oauth_count = analysis.get("oauth_endpoints", {}).get("count", 0)
                custom_count = analysis.get("custom_endpoints", {}).get("count", 0)

        return {
            "specification": {
                "passed": spec_passed,
                "total": spec_total,
                "percentage": f"{(spec_passed / max(1, spec_total) * 100):.1f}%",
            },
            "test_plans": {
                "passed": plan_passed,
                "total": plan_total,
                "skipped": plan_skipped,
                "implemented": plan_total - plan_skipped,
                "coverage": f"{((plan_total - plan_skipped) / max(1, plan_total) * 100):.1f}%",
            },
            "api_endpoints": {
                "total": api_endpoints,
                "oidc_core": oidc_count,
                "oauth": oauth_count,
                "custom": custom_count,
            },
        }

    def generate_summary(self) -> str:
        """Generate comprehensive test summary markdown"""
        spec_results = self.load_spec_compliance()
        test_plans = self.load_test_plan_results()
        self.load_api_matrix()
        overall = self.calculate_overall_metrics()

        summary = f"""# COMPREHENSIVE TEST SUMMARY

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 📊 Executive Summary

### Overall Compliance Status
- **OIDC Specification Compliance**: {overall["specification"]["percentage"]} ({overall["specification"]["passed"]}/{overall["specification"]["total"]} checks)
- **Test Plan Implementation**: {overall["test_plans"]["coverage"]} ({overall["test_plans"]["implemented"]}/{overall["test_plans"]["total"]} tests)
- **API Endpoints Analyzed**: {overall["api_endpoints"]["total"]} total endpoints

## 🎯 Specification Compliance Details

### Category Breakdown
"""

        # Add spec compliance by category
        if spec_results:
            for category, results in spec_results.items():
                if isinstance(results, dict):
                    passed = sum(1 for r in results.values() if isinstance(r, bool) and r)
                    total = sum(1 for r in results.values() if isinstance(r, bool))
                    if total > 0:
                        percentage = (passed / total) * 100
                        status = "✅" if percentage == 100 else "⚠️" if percentage >= 80 else "❌"
                        summary += f"- **{category.replace('_', ' ').title()}**: {status} {percentage:.0f}% ({passed}/{total})\n"

        summary += f"""

## 📋 Test Plan Results

### Official Test Plan Coverage
"""

        # Add test plan results
        if test_plans:
            for plan_name, results in test_plans.items():
                plan_display = plan_name.replace("-", " ").title()
                pass_rate = results.get("pass_rate", "0%")
                total = results.get("total", "0")
                passed = results.get("passed", "0")
                failed = results.get("failed", "0")
                skipped = results.get("skipped", "0")

                summary += f"""
#### {plan_display}
- **Pass Rate**: {pass_rate}
- **Results**: {passed} passed ✅, {failed} failed ❌, {skipped} not implemented ⏭️
- **Total Tests**: {total}
"""

        summary += f"""

## 🔌 API Endpoint Coverage

### Endpoint Statistics
- **Total Endpoints**: {overall["api_endpoints"]["total"]}
- **OIDC Core Endpoints**: {overall["api_endpoints"]["oidc_core"]}
- **OAuth 2.0 Endpoints**: {overall["api_endpoints"]["oauth"]}
- **Custom/Admin Endpoints**: {overall["api_endpoints"]["custom"]}

## 🚦 Readiness Assessment

### Certification Readiness
"""

        spec_percentage = float(overall["specification"]["percentage"].rstrip("%"))
        if spec_percentage >= 95:
            summary += "- **Specification**: ✅ READY - High compliance, ready for certification\n"
        elif spec_percentage >= 80:
            summary += "- **Specification**: ⚠️ NEARLY READY - Minor issues to address\n"
        else:
            summary += "- **Specification**: ❌ NOT READY - Significant gaps to address\n"

        test_coverage = float(overall["test_plans"]["coverage"].rstrip("%"))
        if test_coverage >= 60:
            summary += "- **Test Plans**: ✅ GOOD - Majority of tests implemented\n"
        elif test_coverage >= 40:
            summary += "- **Test Plans**: ⚠️ PARTIAL - Additional test coverage needed\n"
        else:
            summary += "- **Test Plans**: ❌ LIMITED - Significant test implementation required\n"

        summary += f"""

## 📈 Progress Tracking

### Key Metrics
- **Specification Compliance**: {overall["specification"]["percentage"]}
- **Test Implementation**: {overall["test_plans"]["coverage"]}
- **Total Tests Passing**: {overall["specification"]["passed"] + overall["test_plans"]["passed"]}
- **Total Tests Available**: {overall["specification"]["total"] + overall["test_plans"]["total"]}

### Next Steps for Improvement
"""

        # Add recommendations based on current status
        if spec_percentage < 100:
            summary += "1. **Fix Specification Issues**: Review SPECIFICATION_CONFORMANCE.md for failing checks\n"

        if test_coverage < 100:
            unimplemented = overall["test_plans"]["skipped"]
            summary += f"2. **Implement Missing Tests**: {unimplemented} test modules need implementation\n"

        if overall["test_plans"].get("failed", 0) > 0:
            summary += "3. **Fix Failing Tests**: Review test plan reports for failure details\n"

        summary += """

## 📁 Report Files

### Available Reports
- `reports/latest/SPECIFICATION_CONFORMANCE.md` - Detailed spec compliance
- `reports/latest/COMPREHENSIVE_API_MATRIX.md` - API endpoint analysis
- `reports/test-plans/basic-certification_report.md` - Basic OIDC test results
- `reports/test-plans/pkce-certification_report.md` - PKCE test results

---

*Generated by TCK Test Summary Generator*
"""

        return summary

    def save_summary(self, content: str):
        """Save summary to file"""
        output_path = self.reports_path / "latest" / "COMPREHENSIVE_TEST_SUMMARY.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write(content)

        print(f"✅ Comprehensive test summary saved to: {output_path}")
        return output_path


def main():
    """Generate comprehensive test summary"""
    generator = TestSummaryGenerator()
    summary = generator.generate_summary()
    output_path = generator.save_summary(summary)

    # Display summary
    print("\n" + "=" * 60)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 60)

    # Show key metrics
    metrics = generator.calculate_overall_metrics()
    print(f"\n📊 Overall Status:")
    print(f"  • Specification Compliance: {metrics['specification']['percentage']}")
    print(f"  • Test Plan Coverage: {metrics['test_plans']['coverage']}")
    print(f"  • Total Endpoints: {metrics['api_endpoints']['total']}")

    print(f"\n📄 Full report: {output_path}")

    return 0


if __name__ == "__main__":
    exit(main())
