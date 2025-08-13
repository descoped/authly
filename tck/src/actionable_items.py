#!/usr/bin/env python3
"""
Generate actionable items report from all TCK test results
Creates a prioritized list of fixes needed for compliance
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple


class ActionableItemsGenerator:
    """Generate actionable items from test results"""

    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.reports_path = self.base_path / "reports"
        self.items = {
            "critical": [],  # Security/spec violations
            "high": [],  # Failed required tests
            "medium": [],  # Failed optional tests
            "low": [],  # Improvements/optimizations
        }

    def extract_spec_issues(self) -> list[dict[str, str]]:
        """Extract failures from specification conformance"""
        issues = []
        try:
            with open(self.reports_path / "latest" / "conformance_results.json") as f:
                results = json.load(f)

            # Check each category for failures
            for category, checks in results.items():
                if isinstance(checks, dict):
                    for check_name, passed in checks.items():
                        if isinstance(passed, bool) and not passed:
                            # Parse the check name to understand what failed
                            issue = self._create_spec_issue(category, check_name)
                            if issue:
                                issues.append(issue)
        except FileNotFoundError:
            pass

        return issues

    def _create_spec_issue(self, category: str, check_name: str) -> dict[str, str]:
        """Create actionable item from spec failure"""
        # Map check names to actionable items
        issue_map = {
            "issuer_https": {
                "title": "Configure HTTPS for issuer URL",
                "description": "The issuer URL must use HTTPS in production. Currently using HTTP.",
                "fix": "Update OIDC issuer configuration to use HTTPS URL",
                "file_hint": "src/authly/oauth/discovery_service.py",
                "priority": "critical",
            },
            "pkce_enforced": {
                "title": "Enforce PKCE for all authorization code flows",
                "description": "PKCE must be required for OAuth 2.1 compliance",
                "fix": "Update OAuth authorize endpoint to require PKCE parameters",
                "file_hint": "src/authly/api/oauth_router.py",
                "priority": "critical",
            },
            "supports_none_alg": {
                "title": "Ensure 'none' algorithm is rejected",
                "description": "The 'none' algorithm must not be supported for security",
                "fix": "Add validation to reject tokens with 'none' algorithm",
                "file_hint": "src/authly/tokens/service.py",
                "priority": "critical",
            },
        }

        # Convert snake_case check name to lookup key
        key = check_name.replace("_", "").lower()
        for map_key, issue_data in issue_map.items():
            if map_key.replace("_", "").lower() in key:
                return issue_data

        # Generic issue for unmapped checks
        return {
            "title": f"Fix {category}: {check_name.replace('_', ' ').title()}",
            "description": f"Specification check failed in {category}",
            "fix": f"Review and fix {check_name} requirement",
            "file_hint": "",
            "priority": "high",
        }

    def extract_test_plan_failures(self) -> list[dict[str, str]]:
        """Extract failed tests from test plan reports"""
        issues = []
        test_plans_dir = self.base_path / "reports" / "test-plans"

        if test_plans_dir.exists():
            for report_file in test_plans_dir.glob("*report.md"):
                with open(report_file) as f:
                    content = f.read()

                # Parse test results table
                in_table = False
                for line in content.split("\n"):
                    if "| Test Module |" in line:
                        in_table = True
                        continue
                    if in_table and line.startswith("|"):
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 5:
                            test_name = parts[1]
                            status = parts[2]
                            required = parts[3]
                            description = parts[4]

                            if "❌ FAIL" in status:
                                issues.append(self._create_test_issue(test_name, description, required == "Yes"))
                            elif "⏭️ NOT_IMPLEMENTED" in status and required == "Yes":
                                issues.append(self._create_implementation_issue(test_name, description))

        return issues

    def _create_test_issue(self, test_name: str, description: str, required: bool) -> dict[str, str]:
        """Create actionable item from test failure"""
        # Map test names to specific fixes
        test_fixes = {
            "oidcc-discovery-issuer-not-matching-config": {
                "title": "Fix discovery issuer mismatch",
                "fix": "Ensure discovery document issuer matches server configuration",
                "file_hint": "src/authly/oauth/discovery_service.py",
            },
            "oidcc-userinfo-post-header": {
                "title": "Fix UserInfo POST with Bearer token",
                "fix": "Update UserInfo endpoint to accept POST requests with Bearer token in header",
                "file_hint": "src/authly/api/oidc_router.py",
            },
            "oidcc-userinfo-post-body": {
                "title": "Support UserInfo POST with token in body",
                "fix": "Allow access token in request body for UserInfo POST",
                "file_hint": "src/authly/api/oidc_router.py",
            },
        }

        fix_info = test_fixes.get(test_name, {})

        return {
            "title": fix_info.get("title", f"Fix test: {test_name}"),
            "description": description or f"Test {test_name} is failing",
            "fix": fix_info.get("fix", f"Debug and fix {test_name} test failure"),
            "file_hint": fix_info.get("file_hint", ""),
            "priority": "high" if required else "medium",
            "test_name": test_name,
        }

    def _create_implementation_issue(self, test_name: str, description: str) -> dict[str, str]:
        """Create actionable item for unimplemented test"""
        # Map test names to implementation guidance
        impl_map = {
            "oidcc-ensure-request-without-nonce-succeeds-for-code-flow": {
                "title": "Allow authorization without nonce for code flow",
                "fix": "Make nonce optional for authorization code flow (required only for implicit)",
                "file_hint": "src/authly/api/oauth_router.py",
            },
            "oidcc-id-token-kid-absent-single-jwks": {
                "title": "Handle kid absence with single JWKS key",
                "fix": "When only one key in JWKS, allow ID tokens without kid header",
                "file_hint": "src/authly/tokens/service.py",
            },
            "oidcc-scope-address": {
                "title": "Implement address scope claims",
                "fix": "Add support for address claims in UserInfo when address scope requested",
                "file_hint": "src/authly/api/oidc_router.py",
            },
            "oidcc-scope-phone": {
                "title": "Implement phone scope claims",
                "fix": "Add support for phone_number claims when phone scope requested",
                "file_hint": "src/authly/api/oidc_router.py",
            },
            "oidcc-nonce-invalid": {
                "title": "Validate nonce in ID tokens",
                "fix": "Ensure invalid nonce values are rejected in ID token validation",
                "file_hint": "src/authly/tokens/service.py",
            },
            "oidcc-claims-essential": {
                "title": "Support essential claims in requests",
                "fix": "Handle 'essential' property in claims request parameter",
                "file_hint": "src/authly/api/oauth_router.py",
            },
            "oidcc-codereuse-30seconds": {
                "title": "Prevent authorization code reuse within 30 seconds",
                "fix": "Implement code replay protection with 30-second window",
                "file_hint": "src/authly/oauth/authorization_service.py",
            },
            "oidcc-codereuse": {
                "title": "Prevent authorization code reuse",
                "fix": "Ensure authorization codes can only be used once",
                "file_hint": "src/authly/oauth/authorization_service.py",
            },
            "oidcc-ensure-pkce-plain-not-supported": {
                "title": "Reject plain PKCE method",
                "fix": "Only allow S256 code challenge method, reject plain",
                "file_hint": "src/authly/api/oauth_router.py",
            },
            "oidcc-ensure-pkce-invalid-code-verifier": {
                "title": "Validate PKCE code verifier properly",
                "fix": "Reject invalid code verifiers that don't match challenge",
                "file_hint": "src/authly/oauth/pkce_service.py",
            },
            "oidcc-ensure-pkce-missing-code-verifier": {
                "title": "Require code verifier when PKCE used",
                "fix": "Return error when code_verifier missing for PKCE flow",
                "file_hint": "src/authly/api/oauth_router.py",
            },
        }

        impl_info = impl_map.get(test_name, {})

        return {
            "title": impl_info.get("title", f"Implement test: {test_name}"),
            "description": description or f"Test {test_name} needs implementation",
            "fix": impl_info.get("fix", f"Implement functionality for {test_name}"),
            "file_hint": impl_info.get("file_hint", ""),
            "priority": "medium",
            "test_name": test_name,
        }

    def extract_api_gaps(self) -> list[dict[str, str]]:
        """Extract missing or problematic API endpoints"""
        issues = []
        try:
            with open(self.reports_path / "latest" / "api_matrix.json") as f:
                endpoints = json.load(f)

            # Check for missing required endpoints
            required_endpoints = {
                "/oidc/logout": "End Session endpoint for logout",
                "/oidc/register": "Dynamic Client Registration endpoint",
            }

            found_paths = {e["path"] for e in endpoints}

            for path, description in required_endpoints.items():
                if path not in found_paths:
                    issues.append(
                        {
                            "title": f"Implement {description}",
                            "description": f"Optional but recommended: {path}",
                            "fix": f"Add {path} endpoint implementation",
                            "file_hint": "src/authly/api/oidc_router.py",
                            "priority": "low",
                        }
                    )
        except FileNotFoundError:
            pass

        return issues

    def prioritize_items(self, items: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
        """Organize items by priority"""
        prioritized = {"critical": [], "high": [], "medium": [], "low": []}

        for item in items:
            priority = item.get("priority", "medium")
            prioritized[priority].append(item)

        return prioritized

    def generate_actionable_report(self) -> str:
        """Generate the actionable items report"""
        # Collect all issues
        all_issues = []
        all_issues.extend(self.extract_spec_issues())
        all_issues.extend(self.extract_test_plan_failures())
        all_issues.extend(self.extract_api_gaps())

        # Prioritize
        prioritized = self.prioritize_items(all_issues)

        # Count items
        total_items = sum(len(items) for items in prioritized.values())
        critical_count = len(prioritized["critical"])
        high_count = len(prioritized["high"])

        report = f"""# 🎯 ACTIONABLE ITEMS REPORT

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 📊 Summary

**Total Action Items**: {total_items}
- 🔴 Critical: {critical_count} (Security/Compliance violations)
- 🟠 High: {high_count} (Required test failures)
- 🟡 Medium: {len(prioritized["medium"])} (Optional features)
- 🟢 Low: {len(prioritized["low"])} (Improvements)

## 🚨 Quick Start

Focus on **Critical** and **High** priority items first to achieve compliance.

---

## 🔴 CRITICAL PRIORITY
*Security vulnerabilities and spec violations that block certification*

"""

        # Add critical items
        if prioritized["critical"]:
            for i, item in enumerate(prioritized["critical"], 1):
                report += self._format_item(i, item, "🔴")
        else:
            report += "*No critical issues found* ✅\n"

        report += """
## 🟠 HIGH PRIORITY
*Required tests failing - must fix for certification*

"""

        # Add high priority items
        if prioritized["high"]:
            for i, item in enumerate(prioritized["high"], 1):
                report += self._format_item(i, item, "🟠")
        else:
            report += "*No high priority issues found* ✅\n"

        report += """
## 🟡 MEDIUM PRIORITY
*Optional features and non-required test failures*

"""

        # Add medium priority items
        if prioritized["medium"]:
            for i, item in enumerate(prioritized["medium"], 1):
                report += self._format_item(i, item, "🟡")
        else:
            report += "*No medium priority issues found*\n"

        report += """
## 🟢 LOW PRIORITY
*Improvements and optimizations*

"""

        # Add low priority items
        if prioritized["low"]:
            for i, item in enumerate(prioritized["low"], 1):
                report += self._format_item(i, item, "🟢")
        else:
            report += "*No low priority improvements identified*\n"

        # Add TodoWrite ready section
        report += f"""
---

## 📝 Ready for TodoWrite

Copy this list to start working on fixes:

```
"""

        # Generate todo items
        todo_items = []
        for priority in ["critical", "high", "medium", "low"]:
            for item in prioritized[priority]:
                todo_items.append(f"- {item['title']}")

        report += "\n".join(todo_items[:10])  # First 10 items

        if len(todo_items) > 10:
            report += f"\n... and {len(todo_items) - 10} more items"

        report += """
```

## 📁 Related Files to Review

"""

        # Collect unique file hints
        files_to_review = set()
        for items in prioritized.values():
            for item in items:
                if item.get("file_hint"):
                    files_to_review.add(item["file_hint"])

        if files_to_review:
            for file_path in sorted(files_to_review):
                report += f"- `{file_path}`\n"
        else:
            report += "*No specific files identified*\n"

        report += """
---

## 🎯 Next Steps

1. **Start with Critical issues** - These are blocking compliance
2. **Fix High priority items** - Required for certification
3. **Use TodoWrite** - Copy the todo list above to track progress
4. **Run tests after each fix** - `make validate`
5. **Check progress** - `make report`

---

*Generated by TCK Actionable Items Generator*
"""

        return report

    def _format_item(self, num: int, item: dict[str, str], icon: str) -> str:
        """Format a single actionable item"""
        output = f"### {icon} {num}. {item['title']}\n\n"
        output += f"**Issue**: {item['description']}\n\n"
        output += f"**Fix**: {item['fix']}\n"

        if item.get("file_hint"):
            output += f"\n**File**: `{item['file_hint']}`\n"

        if item.get("test_name"):
            output += f"\n**Test**: `{item['test_name']}`\n"

        output += "\n---\n\n"

        return output

    def save_report(self, content: str):
        """Save actionable items report"""
        output_path = self.reports_path / "latest" / "ACTIONABLE_ITEMS.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write(content)

        print(f"✅ Actionable items report saved to: {output_path}")
        return output_path


def main():
    """Generate actionable items report"""
    generator = ActionableItemsGenerator()
    report = generator.generate_actionable_report()
    output_path = generator.save_report(report)

    # Show summary
    print("\n" + "=" * 60)
    print("ACTIONABLE ITEMS REPORT")
    print("=" * 60)

    # Parse the report to show counts
    lines = report.split("\n")
    for line in lines:
        if "**Total Action Items**:" in line:
            print(f"\n{line}")
        elif "🔴 Critical:" in line or "🟠 High:" in line or "🟡 Medium:" in line:
            print(line)
        elif "🟢 Low:" in line:
            print(line)
            break

    print(f"\n📄 Full report: {output_path}")

    return 0


if __name__ == "__main__":
    exit(main())
