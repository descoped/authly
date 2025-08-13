#!/usr/bin/env python3
"""
Common utilities for TCK conformance testing
"""

import json
import os
import requests
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


def load_config(config_file: str) -> dict[str, Any]:
    """Load configuration from JSON file"""
    config_path = Path(__file__).parent.parent / "config" / config_file
    try:
        with open(config_path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Config file {config_file} not found")
        return {}


def save_report(content: str, filename: str, reports_dir: str = "reports/latest") -> Path:
    """Save report content to file"""
    reports_path = Path(__file__).parent.parent / reports_dir
    reports_path.mkdir(parents=True, exist_ok=True)

    report_file = reports_path / filename
    with open(report_file, "w") as f:
        f.write(content)

    return report_file


def get_authly_base_url() -> str:
    """Get Authly base URL from environment or default"""
    return os.getenv("AUTHLY_BASE_URL", "http://localhost:8000")


def check_service_health(base_url: str, timeout: int = 30) -> bool:
    """Check if a service is healthy"""
    health_url = f"{base_url}/health"
    try:
        response = requests.get(health_url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False


def format_test_results(results: dict[str, Any]) -> str:
    """Format test results for display"""
    total_checks = 0
    passed_checks = 0

    for _category, checks in results.items():
        for _check, result in checks.items():
            if isinstance(result, bool):
                total_checks += 1
                if result:
                    passed_checks += 1

    if total_checks > 0:
        percentage = (passed_checks / total_checks) * 100
        return f"{passed_checks}/{total_checks} checks passed ({percentage:.0f}%)"

    return "No results available"


def timestamp() -> str:
    """Get current timestamp for reports"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
