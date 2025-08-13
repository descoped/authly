#!/usr/bin/env python3
"""
Tests for Full Conformance Suite Integration
"""

import unittest
import json
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from conformance_suite import ConformanceSuiteRunner


class TestConformanceSuite(unittest.TestCase):
    """Test the conformance suite runner"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.runner = ConformanceSuiteRunner()
        cls.config_dir = Path(__file__).parent.parent / "config"
    
    def test_suite_availability(self):
        """Test that we can detect suite availability"""
        # This will fail if suite is not running, which is expected in unit tests
        available = self.runner.check_suite_availability()
        if not available:
            self.skipTest("Conformance suite not running - skipping integration tests")
    
    def test_authly_availability(self):
        """Test that we can detect Authly availability"""
        available = self.runner.check_authly_availability()
        if not available:
            self.skipTest("Authly not running - skipping integration tests")
    
    def test_config_files_exist(self):
        """Test that all configuration files exist"""
        configs = [
            "conformance-basic.json",
            "conformance-pkce.json",
            "conformance-security.json"
        ]
        
        for config in configs:
            config_path = self.config_dir / config
            self.assertTrue(
                config_path.exists(),
                f"Configuration file missing: {config}"
            )
    
    def test_config_structure(self):
        """Test that configuration files have correct structure"""
        configs = [
            "conformance-basic.json",
            "conformance-pkce.json",
            "conformance-security.json"
        ]
        
        required_fields = ["alias", "description", "server", "client", "test_plan", "variant"]
        
        for config_name in configs:
            config_path = self.config_dir / config_name
            with open(config_path) as f:
                config = json.load(f)
            
            for field in required_fields:
                self.assertIn(
                    field, config,
                    f"Missing required field '{field}' in {config_name}"
                )
            
            # Check server configuration
            self.assertIn("discoveryUrl", config["server"])
            
            # Check client configuration
            self.assertIn("client_id", config["client"])
            self.assertIn("redirect_uri", config["client"])
    
    def test_get_test_modules(self):
        """Test module selection logic"""
        # Test basic modules
        basic_config = {
            "test_plan": "oidcc-basic-certification-test-plan"
        }
        modules = self.runner.get_test_modules(basic_config)
        self.assertGreater(len(modules), 10, "Basic certification should have >10 modules")
        self.assertIn("oidcc-server", modules)
        self.assertIn("oidcc-userinfo-get", modules)
        
        # Test PKCE modules
        pkce_config = {
            "test_plan": "oidcc-pkce-certification-test-plan"
        }
        modules = self.runner.get_test_modules(pkce_config)
        self.assertGreater(len(modules), 5, "PKCE certification should have >5 modules")
        self.assertIn("oidcc-ensure-pkce-required", modules)
        
        # Test custom modules
        custom_config = {
            "test_modules": ["custom-test-1", "custom-test-2"]
        }
        modules = self.runner.get_test_modules(custom_config)
        self.assertEqual(len(modules), 2)
        self.assertIn("custom-test-1", modules)
        
        # Test skip modules
        skip_config = {
            "test_plan": "oidcc-basic-certification-test-plan",
            "skip_test_modules": ["oidcc-scope-address", "oidcc-scope-phone"]
        }
        modules = self.runner.get_test_modules(skip_config)
        self.assertNotIn("oidcc-scope-address", modules)
        self.assertNotIn("oidcc-scope-phone", modules)
    
    def test_report_generation(self):
        """Test that reports are generated correctly"""
        test_results = {
            "plan_id": "test-plan-123",
            "config": "test-config",
            "timestamp": "2024-01-01T00:00:00",
            "modules": {
                "test-1": {"status": "FINISHED", "message": ""},
                "test-2": {"status": "FAILED", "message": "Error occurred"},
                "test-3": {"status": "WARNING", "message": "Warning"}
            },
            "summary": {
                "total": 3,
                "passed": 1,
                "failed": 1,
                "warnings": 1,
                "skipped": 0,
                "errors": 0,
                "pass_rate": 33.3
            }
        }
        
        # Generate report
        self.runner.generate_report(test_results)
        
        # Check that report files were created
        report_dir = self.runner.reports_dir
        self.assertTrue(report_dir.exists(), "Reports directory should exist")
        
        # Check for markdown report
        md_files = list(report_dir.glob("suite-test-config-*.md"))
        self.assertGreater(len(md_files), 0, "Markdown report should be generated")
        
        # Check for JSON report
        json_files = list(report_dir.glob("suite-test-config-*.json"))
        self.assertGreater(len(json_files), 0, "JSON report should be generated")
    
    @unittest.skipUnless(
        os.getenv("RUN_INTEGRATION_TESTS") == "true",
        "Skipping integration test - set RUN_INTEGRATION_TESTS=true to run"
    )
    def test_full_basic_certification(self):
        """Integration test: Run full basic certification"""
        results = self.runner.run_test_plan("conformance-basic.json")
        
        self.assertNotIn("error", results, "Test plan should run without errors")
        self.assertIn("summary", results)
        self.assertGreater(
            results["summary"]["pass_rate"], 50,
            "Should achieve >50% pass rate on basic certification"
        )
    
    @unittest.skipUnless(
        os.getenv("RUN_INTEGRATION_TESTS") == "true",
        "Skipping integration test - set RUN_INTEGRATION_TESTS=true to run"
    )
    def test_full_pkce_certification(self):
        """Integration test: Run full PKCE certification"""
        results = self.runner.run_test_plan("conformance-pkce.json")
        
        self.assertNotIn("error", results, "Test plan should run without errors")
        self.assertIn("summary", results)
        # PKCE is critical for OAuth 2.1
        self.assertGreater(
            results["summary"]["pass_rate"], 75,
            "Should achieve >75% pass rate on PKCE certification"
        )


if __name__ == "__main__":
    unittest.main()