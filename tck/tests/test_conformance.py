#!/usr/bin/env python3
"""
Unit tests for TCK conformance validation modules
"""

import pytest
import json
from unittest.mock import Mock, patch
from pathlib import Path
import sys

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from validator import OIDCConformanceValidator
from utils import format_test_results, get_authly_base_url
from client import ConformanceClient


class TestOIDCConformanceValidator:
    """Test the OIDC conformance validator"""

    def setup_method(self):
        self.validator = OIDCConformanceValidator("http://localhost:8000")

    def test_validator_initialization(self):
        """Test validator initializes correctly"""
        assert self.validator.base_url == "http://localhost:8000"
        assert self.validator.discovery is None
        assert self.validator.jwks is None
        assert len(self.validator.results) == 5  # 5 categories

    def test_validator_with_env_url(self):
        """Test validator uses environment URL when provided"""
        with patch.dict("os.environ", {"AUTHLY_BASE_URL": "http://test:8080"}):
            validator = OIDCConformanceValidator()
            assert validator.base_url == "http://test:8080"

    @patch("requests.get")
    def test_discovery_validation_success(self, mock_get):
        """Test successful discovery document validation"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "http://localhost:8000",
            "authorization_endpoint": "http://localhost:8000/api/v1/oauth/authorize",
            "token_endpoint": "http://localhost:8000/api/v1/oauth/token",
            "userinfo_endpoint": "http://localhost:8000/oidc/userinfo",
            "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }
        mock_get.return_value = mock_response

        self.validator.validate_discovery_document()

        # Check that required fields are validated
        assert self.validator.results["discovery"]["issuer_present"] is True
        assert self.validator.results["discovery"]["issuer_type_correct"] is True
        assert self.validator.results["discovery"]["pkce_s256_supported"] is True


class TestUtils:
    """Test utility functions"""

    def test_format_test_results_all_pass(self):
        """Test formatting when all tests pass"""
        results = {"category1": {"test1": True, "test2": True}, "category2": {"test3": True, "test4": True}}
        formatted = format_test_results(results)
        assert "4/4 checks passed (100%)" in formatted

    def test_format_test_results_partial_pass(self):
        """Test formatting with partial pass"""
        results = {"category1": {"test1": True, "test2": False}, "category2": {"test3": True, "test4": True}}
        formatted = format_test_results(results)
        assert "3/4 checks passed (75%)" in formatted

    def test_format_test_results_empty(self):
        """Test formatting with empty results"""
        results = {}
        formatted = format_test_results(results)
        assert "No results available" in formatted

    def test_get_authly_base_url_default(self):
        """Test default base URL"""
        with patch.dict("os.environ", {}, clear=True):
            url = get_authly_base_url()
            assert url == "http://localhost:8000"

    def test_get_authly_base_url_from_env(self):
        """Test base URL from environment"""
        with patch.dict("os.environ", {"AUTHLY_BASE_URL": "http://custom:9000"}):
            url = get_authly_base_url()
            assert url == "http://custom:9000"


class TestConformanceClient:
    """Test the conformance client"""

    def test_client_initialization(self):
        """Test client initializes with correct base URL"""
        client = ConformanceClient("https://test:8443")
        assert client.base_url == "https://test:8443"

    def test_client_default_url(self):
        """Test client uses default URL"""
        client = ConformanceClient()
        assert client.base_url == "https://localhost:8443"


class TestIntegration:
    """Integration tests for TCK components"""

    def test_validator_client_integration(self):
        """Test that validator and client can work together"""
        validator = OIDCConformanceValidator("http://localhost:8000")
        client = ConformanceClient("https://localhost:8443")

        # Both should be properly initialized
        assert validator.base_url == "http://localhost:8000"
        assert client.base_url == "https://localhost:8443"

        # Validator should have proper result structure
        expected_categories = ["discovery", "jwks", "id_token", "endpoints", "security"]
        assert list(validator.results.keys()) == expected_categories


if __name__ == "__main__":
    pytest.main([__file__])
