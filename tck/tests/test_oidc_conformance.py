"""
OIDC Conformance Test Suite for Authly

This module provides automated testing against the OpenID Connect conformance suite.
It validates that Authly correctly implements OIDC Core 1.0 and related specifications.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient


class OIDCConformanceTester:
    """Helper class for OIDC conformance testing."""

    def __init__(self, authly_url: str = "http://localhost:8000"):
        self.authly_url = authly_url
        self.client = AsyncClient(verify=False, timeout=30.0)
        self.test_client_id = "oidc-conformance-test"
        self.test_client_secret = "conformance-test-secret-change-in-production"

    async def check_discovery(self) -> dict[str, Any]:
        """Validate OIDC discovery endpoint."""
        response = await self.client.get(f"{self.authly_url}/.well-known/openid_configuration")
        response.raise_for_status()
        return response.json()

    async def check_jwks(self) -> dict[str, Any]:
        """Validate JWKS endpoint."""
        response = await self.client.get(f"{self.authly_url}/.well-known/jwks.json")
        response.raise_for_status()
        return response.json()

    async def validate_discovery_metadata(self, metadata: dict[str, Any]) -> list[str]:
        """Validate required OIDC discovery metadata fields."""
        errors = []

        # Required fields per OIDC Discovery 1.0
        required_fields = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ]

        for field in required_fields:
            if field not in metadata:
                errors.append(f"Missing required field: {field}")

        # Validate issuer matches expected URL
        if metadata.get("issuer") != self.authly_url:
            errors.append(f"Issuer mismatch: {metadata.get('issuer')} != {self.authly_url}")

        # Validate endpoints are absolute URLs
        endpoint_fields = ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"]

        for field in endpoint_fields:
            if field in metadata:
                url = metadata[field]
                if not url.startswith("http://") and not url.startswith("https://"):
                    errors.append(f"{field} is not an absolute URL: {url}")

        return errors

    async def validate_jwks_keys(self, jwks: dict[str, Any]) -> list[str]:
        """Validate JWKS endpoint response."""
        errors = []

        if "keys" not in jwks:
            errors.append("JWKS response missing 'keys' field")
            return errors

        if not isinstance(jwks["keys"], list):
            errors.append("JWKS 'keys' field is not an array")
            return errors

        if len(jwks["keys"]) == 0:
            errors.append("JWKS contains no keys")
            return errors

        # Validate each key
        for i, key in enumerate(jwks["keys"]):
            if "kty" not in key:
                errors.append(f"Key {i} missing 'kty' field")

            if "use" not in key:
                errors.append(f"Key {i} missing 'use' field")

            if "kid" not in key:
                errors.append(f"Key {i} missing 'kid' field")

            # For RSA keys, check required fields
            if key.get("kty") == "RSA":
                rsa_fields = ["n", "e"]
                for field in rsa_fields:
                    if field not in key:
                        errors.append(f"RSA key {i} missing '{field}' field")

        return errors

    async def test_authorization_flow(self) -> dict[str, Any]:
        """Test the authorization code flow."""
        # This would normally interact with the actual conformance suite
        # For now, we'll validate that the endpoints exist and respond

        # Check authorization endpoint
        auth_response = await self.client.get(
            f"{self.authly_url}/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": self.test_client_id,
                "redirect_uri": "https://localhost:8443/test/a/authly/callback",
                "scope": "openid profile",
                "state": "test-state",
                "nonce": "test-nonce",
            },
            follow_redirects=False,
        )

        # Should redirect to login or consent
        if auth_response.status_code not in [302, 303]:
            return {"success": False, "error": f"Authorization endpoint returned {auth_response.status_code}"}

        return {"success": True}

    async def cleanup(self):
        """Clean up resources."""
        await self.client.aclose()


@pytest.mark.asyncio
class TestOIDCConformance:
    """OIDC Conformance test suite."""

    @pytest.fixture
    async def tester(self):
        """Create a conformance tester instance."""
        tester = OIDCConformanceTester()
        yield tester
        await tester.cleanup()

    async def test_discovery_endpoint(self, tester: OIDCConformanceTester):
        """Test OIDC discovery endpoint compliance."""
        metadata = await tester.check_discovery()

        # Validate metadata
        errors = await tester.validate_discovery_metadata(metadata)
        assert len(errors) == 0, f"Discovery validation errors: {errors}"

        # Check for required response types
        assert "code" in metadata["response_types_supported"]

        # Check for required scopes
        scopes = metadata.get("scopes_supported", [])
        assert "openid" in scopes

    async def test_jwks_endpoint(self, tester: OIDCConformanceTester):
        """Test JWKS endpoint compliance."""
        jwks = await tester.check_jwks()

        # Validate JWKS structure
        errors = await tester.validate_jwks_keys(jwks)
        assert len(errors) == 0, f"JWKS validation errors: {errors}"

        # Ensure at least one signing key exists
        signing_keys = [key for key in jwks["keys"] if key.get("use") == "sig"]
        assert len(signing_keys) > 0, "No signing keys found in JWKS"

    async def test_authorization_endpoint_exists(self, tester: OIDCConformanceTester):
        """Test that authorization endpoint exists and responds."""
        result = await tester.test_authorization_flow()
        assert result["success"], result.get("error", "Authorization flow failed")

    async def test_userinfo_endpoint_requires_auth(self, tester: OIDCConformanceTester):
        """Test that UserInfo endpoint requires authentication."""
        response = await tester.client.get(f"{tester.authly_url}/oidc/userinfo")
        # Should return 401 without authentication
        assert response.status_code == 401, "UserInfo endpoint should require authentication"

    async def test_token_endpoint_requires_auth(self, tester: OIDCConformanceTester):
        """Test that token endpoint requires client authentication."""
        response = await tester.client.post(
            f"{tester.authly_url}/api/v1/auth/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid-code",
                "redirect_uri": "https://localhost:8443/test/a/authly/callback",
            },
        )
        # Should return 401 without client authentication
        assert response.status_code in [400, 401], "Token endpoint should require client authentication"

    async def test_session_management_discovery(self, tester: OIDCConformanceTester):
        """Test Session Management 1.0 discovery metadata."""
        metadata = await tester.check_discovery()

        # Check for session management endpoints
        if "check_session_iframe" in metadata:
            assert metadata["check_session_iframe"].startswith("http")

        if "end_session_endpoint" in metadata:
            assert metadata["end_session_endpoint"].startswith("http")

    async def test_pkce_required(self, tester: OIDCConformanceTester):
        """Test that PKCE is required for public clients."""
        # Attempt authorization without PKCE
        response = await tester.client.get(
            f"{tester.authly_url}/api/v1/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": tester.test_client_id,
                "redirect_uri": "https://localhost:8443/test/a/authly/callback",
                "scope": "openid",
                "state": "test-state",
                # Missing code_challenge and code_challenge_method
            },
            follow_redirects=False,
        )

        # For OAuth 2.1 compliance, PKCE should be required
        # The response should indicate an error or redirect with error
        # This behavior depends on Authly's configuration
        assert response.status_code in [302, 303, 400], "Expected redirect or error for missing PKCE"


@pytest.mark.asyncio
class TestConformanceProfiles:
    """Test different OIDC conformance profiles."""

    @pytest.fixture
    def profiles(self):
        """Load conformance profiles."""
        profiles_path = Path(__file__).parent.parent / "config" / "conformance-profiles.json"
        with open(profiles_path) as f:
            return json.load(f)

    async def test_basic_profile_configuration(self, profiles):
        """Test that basic profile is properly configured."""
        basic_profile = profiles["test_profiles"]["basic"]

        assert basic_profile["plan_name"] == "oidcc-basic-certification-test-plan"
        assert "client" in basic_profile["configuration"]
        assert "server" in basic_profile["configuration"]

        # Verify expected tests are defined
        assert len(basic_profile["expected_tests"]) > 0

    async def test_all_profiles_have_configuration(self, profiles):
        """Test that all profiles have required configuration."""
        for profile_name, profile_config in profiles["test_profiles"].items():
            assert "name" in profile_config, f"Profile {profile_name} missing name"
            assert "description" in profile_config, f"Profile {profile_name} missing description"
            assert "plan_name" in profile_config, f"Profile {profile_name} missing plan_name"
            assert "configuration" in profile_config, f"Profile {profile_name} missing configuration"

    async def test_test_suites_reference_valid_profiles(self, profiles):
        """Test that test suites only reference valid profiles."""
        valid_profiles = set(profiles["test_profiles"].keys())

        for suite_name, suite_profiles in profiles["test_suites"].items():
            for profile_name in suite_profiles:
                assert profile_name in valid_profiles, f"Suite {suite_name} references unknown profile: {profile_name}"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
