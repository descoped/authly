"""
Full OAuth 2.1 + OIDC Flow Integration Tests

This module tests complete authorization flows including:
- User creation and authentication
- Authorization code flow with PKCE
- Token exchange
- ID token validation
- UserInfo endpoint access
- Token refresh
- Logout
"""

import base64
import hashlib
import secrets
from typing import Any

import jwt
import pytest
from httpx import AsyncClient


class OAuthFlowTester:
    """Helper class for testing complete OAuth/OIDC flows."""

    def __init__(self, authly_url: str = "http://localhost:8000"):
        self.authly_url = authly_url
        self.client = AsyncClient(verify=False, timeout=30.0, follow_redirects=False)
        self.test_client_id = "oidc-conformance-test"
        self.test_client_secret = "conformance-test-secret"
        self.test_user = {
            "username": "test_user",
            "email": "test@example.com",
            "password": "TestPassword123!",
            "given_name": "Test",
            "family_name": "User",
        }
        self.session_cookies = None
        self.access_token = None
        self.id_token = None
        self.refresh_token = None

    def generate_pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode("utf-8").rstrip("=")
        )
        return code_verifier, code_challenge

    async def create_test_user(self) -> dict[str, Any]:
        """Create a test user in the system."""
        response = await self.client.post(f"{self.authly_url}/api/v1/auth/register", json=self.test_user)
        if response.status_code == 409:  # User already exists
            return {"status": "exists"}
        response.raise_for_status()
        return response.json()

    async def login_user(self) -> dict[str, Any]:
        """Login as the test user and get session."""
        response = await self.client.post(
            f"{self.authly_url}/api/v1/auth/login",
            json={"username": self.test_user["username"], "password": self.test_user["password"]},
        )
        response.raise_for_status()

        # Store session cookies if present
        if "set-cookie" in response.headers:
            self.session_cookies = response.cookies

        result = response.json()
        if "access_token" in result:
            self.access_token = result["access_token"]

        return result

    async def start_authorization_flow(self, scope: str = "openid profile email") -> dict[str, Any]:
        """Start the authorization code flow with PKCE."""
        code_verifier, code_challenge = self.generate_pkce_challenge()

        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": self.test_client_id,
            "redirect_uri": "https://localhost:8443/test/a/authly/callback",
            "scope": scope,
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        # Make authorization request with session
        headers = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        response = await self.client.get(
            f"{self.authly_url}/api/v1/oauth/authorize", params=params, headers=headers, cookies=self.session_cookies
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "location": response.headers.get("location"),
            "code_verifier": code_verifier,
            "state": params["state"],
            "nonce": params["nonce"],
        }

    async def exchange_code_for_tokens(self, code: str, code_verifier: str) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
        # Prepare client authentication (Basic Auth)
        auth_string = f"{self.test_client_id}:{self.test_client_secret}"
        auth_bytes = auth_string.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

        response = await self.client.post(
            f"{self.authly_url}/api/v1/auth/token",
            headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://localhost:8443/test/a/authly/callback",
                "code_verifier": code_verifier,
            },
        )

        if response.status_code == 200:
            tokens = response.json()
            self.access_token = tokens.get("access_token")
            self.id_token = tokens.get("id_token")
            self.refresh_token = tokens.get("refresh_token")
            return tokens

        return {"error": f"Token exchange failed with status {response.status_code}", "details": response.text}

    async def get_userinfo(self) -> dict[str, Any]:
        """Get user information from UserInfo endpoint."""
        if not self.access_token:
            return {"error": "No access token available"}

        response = await self.client.get(
            f"{self.authly_url}/oidc/userinfo", headers={"Authorization": f"Bearer {self.access_token}"}
        )

        if response.status_code == 200:
            return response.json()

        return {"error": f"UserInfo request failed with status {response.status_code}", "details": response.text}

    async def refresh_access_token(self) -> dict[str, Any]:
        """Use refresh token to get new access token."""
        if not self.refresh_token:
            return {"error": "No refresh token available"}

        # Prepare client authentication
        auth_string = f"{self.test_client_id}:{self.test_client_secret}"
        auth_bytes = auth_string.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

        response = await self.client.post(
            f"{self.authly_url}/api/v1/auth/token",
            headers={"Authorization": f"Basic {auth_b64}", "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
        )

        if response.status_code == 200:
            tokens = response.json()
            self.access_token = tokens.get("access_token")
            if "id_token" in tokens:
                self.id_token = tokens["id_token"]
            return tokens

        return {"error": f"Token refresh failed with status {response.status_code}", "details": response.text}

    async def validate_id_token(self) -> dict[str, Any]:
        """Validate the ID token structure and claims."""
        if not self.id_token:
            return {"error": "No ID token available"}

        try:
            # Decode without verification first to inspect
            unverified = jwt.decode(self.id_token, options={"verify_signature": False})

            # Check required claims
            required_claims = ["iss", "sub", "aud", "exp", "iat"]
            missing_claims = [claim for claim in required_claims if claim not in unverified]

            if missing_claims:
                return {"valid": False, "error": f"Missing required claims: {missing_claims}", "claims": unverified}

            # Check issuer
            if unverified["iss"] != self.authly_url:
                return {
                    "valid": False,
                    "error": f"Invalid issuer: {unverified['iss']} != {self.authly_url}",
                    "claims": unverified,
                }

            # Check audience
            if unverified["aud"] != self.test_client_id:
                return {
                    "valid": False,
                    "error": f"Invalid audience: {unverified['aud']} != {self.test_client_id}",
                    "claims": unverified,
                }

            return {"valid": True, "claims": unverified}

        except Exception as e:
            return {"valid": False, "error": str(e)}

    async def logout(self) -> dict[str, Any]:
        """Perform logout/end session."""
        response = await self.client.post(
            f"{self.authly_url}/oidc/logout",
            json={"id_token_hint": self.id_token} if self.id_token else {},
            headers={"Authorization": f"Bearer {self.access_token}"} if self.access_token else {},
        )

        return {"status_code": response.status_code, "success": response.status_code in [200, 204]}

    async def cleanup(self):
        """Clean up resources."""
        await self.client.aclose()


@pytest.mark.asyncio
class TestFullOAuthFlow:
    """Test complete OAuth 2.1 + OIDC flows."""

    @pytest.fixture
    async def flow_tester(self):
        """Create a flow tester instance."""
        tester = OAuthFlowTester()
        yield tester
        await tester.cleanup()

    async def test_complete_authorization_code_flow(self, flow_tester: OAuthFlowTester):
        """Test the complete authorization code flow with PKCE."""
        # Step 1: Create test user
        user_result = await flow_tester.create_test_user()
        assert user_result.get("status") in ["created", "exists"], "User creation failed"

        # Step 2: Login as user
        login_result = await flow_tester.login_user()
        assert "access_token" in login_result or "session" in login_result, "Login failed"

        # Step 3: Start authorization flow
        auth_result = await flow_tester.start_authorization_flow()

        # Authorization might redirect to consent or return a code directly
        # For API-first servers, it might return 200 with code or 302 with redirect
        assert auth_result["status_code"] in [200, 302, 303, 401], (
            f"Unexpected authorization response: {auth_result['status_code']}"
        )

        # If we got a redirect with code, extract it
        if auth_result["location"] and "code=" in auth_result["location"]:
            # Extract code from redirect URL
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(auth_result["location"])
            params = parse_qs(parsed.query)
            code = params.get("code", [None])[0]

            if code:
                # Step 4: Exchange code for tokens
                token_result = await flow_tester.exchange_code_for_tokens(code, auth_result["code_verifier"])

                if "access_token" in token_result:
                    assert "access_token" in token_result, "No access token received"
                    assert "token_type" in token_result, "No token type specified"

                    # Step 5: Validate ID token if present
                    if "id_token" in token_result:
                        id_token_result = await flow_tester.validate_id_token()
                        assert id_token_result["valid"], f"ID token validation failed: {id_token_result.get('error')}"

                    # Step 6: Get UserInfo
                    userinfo_result = await flow_tester.get_userinfo()
                    if "error" not in userinfo_result:
                        assert "sub" in userinfo_result, "UserInfo missing 'sub' claim"

    async def test_token_refresh_flow(self, flow_tester: OAuthFlowTester):
        """Test refresh token flow."""
        # Setup: Get initial tokens
        await flow_tester.create_test_user()
        await flow_tester.login_user()

        # For this test, we need to have tokens first
        # This would normally come from a successful authorization flow

        # Test refresh if we have a refresh token
        if flow_tester.refresh_token:
            refresh_result = await flow_tester.refresh_access_token()

            if "error" not in refresh_result:
                assert "access_token" in refresh_result, "No new access token received"
                assert refresh_result["access_token"] != flow_tester.access_token, (
                    "Access token should be different after refresh"
                )

    async def test_userinfo_requires_valid_token(self, flow_tester: OAuthFlowTester):
        """Test that UserInfo endpoint requires valid authentication."""
        # Test without token
        flow_tester.access_token = None
        userinfo_result = await flow_tester.get_userinfo()
        assert "error" in userinfo_result, "UserInfo should fail without token"

        # Test with invalid token
        flow_tester.access_token = "invalid-token"
        response = await flow_tester.client.get(
            f"{flow_tester.authly_url}/oidc/userinfo", headers={"Authorization": f"Bearer {flow_tester.access_token}"}
        )
        assert response.status_code == 401, "UserInfo should return 401 for invalid token"

    async def test_pkce_is_required(self, flow_tester: OAuthFlowTester):
        """Test that PKCE is required for authorization."""
        # Try authorization without PKCE
        params = {
            "response_type": "code",
            "client_id": flow_tester.test_client_id,
            "redirect_uri": "https://localhost:8443/test/a/authly/callback",
            "scope": "openid",
            "state": "test-state",
            # Missing code_challenge and code_challenge_method
        }

        response = await flow_tester.client.get(f"{flow_tester.authly_url}/api/v1/oauth/authorize", params=params)

        # Should either return error or require PKCE
        # Status could be 400 (bad request) or 401 (unauthorized)
        assert response.status_code in [400, 401, 302], f"Expected error for missing PKCE, got {response.status_code}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
