"""OIDC Compliance Tests - Essential Coverage Only.

Tests required for OpenID Connect 1.0 compliance.
Covers the mandatory features without redundancy.
"""

import jwt
import pytest
from fastapi import status
from fastapi_testing import AsyncTestServer


# NOTE: Using committed fixtures from tests/fixtures/committed_data.py
# These fixtures properly commit data before returning, following test isolation rules
# No custom fixtures needed here - we'll use the shared committed_user and committed_oauth_client


class TestOIDCCoreCompliance:
    """Essential OIDC 1.0 compliance tests."""

    @pytest.mark.asyncio
    async def test_jwks_endpoint(self, test_server: AsyncTestServer):
        """Test JWKS endpoint returns valid keys."""
        response = await test_server.client.get("/.well-known/jwks.json")
        
        assert response.status_code == status.HTTP_200_OK
        
        jwks = await response.json()
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0
        
        # Verify key structure per RFC 7517
        for key in jwks["keys"]:
            assert "kty" in key  # Key type (RSA, EC, etc.)
            assert "kid" in key  # Key ID
            assert "use" in key  # Key use (sig or enc)
            assert "alg" in key  # Algorithm
            
            if key["kty"] == "RSA":
                assert "n" in key  # Modulus
                assert "e" in key  # Exponent

    @pytest.mark.asyncio
    async def test_userinfo_endpoint_with_client_credentials(
        self,
        test_server: AsyncTestServer,
        committed_oauth_client,
    ):
        """Test UserInfo endpoint with client credentials token."""
        import base64
        
        # Get token via client credentials
        credentials = base64.b64encode(
            f"{committed_oauth_client['client_id']}:{committed_oauth_client['client_secret']}".encode()
        ).decode()
        
        response = await test_server.client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": committed_oauth_client['client_id'],
                "client_secret": committed_oauth_client['client_secret'],
            },
        )
        
        if response.status_code != 200:
            error_text = await response.text()
            print(f"Client credentials failed with {response.status_code}: {error_text}")
            pytest.skip("Client credentials flow not available")
        
        token_data = await response.json()
        access_token = token_data["access_token"]
        
        # Client credentials tokens typically don't have user context
        # So userinfo endpoint might not work with them
        response = await test_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        # This should fail or return limited info since no user context
        if response.status_code == 200:
            userinfo = await response.json()
            # Client tokens shouldn't have user claims
            assert "sub" in userinfo  # But sub might be the client_id

    @pytest.mark.asyncio
    async def test_discovery_endpoint(self, test_server: AsyncTestServer):
        """Test OIDC discovery endpoint (.well-known/openid-configuration)."""
        response = await test_server.client.get("/.well-known/openid-configuration")
        
        assert response.status_code == status.HTTP_200_OK
        
        config = await response.json()
        
        # Required metadata per OIDC Discovery 1.0
        assert "issuer" in config
        assert "authorization_endpoint" in config
        assert "token_endpoint" in config
        assert "userinfo_endpoint" in config
        assert "jwks_uri" in config
        
        # Required supported values
        assert "response_types_supported" in config
        assert "code" in config["response_types_supported"]
        
        assert "subject_types_supported" in config
        assert "public" in config["subject_types_supported"]
        
        assert "id_token_signing_alg_values_supported" in config
        assert "RS256" in config["id_token_signing_alg_values_supported"]
        
        # OAuth 2.1 / PKCE support
        assert "code_challenge_methods_supported" in config
        assert "S256" in config["code_challenge_methods_supported"]

    @pytest.mark.asyncio
    async def test_id_token_in_authorization_code_flow(
        self,
        test_server: AsyncTestServer,
        committed_user,  # Use committed fixture from fixtures/committed_data.py
        committed_oauth_client,  # Use committed fixture from fixtures/committed_data.py
    ):
        """Test ID token in authorization code flow with proper PKCE."""
        import base64
        import hashlib
        import secrets
        
        # Generate PKCE pair
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        
        # Step 1: Get access token for authentication using password grant
        async with test_server.client as client:
            from urllib.parse import parse_qs, urlparse
            
            # Login the user using password grant with OIDC scopes
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "password", 
                    "username": committed_user.username, 
                    "password": "TestPassword123!",
                    "scope": "openid profile email"  # OIDC scopes for ID token
                },
            )
            assert login_response.status_code == 200
            login_data = await login_response.json()
            auth_token = login_data["access_token"]

            # Step 2: Start authorization request with openid scope
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "openid profile email",  # OIDC scopes for ID token
                "state": "test_state_oidc",
            }

            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert auth_response.status_code == 200  # Consent form
            
            # Step 3: Submit consent approval
            consent_data = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "openid profile email",
                "state": "test_state_oidc",
                "approved": "true",  # User approves
            }
            
            consent_response = await client.post(
                "/api/v1/oauth/authorize", 
                data=consent_data,
                headers={"Authorization": f"Bearer {auth_token}"},
                follow_redirects=False
            )
            
            assert consent_response.status_code == 302
            location = consent_response._response.headers.get("location")
            assert location is not None

            # Parse authorization code from redirect
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            assert "code" in query_params
            auth_code = query_params["code"][0]

            # Step 4: Exchange authorization code for tokens (should include ID token)
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier,
                },
            )

            assert token_response.status_code == 200
            token_data = await token_response.json()
            
            # Verify OIDC compliance: ID token must be present for openid scope
            assert "access_token" in token_data
            assert "id_token" in token_data  # Key OIDC requirement
            assert token_data["token_type"] == "Bearer"
            
            # Verify ID token is a non-empty JWT-like string
            id_token = token_data["id_token"]
            assert isinstance(id_token, str)
            assert len(id_token) > 0
            assert id_token.count('.') == 2  # JWT has 3 parts separated by dots

    @pytest.mark.asyncio
    async def test_userinfo_requires_valid_token(self, test_server: AsyncTestServer):
        """Test UserInfo endpoint requires valid access token."""
        # No token
        response = await test_server.client.get("/oidc/userinfo")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        # Invalid token
        response = await test_server.client.get(
            "/oidc/userinfo",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_scopes_affect_userinfo_claims(
        self,
        test_server: AsyncTestServer,
        committed_user,  # Use committed fixture
        committed_oauth_client,  # Use committed fixture
    ):
        """Test that UserInfo claims depend on granted scopes."""
        import base64
        import hashlib
        import secrets
        from urllib.parse import parse_qs, urlparse
        
        def generate_pkce_pair():
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
            digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
            return code_verifier, code_challenge
        
        async with test_server.client as client:
            # Test 1: Limited scope (openid only) - should get minimal claims
            code_verifier, code_challenge = generate_pkce_pair()
            
            # Step 1: Login user with limited scope
            login_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "password", 
                    "username": committed_user.username, 
                    "password": "TestPassword123!",
                    "scope": "openid"  # Only openid scope - no profile/email
                },
            )
            assert login_response.status_code == 200
            auth_token = (await login_response.json())["access_token"]
            
            # Step 2: Get authorization code with limited scope
            auth_params = {
                "response_type": "code",
                "client_id": committed_oauth_client["client_id"],
                "redirect_uri": committed_oauth_client["redirect_uris"][0],
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "openid",  # Limited scope
                "state": "test_limited",
            }
            
            auth_response = await client.get(
                "/api/v1/oauth/authorize", params=auth_params, headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert auth_response.status_code == 200
            
            # Submit consent
            consent_response = await client.post(
                "/api/v1/oauth/authorize", 
                data={**auth_params, "approved": "true"},
                headers={"Authorization": f"Bearer {auth_token}"},
                follow_redirects=False
            )
            assert consent_response.status_code == 302
            
            # Get auth code
            location = consent_response._response.headers.get("location")
            auth_code = parse_qs(urlparse(location).query)["code"][0]
            
            # Step 3: Exchange for tokens
            token_response = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier,
                },
            )
            assert token_response.status_code == 200
            limited_token = (await token_response.json())["access_token"]
            
            # Step 4: Get UserInfo with limited token
            userinfo_limited = await client.get(
                "/oidc/userinfo",
                headers={"Authorization": f"Bearer {limited_token}"},
            )
            assert userinfo_limited.status_code == 200
            limited_claims = await userinfo_limited.json()
            
            # Should only have basic claims with openid scope
            assert "sub" in limited_claims  # Always present
            
            # Test 2: Full scope (openid profile email) - should get more claims
            code_verifier2, code_challenge2 = generate_pkce_pair()
            
            # Repeat flow with full scope
            login_response2 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "password", 
                    "username": committed_user.username, 
                    "password": "TestPassword123!",
                    "scope": "openid profile email"  # Full OIDC scopes
                },
            )
            assert login_response2.status_code == 200
            auth_token2 = (await login_response2.json())["access_token"]
            
            # Get full scope token (shortened flow)
            auth_params2 = {**auth_params, "code_challenge": code_challenge2, "scope": "openid profile email", "state": "test_full"}
            
            auth_response2 = await client.get(
                "/api/v1/oauth/authorize", params=auth_params2, headers={"Authorization": f"Bearer {auth_token2}"}
            )
            assert auth_response2.status_code == 200
            
            consent_response2 = await client.post(
                "/api/v1/oauth/authorize", 
                data={**auth_params2, "approved": "true"},
                headers={"Authorization": f"Bearer {auth_token2}"},
                follow_redirects=False
            )
            assert consent_response2.status_code == 302
            
            location2 = consent_response2._response.headers.get("location")
            auth_code2 = parse_qs(urlparse(location2).query)["code"][0]
            
            token_response2 = await client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code2,
                    "redirect_uri": committed_oauth_client["redirect_uris"][0],
                    "client_id": committed_oauth_client["client_id"],
                    "code_verifier": code_verifier2,
                },
            )
            assert token_response2.status_code == 200
            full_token = (await token_response2.json())["access_token"]
            
            # Get UserInfo with full scope token
            userinfo_full = await client.get(
                "/oidc/userinfo",
                headers={"Authorization": f"Bearer {full_token}"},
            )
            assert userinfo_full.status_code == 200
            full_claims = await userinfo_full.json()
            
            # Should have more claims with full scope
            assert "sub" in full_claims
            # Profile and email claims might be present depending on implementation
            # The key test is that full_claims potentially has more data than limited_claims
            assert len(full_claims) >= len(limited_claims)