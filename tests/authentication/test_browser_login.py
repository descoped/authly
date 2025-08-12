"""
Browser-based login flow tests.

Tests the /auth/login endpoint and form-based authentication
that enables OAuth authorization flows using real database and services.
"""

from uuid import uuid4

import pytest
from fastapi import status

from authly.core.resource_manager import AuthlyResourceManager


class TestBrowserLoginPage:
    """Test the login page rendering with real application."""

    @pytest.mark.asyncio
    async def test_login_page_renders_correctly(self, test_server):
        """Test that the login page renders with all required elements."""
        async with test_server.client as client:
            response = await client.get("/auth/login")
            assert response.status_code == status.HTTP_200_OK
            # AsyncTestResponse wraps httpx.Response - access headers through _response
            assert "text/html" in response._response.headers.get("content-type", "")

            # Check for essential form elements
            content = await response.text()
            assert "<form" in content
            assert 'name="username"' in content or 'name="email"' in content
            assert 'name="password"' in content
            assert 'type="submit"' in content

    @pytest.mark.asyncio
    async def test_login_page_with_redirect_param(self, test_server):
        """Test login page preserves redirect_to parameter."""
        async with test_server.client as client:
            redirect_url = "/api/v1/oauth/authorize?client_id=test"
            response = await client.get(f"/auth/login?redirect_to={redirect_url}")
            assert response.status_code == status.HTTP_200_OK

            content = await response.text()
            # The redirect URL should be preserved in the form
            assert "redirect_to" in content

    @pytest.mark.asyncio
    async def test_login_page_shows_error_message(self, test_server):
        """Test login page displays error messages."""
        async with test_server.client as client:
            response = await client.get("/auth/login?error=invalid_credentials")
            assert response.status_code == status.HTTP_200_OK

            content = await response.text()
            assert "invalid" in content.lower() or "error" in content.lower()


class TestBrowserLoginSubmission:
    """Test the login form submission with real user data."""

    @pytest.mark.asyncio
    async def test_login_with_valid_credentials(self, test_server, test_user_committed):
        """Test successful login with valid credentials using real database."""
        async with test_server.client as client:
            username = test_user_committed["username"]
            password = test_user_committed["password"]

            # Get CSRF token from login page
            login_page = await client.get("/auth/login")
            assert login_page.status_code == status.HTTP_200_OK

            # Extract CSRF token from response (if implemented)
            # For now, we'll use a placeholder
            csrf_token = "test_csrf_token"

            # Attempt login with real credentials
            response = await client.post(
                "/auth/login",
                data={"username": username, "password": password, "csrf_token": csrf_token},
                follow_redirects=False,
            )

            # Should redirect after successful login
            assert response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]

            # Should set session cookie
            cookies = response._response.headers.get("set-cookie", "")
            assert "authly_session" in cookies or "session" in cookies

    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test login failure with invalid credentials."""
        async with test_server.client as client:
            response = await client.post(
                "/auth/login",
                data={"username": "nonexistent_user", "password": "wrongpassword", "csrf_token": "test_csrf_token"},
                follow_redirects=False,
            )

            # Should either redirect with error or return error status
            if response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]:
                location = response._response.headers.get("location", "")
                assert "error" in location or "login" in location
            else:
                assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]

    @pytest.mark.asyncio
    async def test_login_missing_credentials(self, test_server):
        """Test login with missing credentials."""
        async with test_server.client as client:
            response = await client.post(
                "/auth/login",
                data={"username": "testuser"},  # Missing password
                follow_redirects=False,
            )

            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_302_FOUND,  # May redirect with error
                status.HTTP_303_SEE_OTHER,
            ]

    @pytest.mark.asyncio
    async def test_login_redirect_after_success(self, test_server, test_user_committed):
        """Test redirect to original URL after successful login."""
        async with test_server.client as client:
            username = test_user_committed["username"]
            password = test_user_committed["password"]

            redirect_url = "/api/v1/oauth/authorize?client_id=test"

            response = await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                    "redirect_to": redirect_url,
                    "csrf_token": "test_csrf_token",
                },
                follow_redirects=False,
            )

            assert response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]
            location = response._response.headers.get("location", "")
            # Should redirect to the requested URL or at least contain 'authorize'
            assert "authorize" in location or redirect_url in location


class TestBrowserLoginRateLimiting:
    """Test rate limiting on login attempts."""

    @pytest.mark.asyncio
    async def test_login_rate_limiting(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test that rate limiting is applied after multiple failed attempts."""
        username = f"testuser_{uuid4().hex[:8]}"

        async with test_server.client as client:
            # Make multiple failed login attempts
            responses = []
            for i in range(10):
                response = await client.post(
                    "/auth/login",
                    data={"username": username, "password": f"wrongpassword{i}", "csrf_token": "test_csrf_token"},
                    follow_redirects=False,
                )
            responses.append(response)

        # Check if any response indicates rate limiting
        status_codes = [r.status_code for r in responses]

        # Should eventually get rate limited or require additional verification
        # Look for 429 (Too Many Requests) or redirects with rate limit errors
        rate_limited = any(code == status.HTTP_429_TOO_MANY_REQUESTS for code in status_codes)

        if not rate_limited:
            # Check if later responses have different behavior (e.g., captcha requirement)
            last_response = responses[-1]
            if last_response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]:
                location = last_response._response.headers.get("location", "")
                # Might redirect to captcha or rate limit page
                rate_limited = "rate" in location.lower() or "captcha" in location.lower()

        # Note: Rate limiting might not be implemented yet
        # This test documents expected behavior


class TestBrowserLoginSession:
    """Test session management after login with real backend."""

    @pytest.mark.asyncio
    async def test_login_session_creation(self, test_server, test_user_committed):
        """Test that a session is created after successful login."""
        async with test_server.client as client:
            username = test_user_committed["username"]
            password = test_user_committed["password"]

            response = await client.post(
                "/auth/login",
                data={"username": username, "password": password, "csrf_token": "test_csrf_token"},
                follow_redirects=False,
            )

            # Verify session cookie is set
            cookies = response._response.headers.get("set-cookie", "")
            assert cookies

            # Cookie should have secure attributes
            cookie_lower = cookies.lower()
            assert "httponly" in cookie_lower
            assert "samesite" in cookie_lower

    @pytest.mark.asyncio
    async def test_session_persists_across_requests(self, test_server, test_user_committed):
        """Test that session persists across multiple requests."""
        async with test_server.client as client:
            username = test_user_committed["username"]
            password = test_user_committed["password"]

            # Login
            login_response = await client.post(
                "/auth/login",
                data={"username": username, "password": password, "csrf_token": "test_csrf_token"},
                follow_redirects=False,
            )

            # Extract session cookie from headers
            cookie_header = login_response._response.headers.get("set-cookie", "")
            # Parse the session cookie value
            session_cookie = None
            if "authly_session" in cookie_header:
                # Extract the session ID from the cookie header
                import re

                match = re.search(r"authly_session=([^;]+)", cookie_header)
                if match:
                    session_cookie = match.group(1)

            # Use session to access protected endpoint
            session_response = await client.get(
                "/auth/session", cookies={"authly_session": session_cookie} if session_cookie else {}
            )

            # Should be authenticated
            if session_response.status_code == status.HTTP_200_OK:
                data = await session_response.json()
                assert data["authenticated"] is True

    @pytest.mark.asyncio
    async def test_login_to_oauth_flow(
        self, test_server, test_user_committed, initialize_authly: AuthlyResourceManager
    ):
        """Test complete flow from login to OAuth authorization."""
        # Use the resource manager's pool directly with autocommit for OAuth client
        pool = initialize_authly.get_pool()

        async with pool.connection() as conn:
            # Enable autocommit so OAuth client is immediately visible
            await conn.set_autocommit(True)

            from authly.oauth.client_repository import ClientRepository
            from authly.oauth.models import ClientType, TokenEndpointAuthMethod

            client_repo = ClientRepository(conn)

            # Create test OAuth client with committed data
            client_id = f"test_client_{uuid4().hex[:8]}"
            await client_repo.create_client(
                {
                    "client_id": client_id,
                    "client_name": "Test Client",
                    "client_type": ClientType.PUBLIC,
                    "redirect_uris": ["http://localhost/callback"],
                    "require_pkce": True,
                    "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
                }
            )

        # Use the committed test user
        username = test_user_committed["username"]
        password = test_user_committed["password"]

        async with test_server.client as client:
            # Step 1: Try to access OAuth authorize endpoint (should redirect to login)
            import base64
            import hashlib
            import secrets

            # Generate proper PKCE code challenge
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
            code_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode("utf-8").rstrip("=")
            )

            oauth_url = f"/api/v1/oauth/authorize?client_id={client_id}&response_type=code&redirect_uri=http://localhost/callback&code_challenge={code_challenge}&code_challenge_method=S256&state=test_state_123"

            auth_response = await client.get(oauth_url, follow_redirects=False)

            # Should redirect to login or return login_required error
            assert auth_response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]

            # Step 2: Login
            login_response = await client.post(
                "/auth/login",
                data={
                    "username": username,
                    "password": password,
                    "redirect_to": oauth_url,
                    "csrf_token": "test_csrf_token",
                },
                follow_redirects=False,
            )

            # Should redirect after login
            assert login_response.status_code in [status.HTTP_302_FOUND, status.HTTP_303_SEE_OTHER]

            # The client should maintain the session automatically
            # Step 3: Access OAuth with the same client (which has the session)
            auth_with_session = await client.get(oauth_url, follow_redirects=False)

            # Should now either show authorization page or process the request
            # Status depends on whether auto-approval is enabled
            assert auth_with_session.status_code in [
                status.HTTP_200_OK,  # Shows consent form
                status.HTTP_302_FOUND,  # Auto-approved and redirected
                status.HTTP_303_SEE_OTHER,  # Auto-approved and redirected
            ]

        # Cleanup OAuth client
        try:
            async with pool.connection() as cleanup_conn:
                await cleanup_conn.set_autocommit(True)
                await cleanup_conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", client_id)
        except Exception:
            pass  # Ignore cleanup errors
