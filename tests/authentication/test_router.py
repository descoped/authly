"""
Real-world tests for authentication router endpoints using FastAPI test server.

These tests use real FastAPI test server with actual database and Redis,
following Authly's testing philosophy of no mocking unless absolutely necessary.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.authentication.router import auth_router
from authly.authentication.service import AuthenticationService
from authly.users.models import UserModel
from authly.users.repository import UserRepository


@pytest.fixture
async def test_user(transaction_manager: TransactionManager) -> UserModel:
    """Create a real test user in the database."""
    user_id = uuid4()
    user_model = UserModel(
        id=user_id,
        username=f"testuser_{user_id.hex[:8]}",
        email=f"test_{user_id.hex[:8]}@example.com",
        password_hash=get_password_hash("TestPassword123!"),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        is_active=True,
        is_verified=True,
        is_admin=False,
    )

    async with transaction_manager.transaction() as conn:
        repo = UserRepository(conn)
        return await repo.create(user_model)


@pytest.fixture
async def auth_server(test_server: AsyncTestServer) -> AsyncTestServer:
    """Configure test server with authentication router."""
    test_server.app.include_router(auth_router)
    return test_server


@pytest.fixture
async def auth_service(initialize_authly) -> AuthenticationService:
    """Create a real authentication service."""
    from authly.core.backend_factory import get_session_backend

    backend = await get_session_backend()
    return AuthenticationService(backend)


class TestAuthenticationRouter:
    """Test authentication router endpoints with real server."""

    @pytest.mark.asyncio
    async def test_get_login_page_not_authenticated(self, auth_server: AsyncTestServer):
        """Test GET /auth/login when not authenticated."""
        response = await auth_server.client.get("/auth/login")
        await response.expect_status(200)

        content = await response.text()
        assert "Sign In" in content
        assert "csrf_token" in content
        assert '<form id="login-form"' in content

    @pytest.mark.asyncio
    async def test_get_login_page_already_authenticated(
        self, auth_server: AsyncTestServer, auth_service: AuthenticationService, test_user: UserModel
    ):
        """Test GET /auth/login when already authenticated redirects."""
        from authly.authentication.models import LoginRequest

        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Try to access login page with session cookie
        response = await auth_server.client.get(
            "/auth/login", cookies={"authly_session": session_id}, follow_redirects=False
        )

        # Should redirect to home since already logged in
        await response.expect_status(302)
        assert response._response.headers["location"] == "/"

    @pytest.mark.asyncio
    async def test_get_login_page_with_redirect(self, auth_server: AsyncTestServer):
        """Test GET /auth/login with redirect_to parameter."""
        response = await auth_server.client.get("/auth/login?redirect_to=/dashboard")
        await response.expect_status(200)

        content = await response.text()
        assert 'value="/dashboard"' in content

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_get_login_page_with_oauth_context(self, auth_server: AsyncTestServer):
        """Test GET /auth/login with OAuth redirect URL."""
        oauth_url = "/api/v1/oauth/authorize?client_id=test_client"
        response = await auth_server.client.get(f"/auth/login?redirect_to={oauth_url}")
        await response.expect_status(200)

        content = await response.text()
        assert "OAuth Context" in content or "OAuth Application" in content

    @pytest.mark.asyncio
    async def test_post_login_success(self, auth_server: AsyncTestServer, test_user: UserModel):
        """Test POST /auth/login with valid credentials."""
        # First get the login page to get CSRF token
        login_page = await auth_server.client.get("/auth/login")
        content = await login_page.text()

        # Extract CSRF token from the form
        import re

        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', content)
        csrf_token = csrf_match.group(1) if csrf_match else "test_token"

        # Login with valid credentials
        response = await auth_server.client.post(
            "/auth/login",
            data={
                "username": test_user.username,
                "password": "TestPassword123!",
                "csrf_token": csrf_token,
                "remember_me": "false",
            },
            follow_redirects=False,
        )

        await response.expect_status(302)
        assert response._response.headers["location"] == "/"

        # Check session cookie is set
        cookies = response._response.cookies
        assert "authly_session" in cookies

    @pytest.mark.asyncio
    async def test_post_login_with_redirect(self, auth_server: AsyncTestServer, test_user: UserModel):
        """Test POST /auth/login with redirect_to parameter."""
        # Get CSRF token
        login_page = await auth_server.client.get("/auth/login")
        content = await login_page.text()
        import re

        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', content)
        csrf_token = csrf_match.group(1) if csrf_match else "test_token"

        response = await auth_server.client.post(
            "/auth/login",
            data={
                "username": test_user.username,
                "password": "TestPassword123!",
                "csrf_token": csrf_token,
                "redirect_to": "/dashboard",
            },
            follow_redirects=False,
        )

        await response.expect_status(302)
        assert response._response.headers["location"] == "/dashboard"

    @pytest.mark.asyncio
    async def test_post_login_with_remember_me(self, auth_server: AsyncTestServer, test_user: UserModel):
        """Test POST /auth/login with remember_me option."""
        # Get CSRF token
        login_page = await auth_server.client.get("/auth/login")
        content = await login_page.text()
        import re

        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', content)
        csrf_token = csrf_match.group(1) if csrf_match else "test_token"

        response = await auth_server.client.post(
            "/auth/login",
            data={
                "username": test_user.username,
                "password": "TestPassword123!",
                "csrf_token": csrf_token,
                "remember_me": "true",
            },
            follow_redirects=False,
        )

        await response.expect_status(302)

        # Check cookie max-age for remember_me (24 hours)
        cookie_header = response._response.headers.get("set-cookie", "")
        assert "Max-Age=86400" in cookie_header or "max-age=86400" in cookie_header

    @pytest.mark.asyncio
    async def test_post_login_invalid_credentials(self, auth_server: AsyncTestServer):
        """Test POST /auth/login with invalid credentials."""
        # Get CSRF token
        login_page = await auth_server.client.get("/auth/login")
        content = await login_page.text()
        import re

        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', content)
        csrf_token = csrf_match.group(1) if csrf_match else "test_token"

        response = await auth_server.client.post(
            "/auth/login",
            data={"username": "wronguser", "password": "wrongpass", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        await response.expect_status(302)
        location = response._response.headers["location"]
        assert "/auth/login" in location
        assert "error=" in location

    @pytest.mark.asyncio
    async def test_logout_with_session(
        self, auth_server: AsyncTestServer, auth_service: AuthenticationService, test_user: UserModel
    ):
        """Test GET /auth/logout with valid session."""
        from authly.authentication.models import LoginRequest

        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        # Logout
        response = await auth_server.client.get(
            "/auth/logout", cookies={"authly_session": session_id}, follow_redirects=False
        )

        await response.expect_status(302)
        location = response._response.headers["location"]
        assert "/auth/login" in location
        assert "message=" in location

        # Check cookie is deleted
        cookie_header = response._response.headers.get("set-cookie", "")
        assert "authly_session" in cookie_header
        assert "Max-Age=0" in cookie_header or "expires=Thu, 01 Jan 1970" in cookie_header

    @pytest.mark.asyncio
    async def test_logout_without_session(self, auth_server: AsyncTestServer):
        """Test GET /auth/logout without session."""
        response = await auth_server.client.get("/auth/logout", follow_redirects=False)

        await response.expect_status(302)
        assert "/auth/login" in response._response.headers["location"]

    @pytest.mark.asyncio
    async def test_logout_with_redirect(
        self, auth_server: AsyncTestServer, auth_service: AuthenticationService, test_user: UserModel
    ):
        """Test GET /auth/logout with redirect_to parameter."""
        from authly.authentication.models import LoginRequest

        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        response = await auth_server.client.get(
            "/auth/logout?redirect_to=/goodbye", cookies={"authly_session": session_id}, follow_redirects=False
        )

        await response.expect_status(302)
        assert response._response.headers["location"] == "/goodbye"

    @pytest.mark.asyncio
    async def test_get_session_info_authenticated(
        self, auth_server: AsyncTestServer, auth_service: AuthenticationService, test_user: UserModel
    ):
        """Test GET /auth/session when authenticated."""
        from authly.authentication.models import LoginRequest

        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        response = await auth_server.client.get("/auth/session", cookies={"authly_session": session_id})

        await response.expect_status(200)
        data = await response.json()
        assert data["authenticated"] is True
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email
        assert "session_id" in data

    @pytest.mark.asyncio
    async def test_get_session_info_not_authenticated(self, auth_server: AsyncTestServer):
        """Test GET /auth/session when not authenticated."""
        response = await auth_server.client.get("/auth/session")

        await response.expect_status(401)
        data = await response.json()
        assert data["detail"] == "Not authenticated"

    @pytest.mark.asyncio
    async def test_validate_session_valid(
        self, auth_server: AsyncTestServer, auth_service: AuthenticationService, test_user: UserModel
    ):
        """Test POST /auth/session/validate with valid session."""
        from authly.authentication.models import LoginRequest

        # Create a session
        request = LoginRequest(username=test_user.username, password="TestPassword123!")
        session, session_id = await auth_service.login(request)

        response = await auth_server.client.post("/auth/session/validate", cookies={"authly_session": session_id})

        await response.expect_status(200)
        data = await response.json()
        assert data["valid"] is True
        assert data["username"] == test_user.username
        assert data["csrf_token"] == session.csrf_token

    @pytest.mark.asyncio
    async def test_validate_session_invalid(self, auth_server: AsyncTestServer):
        """Test POST /auth/session/validate with invalid session."""
        response = await auth_server.client.post("/auth/session/validate")

        await response.expect_status(200)
        data = await response.json()
        assert data["valid"] is False
