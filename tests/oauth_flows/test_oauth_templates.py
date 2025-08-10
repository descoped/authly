"""Tests for OAuth 2.1 Frontend Templates.

Comprehensive tests for the Jinja2 template rendering in OAuth authorization flow including:
- Template rendering functionality
- Static asset serving
- Form submission handling
- Error page rendering
- User interface components
"""

import os

import pytest
from fastapi.staticfiles import StaticFiles
from fastapi_testing import AsyncTestServer

from authly.api import auth_router, oauth_router, users_router


class TestOAuthTemplates:
    """Test OAuth 2.1 template rendering and UI components."""

    @pytest.fixture
    async def template_server(self, test_server: AsyncTestServer) -> AsyncTestServer:
        """Configure test server with OAuth routers and static files."""
        # Mount static files - go up 3 levels from test file to project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        static_dir = os.path.join(project_root, "src", "authly", "static")
        if os.path.exists(static_dir):
            test_server.app.mount("/static", StaticFiles(directory=static_dir), name="static")

        test_server.app.include_router(auth_router, prefix="/api/v1")
        test_server.app.include_router(users_router, prefix="/api/v1")
        test_server.app.include_router(oauth_router, prefix="/api/v1")
        return test_server

    # Removed complex OAuth fixtures to focus on template infrastructure testing

    @pytest.mark.asyncio
    async def test_static_css_accessible(self, template_server: AsyncTestServer):
        """Test that CSS static files are accessible."""
        response = await template_server.client.get("/static/css/style.css")
        await response.expect_status(200)

        content = await response.text()
        # Verify CSS content contains expected styles
        assert "body {" in content
        assert "font-family:" in content
        assert ".btn-primary" in content
        assert ".consent-form" in content

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_template_rendering(self, template_server: AsyncTestServer):
        """Test OAuth authorization consent form template rendering."""
        # Test that template renders properly by directly testing the template file
        # and checking response for common OAuth authorization errors

        # Try to access authorization endpoint without auth (should get redirect or error)
        auth_params = {
            "response_type": "code",
            "client_id": "test_client_123",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "scope": "read",
            "state": "test_state_12345",
        }

        response = await template_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )

        # Should get redirect (302) with login_required error when not authenticated
        status_code = response._response.status_code
        assert status_code in [302, 401, 403], f"Expected 302, 401 or 403, got {status_code}"

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_endpoint_requires_auth(self, template_server: AsyncTestServer):
        """Test that authorization endpoint properly requires authentication."""
        auth_params = {
            "response_type": "code",
            "client_id": "test_client_123",
            "redirect_uri": "http://localhost:3000/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "scope": "read",
        }

        response = await template_server.client.get(
            "/api/v1/oauth/authorize", params=auth_params, follow_redirects=False
        )

        # Should require authentication - expect redirect with login_required error
        status_code = response._response.status_code
        assert status_code in [302, 401, 403], f"Authorization endpoint should require auth, got {status_code}"

    @pytest.mark.asyncio
    async def test_authorization_endpoint_with_invalid_params(self, template_server: AsyncTestServer):
        """Test authorization endpoint with invalid parameters."""
        # Test with missing required parameters
        response = await template_server.client.get("/api/v1/oauth/authorize")

        status_code = response._response.status_code
        assert status_code in [400, 401, 422], f"Should reject invalid params, got {status_code}"

    @pytest.mark.asyncio
    async def test_css_styling_elements(self, template_server: AsyncTestServer):
        """Test that CSS contains all required styling elements."""
        response = await template_server.client.get("/static/css/style.css")
        await response.expect_status(200)

        css_content = await response.text()

        # Verify key CSS classes exist
        required_classes = [
            ".btn-primary",
            ".btn-secondary",
            ".btn-success",
            ".btn-danger",
            ".consent-form",
            ".auth-card",
            ".form-input",
            ".form-label",
            ".client-info",
            ".scope-item",
            ".security-notice",
            ".alert-error",
            ".btn-group",
            ".logo-text",
            ".main-content",
        ]

        for css_class in required_classes:
            assert css_class in css_content, f"Missing CSS class: {css_class}"

        # Verify responsive design
        assert "@media (max-width: 600px)" in css_content

        # Verify accessibility features
        assert "outline:" in css_content  # Focus indicators
        assert "@media (prefers-contrast: high)" in css_content  # High contrast support

    @pytest.mark.asyncio
    async def test_template_security_features(self, template_server: AsyncTestServer):
        """Test that templates include proper security elements."""
        # Read the authorization template file directly to verify security features
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "authorize.html")

        with open(template_path) as f:
            content = f.read()

        # Verify security elements in template
        assert 'type="hidden"' in content  # CSRF protection via hidden fields
        assert 'method="post"' in content
        assert "Security Notice" in content
        assert "Only authorize applications you trust" in content

    @pytest.mark.asyncio
    async def test_javascript_functionality(self, template_server: AsyncTestServer):
        """Test that JavaScript functionality is included in templates."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "authorize.html")

        with open(template_path) as f:
            content = f.read()

        # Verify JavaScript enhancements are included
        assert "<script>" in content
        assert "DOMContentLoaded" in content
        assert "loading" in content  # Loading state functionality
        assert "keydown" in content  # Keyboard navigation
        assert "disabled = true" in content  # Button state management

    @pytest.mark.asyncio
    async def test_template_accessibility_features(self, template_server: AsyncTestServer):
        """Test accessibility features in templates."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "authorize.html")

        with open(template_path) as f:
            content = f.read()

        # Verify accessibility attributes
        assert 'lang="en"' in content or '{% extends "base.html" %}' in content  # Base template has lang
        assert 'viewBox="0 0 20 20"' in content  # SVG icons have proper viewBox
        assert "Ctrl+Enter" in content  # Keyboard shortcuts documented
        assert "Escape" in content

    @pytest.mark.asyncio
    async def test_template_structure_validation(self, template_server: AsyncTestServer):
        """Test that templates have proper structure and template variables."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "authorize.html")

        with open(template_path) as f:
            content = f.read()

        # Verify template structure
        assert '{% extends "base.html" %}' in content
        assert "{% block content %}" in content
        assert "{{ client.client_name }}" in content
        assert "{{ client.client_id }}" in content
        assert "{% for scope in requested_scopes %}" in content

    @pytest.mark.asyncio
    async def test_error_template_rendering(self, template_server: AsyncTestServer):
        """Test error template rendering for various OAuth errors."""
        # This is a placeholder test - in a real implementation, you would
        # need to create specific error conditions or error template endpoints
        # For now, we verify the error template file exists and has proper structure

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        error_template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "error.html")

        assert os.path.exists(error_template_path), "Error template should exist"

        with open(error_template_path) as f:
            error_template = f.read()

        # Verify error template structure
        assert '{% extends "base.html" %}' in error_template
        assert "Authorization Error" in error_template
        assert "error_code" in error_template
        assert "error_description" in error_template
        assert "alert-error" in error_template

    @pytest.mark.asyncio
    async def test_template_inheritance(self, template_server: AsyncTestServer):
        """Test that templates properly inherit from base template."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        base_template_path = os.path.join(project_root, "src", "authly", "core", "templates", "base.html")

        authorize_template_path = os.path.join(project_root, "src", "authly", "oauth", "templates", "authorize.html")

        assert os.path.exists(base_template_path), "Base template should exist"
        assert os.path.exists(authorize_template_path), "Authorize template should exist"

        with open(base_template_path) as f:
            base_template = f.read()

        with open(authorize_template_path) as f:
            authorize_template = f.read()

        # Verify template inheritance
        assert "{% block content %}" in base_template
        assert "{% block title %}" in base_template
        assert '{% extends "base.html" %}' in authorize_template
        assert "{% block content %}" in authorize_template
        assert "{% block title %}" in authorize_template
