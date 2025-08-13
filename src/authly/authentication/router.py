"""
Authentication router for browser-based login flows.

This module provides HTTP endpoints for login, logout, and session management
to enable browser-based OAuth Authorization Code flows.
"""

import logging
import os
import secrets
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from authly.authentication.models import LoginRequest
from authly.authentication.service import AuthenticationError, AuthenticationService

logger = logging.getLogger(__name__)

# Configure template directories - authentication templates and shared core templates
AUTH_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
CORE_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "core", "templates")
templates = Jinja2Templates(directory=[AUTH_TEMPLATES_DIR, CORE_TEMPLATES_DIR])

# Create router
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

# Cookie configuration
COOKIE_NAME = "authly_session"
COOKIE_HTTPONLY = True
COOKIE_SECURE = False  # Set to True in production with HTTPS
COOKIE_SAMESITE = "lax"


async def get_auth_service() -> AuthenticationService:
    """Get authentication service dependency."""
    from authly.core.backend_factory import get_session_backend

    backend = await get_session_backend()
    return AuthenticationService(backend)


async def get_current_session(session_cookie: str | None = Cookie(None, alias=COOKIE_NAME)) -> dict | None:
    """Get current user session from cookie."""
    if not session_cookie:
        return None

    try:
        from authly.core.backend_factory import get_session_backend

        backend = await get_session_backend()
        auth_service = AuthenticationService(backend)
        return await auth_service.get_user_from_session(session_cookie)
    except Exception as e:
        logger.error(f"Error getting session: {e!s}")
        return None


@auth_router.get("/login", response_class=HTMLResponse)
async def show_login_page(
    request: Request,
    redirect_to: str | None = None,
    error: str | None = None,
    message: str | None = None,
    session: dict | None = Depends(get_current_session),
):
    """
    Display the login page.

    If user is already logged in, redirect to the target or home.
    """
    # If already logged in, redirect
    if session:
        if redirect_to:
            return RedirectResponse(url=redirect_to, status_code=302)
        return RedirectResponse(url="/", status_code=302)

    # Generate CSRF token for the form
    csrf_token = secrets.token_urlsafe(32)

    # Store CSRF token in session storage (in production, use Redis or similar)
    # For now, we'll pass it through the form

    # Parse OAuth context from redirect_to if it's an authorize URL
    oauth_context = None
    if redirect_to and "/oauth/authorize" in redirect_to:
        parsed = urlparse(redirect_to)
        params = parse_qs(parsed.query)
        if "client_id" in params:
            # In production, look up client details
            oauth_context = {
                "client_name": "OAuth Application",  # Would be fetched from database
                "client_id": params.get("client_id", [""])[0],
            }

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "redirect_to": redirect_to,
            "error": error,
            "message": message,
            "csrf_token": csrf_token,
            "oauth_context": oauth_context,
        },
    )


@auth_router.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False),
    redirect_to: str | None = Form(None),
    csrf_token: str = Form(...),
    auth_service: AuthenticationService = Depends(get_auth_service),
):
    """
    Process login form submission.

    Creates a session and sets a cookie on successful authentication.
    """
    try:
        # Get client info
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

        # Create login request
        login_request = LoginRequest(username=username, password=password, remember_me=remember_me)

        # Authenticate and create session
        session, session_id = await auth_service.login(login_request, ip_address=client_ip, user_agent=user_agent)

        # Determine redirect URL
        if not redirect_to:
            redirect_to = "/"

        # Create redirect response
        redirect_response = RedirectResponse(url=redirect_to, status_code=302)

        # Set session cookie
        max_age = 86400 if remember_me else 1800  # 24 hours or 30 minutes
        redirect_response.set_cookie(
            key=COOKIE_NAME,
            value=session_id,
            max_age=max_age,
            httponly=COOKIE_HTTPONLY,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
        )

        logger.info(f"User {username} logged in successfully")
        return redirect_response

    except AuthenticationError as e:
        # Redirect back to login with error
        error_params = urlencode({"error": str(e), "redirect_to": redirect_to or ""})
        return RedirectResponse(url=f"/auth/login?{error_params}", status_code=302)
    except Exception as e:
        logger.error(f"Login error: {e!s}")
        error_params = urlencode(
            {"error": "An error occurred during login. Please try again.", "redirect_to": redirect_to or ""}
        )
        return RedirectResponse(url=f"/auth/login?{error_params}", status_code=302)


@auth_router.get("/logout")
@auth_router.post("/logout")
async def logout(
    response: Response,
    redirect_to: str | None = None,
    session_cookie: str | None = Cookie(None, alias=COOKIE_NAME),
    auth_service: AuthenticationService = Depends(get_auth_service),
):
    """
    Log out the current user.

    Invalidates the session and clears the cookie.
    """
    # Invalidate session if exists
    if session_cookie:
        await auth_service.logout(session_cookie)

    # Determine redirect URL
    if not redirect_to:
        redirect_to = "/auth/login?message=You have been logged out successfully"

    # Create redirect response and clear cookie
    redirect_response = RedirectResponse(url=redirect_to, status_code=302)
    redirect_response.delete_cookie(key=COOKIE_NAME)

    return redirect_response


@auth_router.get("/session")
async def get_session_info(session: dict | None = Depends(get_current_session)):
    """
    Get current session information.

    Returns user info if logged in, or 401 if not authenticated.
    """
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {
        "authenticated": True,
        "username": session["username"],
        "email": session["email"],
        "is_admin": session["is_admin"],
        "session_id": session["session_id"][:8] + "...",  # Partial for security
    }


@auth_router.post("/session/validate")
async def validate_session(session: dict | None = Depends(get_current_session)):
    """
    Validate the current session.

    Used by JavaScript to check if user is still logged in.
    """
    if not session:
        return {"valid": False}

    return {"valid": True, "username": session["username"], "csrf_token": session["csrf_token"]}
