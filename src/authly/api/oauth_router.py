"""OAuth 2.1 API Router.

Provides OAuth 2.1 endpoints including discovery, authorization, and token operations.
"""

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from authly.api.auth_dependencies import (
    get_authorization_service,
    get_rate_limiter,
    get_scope_repository,
    get_token_service_with_client,
)
from authly.api.users_dependencies import get_current_user, get_user_repository
from authly.auth import decode_token, verify_password
from authly.config import AuthlyConfig
from authly.core.dependencies import get_config
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.discovery_service import DiscoveryService
from authly.oauth.models import (
    AuthorizationError,
    CodeChallengeMethod,
    Display,
    OAuthAuthorizationRequest,
    Prompt,
    ResponseMode,
    ResponseType,
    UserConsentRequest,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens import TokenService, get_token_service
from authly.users import UserModel, UserRepository

logger = logging.getLogger(__name__)

# OAuth2 scheme that doesn't auto-error for authorization endpoint
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/v1/oauth/token", auto_error=False)


def oauth_error_response(error: str, error_description: str = None, status_code: int = 400) -> JSONResponse:
    """
    Create an OAuth 2.0 compliant error response.

    Args:
        error: OAuth 2.0 error code (e.g., 'invalid_request', 'invalid_grant')
        error_description: Optional human-readable error description
        status_code: HTTP status code (default 400)

    Returns:
        JSONResponse with OAuth-compliant error format
    """
    content = {"error": error}
    if error_description:
        content["error_description"] = error_description
    return JSONResponse(content=content, status_code=status_code)


# Import authentication metrics tracking
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False
    metrics = None


# Token request/response models
class TokenRequest(BaseModel):
    """OAuth 2.1 Token Request."""

    grant_type: str = Field(..., description="The grant type")
    username: str | None = Field(None, description="Username for password grant")
    password: str | None = Field(None, description="Password for password grant")
    scope: str | None = Field(None, description="Requested scope")
    code: str | None = Field(None, description="Authorization code for authorization_code grant")
    redirect_uri: str | None = Field(None, description="Redirect URI for authorization_code grant")
    code_verifier: str | None = Field(None, description="PKCE code verifier")
    client_id: str | None = Field(None, description="OAuth client ID")
    client_secret: str | None = Field(None, description="OAuth client secret")
    refresh_token: str | None = Field(None, description="Refresh token for refresh_token grant")


class RefreshRequest(BaseModel):
    """OAuth 2.1 Refresh Token Request."""

    grant_type: str = Field("refresh_token", description="Must be 'refresh_token'")
    refresh_token: str = Field(..., description="The refresh token")
    scope: str | None = Field(None, description="Requested scope")


class TokenResponse(BaseModel):
    """OAuth 2.1 Token Response."""

    access_token: str = Field(..., description="The access token")
    token_type: str = Field("Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    refresh_token: str | None = Field(None, description="The refresh token")
    scope: str | None = Field(None, description="Granted scope")
    id_token: str | None = Field(None, description="OpenID Connect ID token")
    requires_password_change: bool | None = Field(None, description="Whether password change is required")


class TokenRevocationRequest(BaseModel):
    """OAuth 2.0 Token Revocation Request."""

    token: str = Field(..., description="The token to revoke (access or refresh token)")
    token_type_hint: str | None = Field(None, description="Optional hint: 'access_token' or 'refresh_token'")


# Create OAuth router
oauth_router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])


class LoginAttemptTracker:
    def __init__(self, config: AuthlyConfig | None = None):
        self.attempts: dict[str, dict[str, int | datetime | None]] = {}
        if config:
            self.lockout_duration = config.lockout_duration_seconds
            self.max_attempts = config.lockout_max_attempts
        else:
            self.lockout_duration = 300
            self.max_attempts = 5

    def check_and_update(self, username: str) -> bool:
        now = datetime.now(UTC)
        user_attempts = self.attempts.get(username, {"count": 0, "lockout_until": None})

        if isinstance(user_attempts["lockout_until"], datetime) and now < user_attempts["lockout_until"]:
            return False

        if user_attempts["count"] >= self.max_attempts:
            user_attempts["lockout_until"] = now + timedelta(seconds=self.lockout_duration)
            user_attempts["count"] = 0
            self.attempts[username] = user_attempts
            return False

        user_attempts["count"] += 1
        self.attempts[username] = user_attempts
        return True


# Global login tracker instance - will be initialized with config via dependency
_login_tracker: LoginAttemptTracker | None = None


def get_login_tracker(config: AuthlyConfig = Depends(get_config)) -> LoginAttemptTracker:
    """Get login tracker instance with configuration."""
    global _login_tracker
    if _login_tracker is None:
        _login_tracker = LoginAttemptTracker(config)
    return _login_tracker


# Configure template directory
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)


async def get_discovery_service(scope_repo: "ScopeRepository" = Depends(get_scope_repository)) -> DiscoveryService:
    """
    Get an instance of the DiscoveryService.

    Uses FastAPI dependency injection to properly get the scope repository
    with a database connection.

    Args:
        scope_repo: Injected scope repository with database connection

    Returns:
        DiscoveryService: Service with proper database connection
    """
    return DiscoveryService(scope_repo)


def _build_issuer_url(request: Request) -> str:
    """
    Build the issuer URL from the request.

    Args:
        request: FastAPI request object

    Returns:
        str: Complete issuer URL (e.g., https://auth.example.com)
    """
    # Use X-Forwarded-Proto and X-Forwarded-Host headers if available (for reverse proxy setups)
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)

    # Get host, handling the case where it might include port
    host_header = request.headers.get("x-forwarded-host", request.headers.get("host"))

    if host_header:
        # Host header might include port (e.g., "localhost:8000")
        # Parse it to separate hostname and port
        if ":" in host_header:
            host, header_port = host_header.split(":", 1)
            try:
                port_num = int(header_port)
            except ValueError:
                # If port in header is invalid, fall back to request URL
                host = request.url.hostname or "localhost"
                port_num = request.url.port
        else:
            host = host_header
            port_num = request.url.port
    else:
        # Fallback to request URL
        host = request.url.hostname or "localhost"
        port_num = request.url.port

    # Add port only if it's not standard (80 for HTTP, 443 for HTTPS)
    if port_num and not ((scheme == "https" and port_num == 443) or (scheme == "http" and port_num == 80)):
        return f"{scheme}://{host}:{port_num}"
    else:
        return f"{scheme}://{host}"


# OAuth 2.1 Discovery endpoint moved to oauth_discovery_router.py for RFC 8414 compliance
# The discovery endpoint must be accessible at /.well-known/oauth-authorization-server (root level)
# without API versioning prefixes, while business endpoints remain under /api/v1/oauth/


# OAuth 2.1 Authorization Endpoints


@oauth_router.get(
    "/authorize",
    summary="OAuth 2.1 Authorization Endpoint with OpenID Connect Support",
    description="""
    OAuth 2.1 Authorization endpoint (RFC 6749 Section 4.1.1) with OpenID Connect 1.0 support.

    Initiates the authorization code flow with PKCE. This endpoint validates
    the authorization request and serves a consent form for user approval.

    **Required Parameters:**
    - response_type: Must be 'code'
    - client_id: Registered client identifier
    - redirect_uri: Client redirect URI
    - code_challenge: PKCE code challenge (base64url, 43-128 chars)

    **Optional Parameters:**
    - scope: Requested scopes (space-separated)
    - state: CSRF protection parameter
    - code_challenge_method: Must be 'S256' (default)

    **OpenID Connect Parameters:**
    - nonce: Nonce for ID token binding
    - response_mode: How the response should be returned (query, fragment, form_post)
    - display: How the authorization server displays the interface (page, popup, touch, wap)
    - prompt: Whether to prompt for re-authentication/consent (none, login, consent, select_account)
    - max_age: Maximum authentication age in seconds
    - ui_locales: Preferred UI languages (space-separated)
    - id_token_hint: ID token hint for logout or re-authentication
    - login_hint: Hint to identify the user for authentication
    - acr_values: Authentication Context Class Reference values
    """,
    responses={
        200: {"description": "Authorization form displayed", "content": {"text/html": {}}},
        302: {"description": "Redirect to client with error"},
        400: {"description": "Invalid request parameters"},
    },
)
async def authorize_get(
    request: Request,
    response_type: str | None = Query(None, description="Must be 'code'"),
    client_id: str | None = Query(None, description="Client identifier"),
    redirect_uri: str | None = Query(None, description="Client redirect URI"),
    code_challenge: str | None = Query(None, description="PKCE code challenge"),
    scope: str | None = Query(None, description="Requested scopes"),
    state: str | None = Query(None, description="CSRF protection parameter"),
    code_challenge_method: str = Query("S256", description="PKCE challenge method"),
    # OpenID Connect parameters
    nonce: str | None = Query(None, description="OpenID Connect nonce"),
    response_mode: str | None = Query(None, description="Response mode"),
    display: str | None = Query(None, description="Display preference"),
    prompt: str | None = Query(None, description="Prompt parameter"),
    max_age: int | None = Query(None, description="Maximum authentication age"),
    ui_locales: str | None = Query(None, description="UI locales preference"),
    id_token_hint: str | None = Query(None, description="ID token hint"),
    login_hint: str | None = Query(None, description="Login hint"),
    acr_values: str | None = Query(None, description="ACR values"),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    # Authentication dependencies - using non-auto-error scheme for parameter validation
    token: Annotated[str | None, Depends(oauth2_scheme_optional)] = None,
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
):
    """
    OAuth 2.1 Authorization endpoint (GET).

    Validates the authorization request and displays a consent form.
    If user is not authenticated, redirects back to client with login_required error.
    """

    # CRITICAL: Validate required parameters FIRST (before authentication check)
    # Check basic required parameters
    if not response_type or not client_id or not redirect_uri:
        return JSONResponse(
            content={
                "error": "invalid_request",
                "error_description": "Missing required parameters: response_type, client_id, and redirect_uri are required",
            },
            status_code=400,
        )

    # This ensures PKCE is validated regardless of authentication status
    if not code_challenge:
        # PKCE is required for OAuth 2.1
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "code_challenge is required (PKCE)"},
            status_code=400,
        )

    if response_type != "code":
        # Only authorization code flow is supported
        return JSONResponse(
            content={
                "error": "unsupported_response_type",
                "error_description": "Only 'code' response type is supported",
            },
            status_code=400,
        )

    # NOW check authentication manually after parameter validation
    current_user = None
    if token:
        try:
            payload = decode_token(token, config.secret_key, config.algorithm)
            user_id_str = payload.get("sub")
            jti = payload.get("jti")

            # Check if token has valid user and hasn't been revoked
            if user_id_str and (jti is None or await token_service.is_token_valid(jti)):
                user_id = UUID(user_id_str)
                current_user = await user_repo.get_by_id(user_id)
                if current_user and not current_user.is_active:
                    current_user = None
        except Exception:
            # Invalid token, treat as not authenticated
            pass

    # Check if user is authenticated
    if not current_user:
        # User is not authenticated - redirect back with error
        error_params = {"error": "login_required", "error_description": "User authentication required"}
        if state:
            error_params["state"] = state
        error_url = f"{redirect_uri}?{urlencode(error_params)}"
        return RedirectResponse(url=error_url, status_code=302)

    try:
        # Create authorization request model with OpenID Connect parameters
        auth_request = OAuthAuthorizationRequest(
            response_type=ResponseType(response_type),
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=CodeChallengeMethod(code_challenge_method),
            scope=scope,
            state=state,
            # OpenID Connect parameters
            nonce=nonce,
            response_mode=ResponseMode(response_mode) if response_mode else None,
            display=Display(display) if display else None,
            prompt=Prompt(prompt) if prompt else None,
            max_age=max_age,
            ui_locales=ui_locales,
            id_token_hint=id_token_hint,
            login_hint=login_hint,
            acr_values=acr_values,
        )

        # Validate the authorization request
        is_valid, error_code, client = await authorization_service.validate_authorization_request(auth_request)

        if not is_valid:
            # Redirect back to client with error
            error_params = {"error": error_code}
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

        # Get requested scopes for display
        requested_scopes = await authorization_service.get_requested_scopes(scope, client)

        # Render the authorization consent template
        return templates.TemplateResponse(
            request=request,
            name="oauth/authorize.html",
            context={
                "client": client,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "requested_scopes": requested_scopes,
                "current_user": current_user,
                # OpenID Connect parameters
                "nonce": nonce,
                "response_mode": response_mode,
                "display": display,
                "prompt": prompt,
                "max_age": max_age,
                "ui_locales": ui_locales,
                "id_token_hint": id_token_hint,
                "login_hint": login_hint,
                "acr_values": acr_values,
                "is_oidc_request": auth_request.is_oidc_request(),
            },
        )

    except ValueError as e:
        # Invalid enum values
        logger.warning(f"Invalid parameter in authorization request: {e}")
        return oauth_error_response("invalid_request", "Invalid request parameters")

    except Exception as e:
        logger.error(f"Error in authorization endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authorization server error"
        ) from None


@oauth_router.post(
    "/authorize",
    summary="OAuth 2.1 Authorization Processing with OpenID Connect Support",
    description="""
    OAuth 2.1 Authorization processing endpoint (RFC 6749 Section 4.1.2) with OpenID Connect 1.0 support.
    Processes user consent and generates authorization code or returns error.
    This endpoint is called when the user submits the consent form.
    """,
    responses={
        302: {"description": "Redirect to client with code or error"},
        400: {"description": "Invalid request"},
        500: {"description": "Server error"},
    },
)
async def authorize_post(
    request: Request,
    response_type: str = Form("code"),  # OAuth requires this parameter
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str | None = Form(None),
    state: str | None = Form(None),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    approved: str = Form(...),  # "true" or "false"
    # OpenID Connect parameters
    nonce: str | None = Form(None),
    response_mode: str | None = Form(None),
    display: str | None = Form(None),
    prompt: str | None = Form(None),
    max_age: int | None = Form(None),
    ui_locales: str | None = Form(None),
    id_token_hint: str | None = Form(None),
    login_hint: str | None = Form(None),
    acr_values: str | None = Form(None),
    current_user: UserModel = Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
):
    """
    OAuth 2.1 Authorization processing endpoint (POST).

    Handles user consent and generates authorization code.
    """
    # Validate required parameters first
    if not code_challenge:
        # PKCE is required for OAuth 2.1
        return JSONResponse(
            content={"error": "invalid_request", "error_description": "code_challenge is required (PKCE)"},
            status_code=400,
        )

    if response_type != "code":
        # Only authorization code flow is supported
        return JSONResponse(
            content={
                "error": "unsupported_response_type",
                "error_description": "Only 'code' response type is supported",
            },
            status_code=400,
        )

    try:
        # Use the authenticated user ID from the JWT token
        authenticated_user_id = current_user.id

        # Convert approved string to boolean
        user_approved = approved.lower() == "true"

        if not user_approved:
            # User denied the request
            error_params = {
                "error": AuthorizationError.ACCESS_DENIED,
                "error_description": "The resource owner denied the request",
            }
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

        # Create consent request with OpenID Connect parameters
        consent_request = UserConsentRequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=CodeChallengeMethod(code_challenge_method),
            user_id=authenticated_user_id,
            approved=True,
            approved_scopes=scope.split() if scope else None,
            # OpenID Connect parameters
            nonce=nonce,
            response_mode=ResponseMode(response_mode) if response_mode else None,
            display=Display(display) if display else None,
            prompt=Prompt(prompt) if prompt else None,
            max_age=max_age,
            ui_locales=ui_locales,
            id_token_hint=id_token_hint,
            login_hint=login_hint,
            acr_values=acr_values,
        )

        # Generate authorization code
        auth_code = await authorization_service.generate_authorization_code(consent_request)

        if auth_code:
            # Success - redirect with authorization code
            success_params = {"code": auth_code}
            if state:
                success_params["state"] = state

            success_url = f"{redirect_uri}?{urlencode(success_params)}"
            return RedirectResponse(url=success_url, status_code=302)
        else:
            # Failed to generate code
            error_params = {
                "error": AuthorizationError.SERVER_ERROR,
                "error_description": "Failed to generate authorization code",
            }
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

    except Exception as e:
        logger.error(f"Error processing authorization: {e}")

        # Try to redirect with error, fall back to HTTP error
        try:
            error_params = {
                "error": AuthorizationError.SERVER_ERROR,
                "error_description": "Authorization server encountered an error",
            }
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authorization server error"
            ) from e


@oauth_router.post("/token")
async def get_access_token(
    grant_type: str = Form(..., description="The grant type"),
    username: str | None = Form(None, description="Username for password grant"),
    password: str | None = Form(None, description="Password for password grant"),
    scope: str | None = Form(None, description="Requested scope"),
    code: str | None = Form(None, description="Authorization code"),
    redirect_uri: str | None = Form(None, description="Redirect URI"),
    code_verifier: str | None = Form(None, description="PKCE code verifier"),
    client_id: str | None = Form(None, description="OAuth client ID"),
    client_secret: str | None = Form(None, description="OAuth client secret"),
    refresh_token: str | None = Form(None, description="Refresh token"),
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service_with_client),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    rate_limiter=Depends(get_rate_limiter),
    login_tracker: LoginAttemptTracker = Depends(get_login_tracker),
):
    """
    OAuth 2.1 Token Endpoint - supports multiple grant types.

    Accepts application/x-www-form-urlencoded as per OAuth 2.0 specification.

    Supported grant types:
    - password: Username/password authentication (existing)
    - authorization_code: OAuth 2.1 authorization code flow with PKCE
    - refresh_token: Refresh an access token
    """

    # Create a TokenRequest object from form data for backward compatibility
    request = TokenRequest(
        grant_type=grant_type,
        username=username,
        password=password,
        scope=scope,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
    )

    if request.grant_type == "password":
        return await _handle_password_grant(request, user_repo, token_service, rate_limiter, login_tracker)
    elif request.grant_type == "authorization_code":
        return await _handle_authorization_code_grant(request, user_repo, token_service, authorization_service)
    elif request.grant_type == "refresh_token":
        return await _handle_refresh_token_grant(request, user_repo, token_service)
    else:
        return oauth_error_response(
            "unsupported_grant_type", f"The authorization grant type '{request.grant_type}' is not supported"
        )


async def _handle_password_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
    rate_limiter,
    login_tracker: LoginAttemptTracker,
) -> TokenResponse:
    """Handle password grant type (existing functionality)."""
    import time

    start_time = time.time()

    # Validate required fields for password grant
    if not request.username or not request.password:
        # Track validation error
        if METRICS_ENABLED and metrics:
            metrics.track_oauth_token_request("password", "unknown", "validation_error", 0.0)
        return oauth_error_response("invalid_request", "Username and password are required for password grant")

    # Rate limiting check
    await rate_limiter.check_rate_limit(f"login:{request.username}")

    # Check login attempts
    if not login_tracker.check_and_update(request.username):
        # Track rate limit hit
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "rate_limited", duration)
            metrics.track_rate_limit_hit(request.username, "password_grant")
        return oauth_error_response(
            "invalid_grant", "Too many failed attempts. Account temporarily locked.", status_code=429
        )

    # Validate user
    user = await user_repo.get_by_username(request.username)
    if not user or not verify_password(request.password, user.password_hash):
        # Track authentication failure
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "invalid_credentials", duration)
            metrics.track_login_attempt("failed", "password", request.username)
        return oauth_error_response("invalid_grant", "Incorrect username or password")

    if not user.is_active:
        # Track inactive user attempt
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "user_inactive", duration)
        return oauth_error_response("invalid_grant", "Account is deactivated")

    if not user.is_verified:
        # Track unverified user attempt
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "user_unverified", duration)
        return oauth_error_response("invalid_grant", "Account not verified")

    try:
        # Create token pair using TokenService
        token_response = await token_service.create_token_pair(user, request.scope)

        # Clear failed attempts on successful login
        if request.username in login_tracker.attempts:
            del login_tracker.attempts[request.username]

        # Update last login
        await user_repo.update_last_login(user.id)

        # Check if password change is required
        response = TokenResponse(
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
        )

        if user.requires_password_change:
            logger.info(f"User {user.username} requires password change on login")
            response.requires_password_change = True

        # Track successful authentication
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "success", duration)
            metrics.track_login_attempt("success", "password", request.username)

        return response

    except HTTPException:
        # Let HTTPExceptions from TokenService pass through
        raise
    except Exception:
        # Track general authentication error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("password", request.username, "error", duration)
        return oauth_error_response("invalid_grant", "Could not create authentication tokens")


async def _handle_authorization_code_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
    authorization_service: AuthorizationService,
) -> TokenResponse:
    """Handle authorization_code grant type with PKCE verification."""
    import time

    start_time = time.time()

    # Validate required fields for authorization code grant
    if not request.code or not request.redirect_uri or not request.client_id or not request.code_verifier:
        # Track validation error
        if METRICS_ENABLED and metrics:
            metrics.track_oauth_token_request(
                "authorization_code", request.client_id or "unknown", "validation_error", 0.0
            )
        return oauth_error_response(
            "invalid_request",
            "code, redirect_uri, client_id, and code_verifier are required for authorization_code grant",
        )

    try:
        # Exchange authorization code for token data
        success, code_data, error_msg = await authorization_service.exchange_authorization_code(
            code=request.code,
            client_id=request.client_id,
            redirect_uri=request.redirect_uri,
            code_verifier=request.code_verifier,
        )

        if not success:
            # Track authorization code exchange failure
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request(
                    "authorization_code", request.client_id, "invalid_authorization_code", duration
                )
            logger.warning(f"Authorization code exchange failed: {error_msg}")
            return oauth_error_response("invalid_grant", error_msg or "Invalid authorization code")

        # Get user for token generation
        user = await user_repo.get_by_id(code_data["user_id"])
        if not user:
            # Track user not found error
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("authorization_code", request.client_id, "user_not_found", duration)
            logger.error(f"User not found for authorization code: {code_data['user_id']}")
            return oauth_error_response(
                "invalid_grant", "The provided authorization grant is invalid, expired, or revoked"
            )

        if not user.is_active:
            # Track inactive user attempt
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("authorization_code", request.client_id, "user_inactive", duration)
            return oauth_error_response("invalid_grant", "Account is deactivated")

        if not user.is_verified:
            # Track unverified user attempt
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("authorization_code", request.client_id, "user_unverified", duration)
            return oauth_error_response("invalid_grant", "Account not verified")

        # Extract OIDC parameters from authorization code data for ID token generation
        oidc_params = None
        if code_data.get("nonce") or code_data.get("max_age") or code_data.get("acr_values"):
            oidc_params = {
                "nonce": code_data.get("nonce"),
                "max_age": code_data.get("max_age"),
                "acr_values": code_data.get("acr_values"),
            }

        # Create token pair with scope information and OIDC parameters
        token_response = await token_service.create_token_pair(
            user, scope=code_data.get("scope"), client_id=code_data.get("client_id"), oidc_params=oidc_params
        )

        # Update last login
        await user_repo.update_last_login(user.id)

        # Track successful authorization code grant
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("authorization_code", request.client_id, "success", duration)
            metrics.track_login_attempt("success", "authorization_code", str(user.id))

        logger.info(f"Authorization code exchanged successfully for user {user.id}")

        return TokenResponse(
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            id_token=token_response.id_token,
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Track general authorization code grant error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("authorization_code", request.client_id or "unknown", "error", duration)
        logger.error(f"Error handling authorization code grant: {e}")
        return oauth_error_response("invalid_grant", "Could not process authorization code")


async def _handle_refresh_token_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
) -> TokenResponse:
    """Handle refresh_token grant type."""
    import time

    start_time = time.time()

    # Validate required fields for refresh token grant
    if not request.refresh_token:
        # Track validation error
        if METRICS_ENABLED and metrics:
            metrics.track_oauth_token_request("refresh_token", request.client_id or "unknown", "validation_error", 0.0)
        return oauth_error_response("invalid_request", "refresh_token is required for refresh_token grant")

    try:
        # Refresh token pair - client_id lookup will be handled by token service
        client_id = request.client_id if request.client_id else None
        token_response = await token_service.refresh_token_pair(request.refresh_token, user_repo, client_id=client_id)

        # Track successful refresh token grant
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("refresh_token", request.client_id or "unknown", "success", duration)

        logger.info("Refresh token exchanged successfully")

        return TokenResponse(
            access_token=token_response.access_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            refresh_token=token_response.refresh_token,
            id_token=token_response.id_token,
        )

    except HTTPException as he:
        # Convert HTTPExceptions to OAuth error responses
        # Track refresh token grant error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request(
                "refresh_token", request.client_id or "unknown", "invalid_grant", duration
            )

        # Map HTTP status codes to OAuth errors
        if he.status_code == status.HTTP_401_UNAUTHORIZED:
            return oauth_error_response("invalid_grant", he.detail)
        elif he.status_code == status.HTTP_400_BAD_REQUEST:
            return oauth_error_response("invalid_request", he.detail)
        else:
            return oauth_error_response("invalid_grant", he.detail)
    except Exception as e:
        # Track general refresh token grant error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("refresh_token", request.client_id or "unknown", "error", duration)
        logger.error(f"Error handling refresh token grant: {e}")
        return oauth_error_response("invalid_grant", "Could not process refresh token")


@oauth_router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke_token(
    request: TokenRevocationRequest,
    token_service: TokenService = Depends(get_token_service),
):
    """
    OAuth 2.0 Token Revocation Endpoint (RFC 7009).

    Allows clients to notify the authorization server that a previously obtained
    refresh or access token is no longer needed. This invalidates the token and,
    if applicable, related tokens.

    **Request Parameters:**
    - token: The token to revoke (access or refresh token)
    - token_type_hint: Optional hint ("access_token" or "refresh_token")

    **Response:**
    Always returns HTTP 200 OK per RFC 7009, even for invalid tokens.
    This prevents token enumeration attacks.
    """
    import time

    start_time = time.time()
    try:
        # Attempt to revoke the token using the token service
        revoked = await token_service.revoke_token(request.token, request.token_type_hint)

        # Track token revocation
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            status_result = "success" if revoked else "invalid_token"
            token_type = request.token_type_hint or "unknown"
            metrics.track_token_revocation(token_type, status_result)

        if revoked:
            logger.info("Token revoked successfully")
        else:
            # Don't log details about invalid tokens to prevent information leakage
            logger.debug("Token revocation request processed (token may have been invalid)")

        # Always return 200 OK per RFC 7009 Section 2.2:
        # "The authorization server responds with HTTP status code 200 if the token
        # has been revoked successfully or if the client submitted an invalid token"
        return {"message": "Token revocation processed successfully"}

    except Exception as e:
        # Track token revocation error
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            token_type = request.token_type_hint or "unknown"
            metrics.track_token_revocation(token_type, "error")
        # Even on errors, return 200 OK per RFC 7009 to prevent information disclosure
        logger.error(f"Error during token revocation: {e!s}")
        return {"message": "Token revocation processed successfully"}


@oauth_router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: RefreshRequest,
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service_with_client),
):
    """Create new token pair while invalidating old refresh token"""
    import time

    start_time = time.time()

    if request.grant_type != "refresh_token":
        # Track invalid grant type
        if METRICS_ENABLED and metrics:
            metrics.track_oauth_token_request("refresh_token", "unknown", "invalid_grant_type", 0.0)
        return oauth_error_response("unsupported_grant_type", "The authorization grant type is not supported")

    try:
        # Refresh token pair using TokenService
        token_response = await token_service.refresh_token_pair(request.refresh_token, user_repo)

        # Track successful token refresh
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("refresh_token", "unknown", "success", duration)

        return TokenResponse(
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            id_token=token_response.id_token,
        )

    except HTTPException as he:
        # Convert HTTPExceptions to OAuth error responses
        # Track token refresh error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("refresh_token", "unknown", "invalid_grant", duration)

        # Map HTTP status codes to OAuth errors
        if he.status_code == status.HTTP_401_UNAUTHORIZED:
            return oauth_error_response("invalid_grant", he.detail)
        elif he.status_code == status.HTTP_400_BAD_REQUEST:
            return oauth_error_response("invalid_request", he.detail)
        else:
            return oauth_error_response("invalid_grant", he.detail)
    except Exception:
        # Track token refresh error
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("refresh_token", "unknown", "error", duration)
        return oauth_error_response("invalid_grant", "Could not refresh tokens")
