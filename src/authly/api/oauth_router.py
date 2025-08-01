"""OAuth 2.1 API Router.

Provides OAuth 2.1 endpoints including discovery, authorization, and token operations.
"""

import logging
import os
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from authly.api.auth_dependencies import get_authorization_service, get_scope_repository
from authly.api.users_dependencies import get_current_user
from authly.core.dependencies import get_config
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.discovery_models import OAuthServerMetadata
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
from authly.users import UserModel

logger = logging.getLogger(__name__)

# Create OAuth router
oauth_router = APIRouter(prefix="/oauth", tags=["OAuth 2.1"])

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
    response_type: str = Query(..., description="Must be 'code'"),
    client_id: str = Query(..., description="Client identifier"),
    redirect_uri: str = Query(..., description="Client redirect URI"),
    code_challenge: str = Query(..., description="PKCE code challenge"),
    scope: Optional[str] = Query(None, description="Requested scopes"),
    state: Optional[str] = Query(None, description="CSRF protection parameter"),
    code_challenge_method: str = Query("S256", description="PKCE challenge method"),
    # OpenID Connect parameters
    nonce: Optional[str] = Query(None, description="OpenID Connect nonce"),
    response_mode: Optional[str] = Query(None, description="Response mode"),
    display: Optional[str] = Query(None, description="Display preference"),
    prompt: Optional[str] = Query(None, description="Prompt parameter"),
    max_age: Optional[int] = Query(None, description="Maximum authentication age"),
    ui_locales: Optional[str] = Query(None, description="UI locales preference"),
    id_token_hint: Optional[str] = Query(None, description="ID token hint"),
    login_hint: Optional[str] = Query(None, description="Login hint"),
    acr_values: Optional[str] = Query(None, description="ACR values"),
    current_user: UserModel = Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
):
    """
    OAuth 2.1 Authorization endpoint (GET).

    Validates the authorization request and displays a consent form.
    """
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request parameters")
    except Exception as e:
        logger.error(f"Error in authorization endpoint: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authorization server error")


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
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    approved: str = Form(...),  # "true" or "false"
    # OpenID Connect parameters
    nonce: Optional[str] = Form(None),
    response_mode: Optional[str] = Form(None),
    display: Optional[str] = Form(None),
    prompt: Optional[str] = Form(None),
    max_age: Optional[int] = Form(None),
    ui_locales: Optional[str] = Form(None),
    id_token_hint: Optional[str] = Form(None),
    login_hint: Optional[str] = Form(None),
    acr_values: Optional[str] = Form(None),
    current_user: UserModel = Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
):
    """
    OAuth 2.1 Authorization processing endpoint (POST).

    Handles user consent and generates authorization code.
    """
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
        except:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authorization server error")


# Additional OAuth endpoints to be implemented
# - POST /token (enhancement to existing auth endpoint)
# - POST /revoke (token revocation)
