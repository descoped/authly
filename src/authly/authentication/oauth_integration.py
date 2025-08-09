"""
OAuth integration for browser-based authentication.

This module patches the OAuth authorization endpoint to support
both session-based (browser) and token-based (API) authentication.
"""

import logging
from urllib.parse import quote, urlencode
from uuid import UUID

from fastapi import Cookie, Depends, Query, Request
from fastapi.responses import RedirectResponse

from authly.api.auth_dependencies import get_authorization_service, oauth2_scheme_optional
from authly.api.oauth_router import oauth_router, templates
from authly.api.users_dependencies import get_user_repository
from authly.auth import decode_token
from authly.authentication.service import AuthenticationService
from authly.config import AuthlyConfig
from authly.core.dependencies import get_config
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.models import (
    CodeChallengeMethod,
    Display,
    OAuthAuthorizationRequest,
    Prompt,
    ResponseMode,
    ResponseType,
)
from authly.tokens import TokenService, get_token_service
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)

# Cookie configuration (must match router.py)
COOKIE_NAME = "authly_session"


async def get_current_user_for_oauth(
    request: Request,
    token: str | None = Depends(oauth2_scheme_optional),
    session_cookie: str | None = Cookie(None, alias=COOKIE_NAME),
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> UserModel | None:
    """
    Get current user from either session cookie or Bearer token for OAuth flows.

    This dependency supports both browser-based (session) and API-based (Bearer token)
    authentication methods, allowing the OAuth authorization endpoint to work with both.

    Priority:
    1. Check for session cookie (browser flow)
    2. Check for Bearer token (API flow)
    3. Return None if neither present
    """
    # First, try session-based authentication (browser flow)
    if session_cookie:
        try:
            from authly.core.backend_factory import get_session_backend

            backend = await get_session_backend()
            auth_service = AuthenticationService(backend)
            session_data = await auth_service.get_user_from_session(session_cookie)

            if session_data:
                # Get full user model
                user = await user_repo.get_by_id(UUID(session_data["id"]))
                if user and user.is_active:
                    logger.debug(f"OAuth: User {user.username} authenticated via session")
                    return user
        except Exception as e:
            logger.debug(f"OAuth: Session authentication failed: {e!s}")

    # Second, try token-based authentication (API flow)
    if token:
        try:
            payload = decode_token(token, config.secret_key, config.algorithm)
            user_id_str = payload.get("sub")
            jti = payload.get("jti")

            # Check if token has valid user and hasn't been revoked
            if user_id_str and (jti is None or await token_service.is_token_valid(jti)):
                user_id = UUID(user_id_str)
                user = await user_repo.get_by_id(user_id)
                if user and user.is_active:
                    logger.debug(f"OAuth: User {user.username} authenticated via Bearer token")
                    return user
        except Exception as e:
            logger.debug(f"OAuth: Token authentication failed: {e!s}")

    # No authentication method succeeded
    return None


def patch_oauth_authorization_endpoints():
    """
    Patch the OAuth authorization endpoints to support session-based authentication.

    This function modifies the existing OAuth router to add session support
    while maintaining backward compatibility with token-based authentication.
    """

    # Remove the existing authorize_get endpoint
    for route in oauth_router.routes[:]:
        if route.path == "/authorize" and "GET" in route.methods:
            oauth_router.routes.remove(route)
            break

    # Add the new authorize_get with session support
    @oauth_router.get(
        "/authorize",
        summary="OAuth 2.1 Authorization with Session Support",
        description="""
        OAuth 2.1 Authorization endpoint with support for both session-based
        (browser) and token-based (API) authentication.
        """,
        responses={
            200: {"description": "Authorization form displayed"},
            302: {"description": "Redirect to client or login"},
            400: {"description": "Invalid request parameters"},
        },
    )
    async def authorize_get_with_session(
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
        # Dependencies
        authorization_service: AuthorizationService = Depends(get_authorization_service),
        current_user: UserModel | None = Depends(get_current_user_for_oauth),
    ):
        """
        OAuth 2.1 Authorization endpoint with session support.
        """
        from fastapi.responses import JSONResponse

        # Validate required parameters
        if not response_type or not client_id or not redirect_uri:
            return JSONResponse(
                content={
                    "error": "invalid_request",
                    "error_description": "Missing required parameters",
                },
                status_code=400,
            )

        # PKCE is required
        if not code_challenge:
            return JSONResponse(
                content={
                    "error": "invalid_request",
                    "error_description": "code_challenge is required (PKCE)",
                },
                status_code=400,
            )

        if response_type != "code":
            return JSONResponse(
                content={
                    "error": "unsupported_response_type",
                    "error_description": "Only 'code' response type is supported",
                },
                status_code=400,
            )

        # Check if user is authenticated
        if not current_user:
            # Redirect to login page with OAuth context
            oauth_params = {
                "response_type": response_type,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            }

            # Add optional parameters
            if scope:
                oauth_params["scope"] = scope
            if state:
                oauth_params["state"] = state
            if nonce:
                oauth_params["nonce"] = nonce

            # Build the OAuth authorize URL to redirect back to after login
            oauth_url = f"/api/v1/oauth/authorize?{urlencode(oauth_params)}"

            # Redirect to login with return URL
            login_url = f"/auth/login?redirect_to={quote(oauth_url)}"
            return RedirectResponse(url=login_url, status_code=302)

        try:
            # Create authorization request model
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType(response_type),
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod(code_challenge_method),
                scope=scope,
                state=state,
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
            logger.warning(f"Invalid parameter in authorization request: {e}")
            return JSONResponse(
                content={
                    "error": "invalid_request",
                    "error_description": "Invalid request parameters",
                },
                status_code=400,
            )
        except Exception as e:
            logger.error(f"Error in authorization endpoint: {e}")
            return JSONResponse(
                content={
                    "error": "server_error",
                    "error_description": "Authorization server error",
                },
                status_code=500,
            )

    # Remove the existing authorize_post endpoint
    for route in oauth_router.routes[:]:
        if route.path == "/authorize" and "POST" in route.methods:
            oauth_router.routes.remove(route)
            break

    # Add the new authorize_post with session support
    from fastapi import Form

    @oauth_router.post(
        "/authorize",
        summary="OAuth 2.1 Authorization Processing with Session Support",
        description="""
        OAuth 2.1 Authorization processing endpoint with support for both
        session-based (browser) and token-based (API) authentication.
        """,
        responses={
            302: {"description": "Redirect to client with code or error"},
            400: {"description": "Invalid request"},
            401: {"description": "Authentication required"},
        },
    )
    async def authorize_post_with_session(
        request: Request,
        response_type: str = Form("code"),
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
        # Dependencies
        current_user: UserModel | None = Depends(get_current_user_for_oauth),
        authorization_service: AuthorizationService = Depends(get_authorization_service),
    ):
        """
        OAuth 2.1 Authorization processing endpoint with session support.
        """
        from fastapi import HTTPException, status

        # Check authentication
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        # Check if user approved
        if approved.lower() != "true":
            # User denied authorization
            error_params = {"error": "access_denied", "error_description": "User denied authorization"}
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

        try:
            # Create authorization request model
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType(response_type),
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod(code_challenge_method),
                scope=scope,
                state=state,
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
            auth_code = await authorization_service.create_authorization_code(auth_request, current_user.id)

            # Build success response parameters
            response_params = {"code": auth_code.code}
            if state:
                response_params["state"] = state

            # Redirect to client with authorization code
            success_url = f"{redirect_uri}?{urlencode(response_params)}"
            return RedirectResponse(url=success_url, status_code=302)

        except ValueError as e:
            logger.warning(f"Invalid parameter in authorization request: {e}")
            error_params = {"error": "invalid_request", "error_description": str(e)}
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

        except Exception as e:
            logger.error(f"Error processing authorization: {e}")
            error_params = {"error": "server_error", "error_description": "Authorization server error"}
            if state:
                error_params["state"] = state

            error_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=error_url, status_code=302)

    logger.info("OAuth authorization endpoints patched with session support")
