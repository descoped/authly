import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware

from authly.api.auth_dependencies import (
    get_authorization_service,
    get_rate_limiter,
    get_token_service_with_client,
    oauth2_scheme,
)
from authly.api.users_dependencies import get_current_user, get_user_repository
from authly.auth import verify_password
from authly.oauth.authorization_service import AuthorizationService
from authly.tokens import TokenService, get_token_service
from authly.users import UserModel, UserRepository

logger = logging.getLogger(__name__)


class TokenRequest(BaseModel):
    grant_type: str

    # Password grant fields
    username: Optional[str] = None
    password: Optional[str] = None

    # Authorization code grant fields
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: Optional[str] = None
    code_verifier: Optional[str] = None  # PKCE

    # OAuth 2.1 scope field
    scope: Optional[str] = None

    # Refresh token grant fields
    refresh_token: Optional[str] = None
    client_secret: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str
    grant_type: str


class TokenRevocationRequest(BaseModel):
    token: str = Field(..., description="The token to revoke (access or refresh token)")
    token_type_hint: Optional[str] = Field(None, description="Optional hint: 'access_token' or 'refresh_token'")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    id_token: Optional[str] = None  # ID token for OpenID Connect flows
    requires_password_change: Optional[bool] = None  # Security flag for mandatory password change


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginAttemptTracker:
    def __init__(self):
        self.attempts: Dict[str, Dict[str, Union[int, Optional[datetime]]]] = {}
        self.lockout_duration = 300
        self.max_attempts = 5

    def check_and_update(self, username: str) -> bool:
        now = datetime.now(timezone.utc)
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


login_tracker = LoginAttemptTracker()


async def update_last_login(user_repo: UserRepository, user_id: UUID):
    await user_repo.update(user_id, {"last_login": datetime.now(timezone.utc)})


@router.post("/token", response_model=TokenResponse)
async def get_access_token(
    request: TokenRequest,
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service_with_client),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    rate_limiter=Depends(get_rate_limiter),
):
    """
    OAuth 2.1 Token Endpoint - supports multiple grant types.

    Supported grant types:
    - password: Username/password authentication (existing)
    - authorization_code: OAuth 2.1 authorization code flow with PKCE
    """

    if request.grant_type == "password":
        return await _handle_password_grant(request, user_repo, token_service, rate_limiter)
    elif request.grant_type == "authorization_code":
        return await _handle_authorization_code_grant(request, user_repo, token_service, authorization_service)
    elif request.grant_type == "refresh_token":
        return await _handle_refresh_token_grant(request, user_repo, token_service)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported grant type: {request.grant_type}"
        )


async def _handle_password_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
    rate_limiter,
) -> TokenResponse:
    """Handle password grant type (existing functionality)."""

    # Validate required fields for password grant
    if not request.username or not request.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required for password grant"
        )

    # Rate limiting check
    await rate_limiter.check_rate_limit(f"login:{request.username}")

    # Check login attempts
    if not login_tracker.check_and_update(request.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Account temporarily locked.",
        )

    # Validate user
    user = await user_repo.get_by_username(request.username)
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")

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

        return response

    except HTTPException:
        # Let HTTPExceptions from TokenService pass through
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create authentication tokens"
        )


async def _handle_authorization_code_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
    authorization_service: AuthorizationService,
) -> TokenResponse:
    """Handle authorization_code grant type with PKCE verification."""

    # Validate required fields for authorization code grant
    if not request.code or not request.redirect_uri or not request.client_id or not request.code_verifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="code, redirect_uri, client_id, and code_verifier are required for authorization_code grant",
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
            logger.warning(f"Authorization code exchange failed: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg or "Invalid authorization code"
            )

        # Get user for token generation
        user = await user_repo.get_by_id(code_data["user_id"])
        if not user:
            logger.error(f"User not found for authorization code: {code_data['user_id']}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authorization code")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

        if not user.is_verified:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not verified")

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
        logger.error(f"Error handling authorization code grant: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not process authorization code"
        )


async def _handle_refresh_token_grant(
    request: TokenRequest,
    user_repo: UserRepository,
    token_service: TokenService,
) -> TokenResponse:
    """Handle refresh_token grant type."""

    # Validate required fields for refresh token grant
    if not request.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="refresh_token is required for refresh_token grant"
        )

    try:
        # Refresh token pair - client_id lookup will be handled by token service
        client_id = request.client_id if request.client_id else None
        token_response = await token_service.refresh_token_pair(request.refresh_token, user_repo, client_id=client_id)

        logger.info(f"Refresh token exchanged successfully")

        return TokenResponse(
            access_token=token_response.access_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            refresh_token=token_response.refresh_token,
            id_token=token_response.id_token,
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like invalid refresh token) as-is
        raise
    except Exception as e:
        logger.error(f"Error handling refresh token grant: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not process refresh token")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: RefreshRequest,
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service_with_client),
):
    """Create new token pair while invalidating old refresh token"""

    if request.grant_type != "refresh_token":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid grant type")

    try:
        # Refresh token pair using TokenService
        token_response = await token_service.refresh_token_pair(request.refresh_token, user_repo)

        return TokenResponse(
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            id_token=token_response.id_token,
        )

    except HTTPException:
        # Let HTTPExceptions from TokenService pass through
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not refresh tokens")


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    token: Annotated[str, Depends(oauth2_scheme)],
    current_user: UserModel = Depends(get_current_user),
    token_service: TokenService = Depends(get_token_service),
):
    """Invalidate all active tokens for the current user"""

    try:
        # Logout user session using TokenService
        invalidated_count = await token_service.logout_user_session(token, current_user.id)

        if invalidated_count > 0:
            logger.info(f"Invalidated {invalidated_count} tokens for user {current_user.id}")
            return {"message": "Successfully logged out", "invalidated_tokens": invalidated_count}
        else:
            logger.warning(f"No active tokens found to invalidate for user {current_user.id}")
            return {"message": "No active sessions found to logout", "invalidated_tokens": 0}

    except HTTPException:
        # Let HTTPExceptions from TokenService pass through
        raise
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout operation failed")


@router.post("/revoke", status_code=status.HTTP_200_OK)
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
    try:
        # Attempt to revoke the token using the token service
        revoked = await token_service.revoke_token(request.token, request.token_type_hint)

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
        # Even on errors, return 200 OK per RFC 7009 to prevent information disclosure
        logger.error(f"Error during token revocation: {str(e)}")
        return {"message": "Token revocation processed successfully"}
