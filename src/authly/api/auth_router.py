import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Union, Optional, Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from jose import jwt
from jose.exceptions import JWTError
from psycopg_toolkit import RecordNotFoundError
from pydantic import BaseModel
from requests import Request
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware

from authly import get_config
from authly.api.auth_dependencies import get_rate_limiter, oauth2_scheme
from authly.api.users_dependencies import get_current_user, get_user_repository
from authly.auth import create_access_token, verify_password, create_refresh_token
from authly.tokens import TokenModel, TokenType
from authly.tokens import TokenService, get_token_service
from authly.users import UserModel
from authly.users import UserRepository

logger = logging.getLogger(__name__)


class TokenRequest(BaseModel):
    username: str
    password: str
    grant_type: str


class RefreshRequest(BaseModel):
    refresh_token: str
    grant_type: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


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
    await user_repo.update(
        user_id,
        {"last_login": datetime.now(timezone.utc)}
    )


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
        request: TokenRequest,
        user_repo: UserRepository = Depends(get_user_repository),
        token_service: TokenService = Depends(get_token_service),
        rate_limiter=Depends(get_rate_limiter),
):
    """Create and store new access and refresh tokens for user login"""

    # Validate grant type
    if request.grant_type != "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type"
        )

    # Rate limiting check
    await rate_limiter.check_rate_limit(f"login:{request.username}")

    # Check login attempts
    if not login_tracker.check_and_update(request.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Account temporarily locked."
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not verified"
        )

    config = get_config()

    try:
        # Generate unique JTIs for both tokens
        access_jti = secrets.token_hex(32)
        refresh_jti = secrets.token_hex(32)

        # Create access token with its own JTI
        access_token = create_access_token(
            data={
                "sub": str(user.id),
                "jti": access_jti
            },
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            expires_delta=config.access_token_expire_minutes
        )

        # Create refresh token with its own JTI
        refresh_token = create_refresh_token(
            user_id=str(user.id),
            secret_key=config.refresh_secret_key,
            jti=refresh_jti  # Pass the JTI to create_refresh_token
        )

        # Decode tokens to get expiry times
        access_payload = jwt.decode(
            access_token,
            config.secret_key,
            algorithms=[config.algorithm]
        )
        refresh_payload = jwt.decode(
            refresh_token,
            config.refresh_secret_key,
            algorithms=[config.algorithm]
        )

        # Create access token model
        access_token_model = TokenModel(
            id=uuid4(),
            user_id=user.id,
            token_jti=access_jti,
            token_type=TokenType.ACCESS,
            token_value=access_token,
            expires_at=datetime.fromtimestamp(
                access_payload["exp"],
                tz=timezone.utc
            ),
            created_at=datetime.now(timezone.utc)
        )

        # Create refresh token model
        refresh_token_model = TokenModel(
            id=uuid4(),
            user_id=user.id,
            token_jti=refresh_jti,
            token_type=TokenType.REFRESH,
            token_value=refresh_token,
            expires_at=datetime.fromtimestamp(
                refresh_payload["exp"],
                tz=timezone.utc
            ),
            created_at=datetime.now(timezone.utc)
        )

        # Store both tokens
        await token_service.create_token(access_token_model)
        await token_service.create_token(refresh_token_model)

        # Clear failed attempts on successful login
        if request.username in login_tracker.attempts:
            del login_tracker.attempts[request.username]

        # Update last login
        await user_repo.update_last_login(user.id)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer",
            expires_in=config.access_token_expire_minutes * 60
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create authentication tokens"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
        request: RefreshRequest,
        user_repo: UserRepository = Depends(get_user_repository),
        token_service: TokenService = Depends(get_token_service)
):
    """Create new token pair while invalidating old refresh token"""

    if request.grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type"
        )

    config = get_config()

    try:
        # Decode the provided refresh token
        payload = jwt.decode(
            request.refresh_token,
            config.refresh_secret_key,
            algorithms=[config.algorithm]
        )

        # Validate token type and extract claims
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )

        user_id = payload.get("sub")
        token_jti = payload.get("jti")

        if not user_id or not token_jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token claims"
            )

        # Verify token is valid in store
        if not await token_service.is_token_valid(token_jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is invalid or expired"
            )

        # Get the user
        try:
            user = await user_repo.get_by_id(UUID(user_id))
        except (ValueError, RecordNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User is inactive"
            )

        # --- Create new tokens ---

        # For the access token, explicitly include a new JTI in the payload.
        new_access_jti = secrets.token_hex(32)
        new_access_token = create_access_token(
            data={"sub": user_id, "jti": new_access_jti},
            secret_key=config.secret_key,
            algorithm=config.algorithm,
            expires_delta=config.access_token_expire_minutes
        )
        # Decode the access token to verify its payload
        access_payload = jwt.decode(
            new_access_token,
            config.secret_key,
            algorithms=[config.algorithm]
        )
        access_jti = access_payload.get("jti", new_access_jti)

        # Create a new refresh token; it will generate its own unique JTI.
        new_refresh_token = create_refresh_token(
            user_id=user_id,
            secret_key=config.refresh_secret_key
        )
        # Decode refresh token to extract its JTI.
        refresh_payload = jwt.decode(
            new_refresh_token,
            config.refresh_secret_key,
            algorithms=[config.algorithm]
        )
        refresh_jti = refresh_payload["jti"]

        # Invalidate the old refresh token.
        await token_service.invalidate_token(token_jti)

        # Create token models with their respective JTIs.
        new_access_model = TokenModel(
            id=uuid4(),
            user_id=UUID(user_id),
            token_jti=access_jti,
            token_type=TokenType.ACCESS,
            token_value=new_access_token,
            expires_at=datetime.fromtimestamp(
                access_payload["exp"],
                tz=timezone.utc
            ),
            created_at=datetime.now(timezone.utc)
        )

        new_refresh_model = TokenModel(
            id=uuid4(),
            user_id=UUID(user_id),
            token_jti=refresh_jti,
            token_type=TokenType.REFRESH,
            token_value=new_refresh_token,
            expires_at=datetime.fromtimestamp(
                refresh_payload["exp"],
                tz=timezone.utc
            ),
            created_at=datetime.now(timezone.utc)
        )

        # Store the new tokens.
        await token_service.create_token(new_access_model)
        await token_service.create_token(new_refresh_model)

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="Bearer",
            expires_in=config.access_token_expire_minutes * 60
        )

    except HTTPException as exc:
        # Let HTTPExceptions (such as 401 for invalid/expired tokens) pass through.
        raise exc
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not refresh tokens"
        )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
        token: Annotated[str, Depends(oauth2_scheme)],
        current_user: UserModel = Depends(get_current_user),
        token_service: TokenService = Depends(get_token_service)
):
    """Invalidate all active tokens for the current user"""

    config = get_config()

    try:
        # Decode current access token to get JTI
        payload = jwt.decode(
            token,
            config.secret_key,
            algorithms=[config.algorithm]
        )
        current_jti = payload.get("jti")

        # Invalidate current token first if JTI exists
        if current_jti:
            await token_service.invalidate_token(current_jti)

        # Invalidate all user tokens (both access and refresh)
        invalidated_count = await token_service.invalidate_user_tokens(current_user.id)

        if invalidated_count > 0:
            logger.info(f"Invalidated {invalidated_count} tokens for user {current_user.id}")
            return {
                "message": "Successfully logged out",
                "invalidated_tokens": invalidated_count
            }
        else:
            logger.warning(f"No active tokens found to invalidate for user {current_user.id}")
            return {
                "message": "No active sessions found to logout",
                "invalidated_tokens": 0
            }

    except JWTError as e:
        logger.error(f"JWT validation failed during logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout operation failed"
        )
