import logging
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from jose import JWTError
from psycopg_toolkit import OperationError, RecordNotFoundError

from authly.api.auth_dependencies import oauth2_scheme
from authly.auth import decode_token
from authly.config import AuthlyConfig
from authly.core.dependencies import get_config, get_database_connection
from authly.oidc.userinfo import UserInfoService
from authly.tokens import TokenService, get_token_service
from authly.users.models import UserModel
from authly.users.repository import UserRepository
from authly.users.service import UserService

logger = logging.getLogger(__name__)


async def get_user_repository(db_connection=Depends(get_database_connection)) -> UserRepository:
    """
    Get an instance of the UserRepository.

    Dependencies:
        - Database connection from get_db_connection
    """
    return UserRepository(db_connection)


async def get_user_service(user_repo: UserRepository = Depends(get_user_repository)) -> UserService:
    """
    Get an instance of the UserService.

    Dependencies:
        - User repository from get_user_repository
    """
    return UserService(user_repo)


def _create_credentials_exception() -> HTTPException:
    """Create standardized credentials exception."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _validate_token_and_get_user_id(token: str, token_service: TokenService, config: AuthlyConfig) -> UUID:
    """
    Shared token validation logic to eliminate duplication.

    Args:
        token: JWT token to validate
        token_service: Token service for checking revocation status

    Returns:
        UUID: User ID extracted from token

    Raises:
        HTTPException: If token is invalid, revoked, or user ID cannot be extracted
    """
    credentials_exception = _create_credentials_exception()

    try:
        payload = decode_token(token, config.secret_key, config.algorithm)
        user_id_str: str = payload.get("sub")
        jti: str = payload.get("jti")

        if user_id_str is None:
            raise credentials_exception

        # Check if token has been revoked (only if JTI is present)
        # Tokens without JTI are considered legacy tokens and are always valid
        if jti is not None:
            if not await token_service.is_token_valid(jti):
                logger.info(f"Access attempt with revoked token JTI: {jti}")
                raise credentials_exception
        else:
            logger.debug("Token without JTI detected - treating as legacy token")

        try:
            return UUID(user_id_str)
        except ValueError:
            raise credentials_exception from None

    except JWTError:
        raise credentials_exception from None
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        raise credentials_exception from e


async def _get_user_by_id(user_repo: UserRepository, user_id: UUID) -> UserModel:
    """
    Shared user retrieval logic.

    Args:
        user_repo: User repository instance
        user_id: User ID to look up

    Returns:
        UserModel: Retrieved user

    Raises:
        HTTPException: If user not found or database error
    """
    credentials_exception = _create_credentials_exception()

    try:
        return await user_repo.get_by_id(user_id)
    except RecordNotFoundError:
        raise credentials_exception from None
    except OperationError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> UserModel:
    """
    Get the current authenticated user.

    Dependencies:
        - JWT token from oauth2_scheme
        - User repository from get_user_repository
        - Token service from get_token_service

    Returns:
        UserModel: The authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    user_id = await _validate_token_and_get_user_id(token, token_service, config)
    return await _get_user_by_id(user_repo, user_id)


async def get_current_user_optional(
    token: Annotated[str | None, Depends(oauth2_scheme)],
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> UserModel | None:
    """
    Get the current authenticated user if available, returns None if not authenticated.

    This is used for endpoints that need to check authentication but don't require it.

    Returns:
        UserModel | None: The authenticated user or None
    """
    if not token:
        return None

    try:
        user_id = await _validate_token_and_get_user_id(token, token_service, config)
        return await _get_user_by_id(user_repo, user_id)
    except Exception:
        return None


async def get_current_user_no_update(
    token: Annotated[str, Depends(oauth2_scheme)],
    user_repo: UserRepository = Depends(get_user_repository),
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> UserModel:
    """
    Get the current authenticated user without updating last login.

    Dependencies:
        - JWT token from oauth2_scheme
        - User repository from get_user_repository
        - Token service from get_token_service

    Returns:
        UserModel: The authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    user_id = await _validate_token_and_get_user_id(token, token_service, config)
    return await _get_user_by_id(user_repo, user_id)


async def get_current_active_user(current_user: Annotated[UserModel, Depends(get_current_user)]) -> UserModel:
    """
    Get the current user and verify they are active.

    Dependencies:
        - Current user from get_current_user

    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user


async def get_current_verified_user(current_user: Annotated[UserModel, Depends(get_current_active_user)]) -> UserModel:
    """
    Get the current user and verify they are verified.

    Dependencies:
        - Active user from get_current_active_user

    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not verified")
    return current_user


async def get_current_admin_user(current_user: Annotated[UserModel, Depends(get_current_verified_user)]) -> UserModel:
    """
    Get the current user and verify they have admin privileges.

    Dependencies:
        - Verified user from get_current_verified_user

    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


async def get_token_scopes(
    token: Annotated[str, Depends(oauth2_scheme)],
    token_service: TokenService = Depends(get_token_service),
    config: AuthlyConfig = Depends(get_config),
) -> list[str]:
    """
    Extract scopes from JWT access token.

    Args:
        token: JWT access token
        token_service: Token service for validation

    Returns:
        List of scopes granted to the token

    Raises:
        HTTPException: If token is invalid or does not contain valid scopes
    """
    credentials_exception = _create_credentials_exception()

    try:
        # Decode token to get payload
        payload = decode_token(token, config.secret_key, config.algorithm)

        # Validate token is not revoked (reuse existing logic)
        jti = payload.get("jti")
        if jti is not None and not await token_service.is_token_valid(jti):
            logger.info(f"Access attempt with revoked token JTI: {jti}")
            raise credentials_exception

        # Extract scopes from token
        scope_string = payload.get("scope", "")
        scopes = scope_string.split() if scope_string else []

        logger.debug(f"Extracted scopes from token: {scopes}")
        return scopes

    except JWTError:
        raise credentials_exception from None
    except Exception as e:
        logger.error(f"Error extracting scopes from token: {e}")
        raise credentials_exception from e


async def get_userinfo_service() -> UserInfoService:
    """
    Get an instance of the UserInfoService.

    Returns:
        UserInfoService: Service for handling UserInfo operations
    """
    return UserInfoService()
