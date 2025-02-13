import logging
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from jose import JWTError
from psycopg_toolkit import RecordNotFoundError, OperationError

from authly import get_config, authly_db_connection
from authly.api.auth_dependencies import oauth2_scheme
from authly.auth import decode_token
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


async def get_user_repository(
        db_connection=Depends(authly_db_connection)
) -> UserRepository:
    """
    Get an instance of the UserRepository.

    Dependencies:
        - Database connection from get_db_connection
    """
    return UserRepository(db_connection)


async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)],
        user_repo: UserRepository = Depends(get_user_repository)
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    config = get_config()

    # Decode the token and extract user_id
    try:
        payload = decode_token(
            token,
            config.secret_key,
            config.algorithm
        )

        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        try:
            user_id_uuid = UUID(user_id)
        except ValueError:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        raise

    # Look up the user
    try:
        try:
            user = await user_repo.get_by_id(user_id_uuid)
        except RecordNotFoundError:
            raise credentials_exception

        return user

    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


async def get_current_user_no_update(
        token: Annotated[str, Depends(oauth2_scheme)],
        user_repo: UserRepository = Depends(get_user_repository)
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    config = get_config()

    try:
        payload = decode_token(token, config.secret_key, config.algorithm)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        try:
            user_id_uuid = UUID(user_id)
        except ValueError:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    try:
        try:
            user = await user_repo.get_by_id(user_id_uuid)
        except RecordNotFoundError:
            raise credentials_exception
        return user
    except OperationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


async def get_current_active_user(
        current_user: Annotated[UserModel, Depends(get_current_user)]
) -> UserModel:
    """
    Get the current user and verify they are active.

    Dependencies:
        - Current user from get_current_user

    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(
        current_user: Annotated[UserModel, Depends(get_current_active_user)]
) -> UserModel:
    """
    Get the current user and verify they are verified.

    Dependencies:
        - Active user from get_current_active_user

    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not verified"
        )
    return current_user


# Optional: Admin user dependency if needed
async def get_current_admin_user(
        current_user: Annotated[UserModel, Depends(get_current_verified_user)]
) -> UserModel:
    """
    Get the current user and verify they have admin privileges.

    Dependencies:
        - Verified user from get_current_verified_user

    Raises:
        HTTPException: If user is not an admin
    """
    # Implement your admin check logic here
    # For example:
    # if not current_user.is_admin:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Admin privileges required"
    #     )
    return current_user
