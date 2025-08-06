import logging
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from starlette import status

from authly.api.auth_dependencies import (
    oauth2_scheme,
)
from authly.api.users_dependencies import get_current_user
from authly.tokens import TokenService, get_token_service
from authly.users import UserModel, UserRepository

logger = logging.getLogger(__name__)

# Import authentication metrics tracking
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    logger.debug("Metrics collection not available in auth router")
    METRICS_ENABLED = False
    metrics = None


# Models and LoginAttemptTracker moved to oauth_router.py

router = APIRouter(prefix="/auth", tags=["auth"])


async def update_last_login(user_repo: UserRepository, user_id: UUID):
    await user_repo.update(user_id, {"last_login": datetime.now(UTC)})


# Token endpoint and helper functions moved to oauth_router.py


# Refresh endpoint moved to oauth_router.py


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    token: Annotated[str, Depends(oauth2_scheme)],
    current_user: UserModel = Depends(get_current_user),
    token_service: TokenService = Depends(get_token_service),
):
    """Invalidate all active tokens for the current user"""
    import time

    start_time = time.time()

    try:
        # Logout user session using TokenService
        invalidated_count = await token_service.logout_user_session(token, current_user.id)

        # Track logout operation
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            status_result = "success" if invalidated_count > 0 else "no_active_tokens"
            metrics.track_logout_event(str(current_user.id), status_result, invalidated_count)

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
        # Track logout error
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            metrics.track_logout_event(str(current_user.id), "error", 0)
        logger.error(f"Logout failed: {e!s}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout operation failed") from e


# Revoke endpoint moved to oauth_router.py
