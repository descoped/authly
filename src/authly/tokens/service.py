from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from fastapi import HTTPException
from starlette import status

from authly.tokens.models import TokenModel, TokenType
from authly.tokens.store.base import TokenStore


class TokenService:
    """
    Service for managing tokens, using an abstract TokenStore for storage.
    This allows for easy swapping between different storage backends (PostgreSQL, Redis, etc.)
    """

    def __init__(self, token_store: TokenStore):
        self._store = token_store

    async def create_token(self, token: TokenModel) -> TokenModel:
        """Create a new token record"""
        return await self._store.create_token(token)

    async def get_token(self, token_jti: str) -> Optional[TokenModel]:
        """Get a token by its JTI"""
        return await self._store.get_token(token_jti)

    async def get_user_tokens(
            self,
            user_id: UUID,
            token_type: Optional[TokenType] = None,
            valid_only: bool = True
    ) -> List[TokenModel]:
        """Get all tokens for a user"""
        return await self._store.get_user_tokens(user_id, token_type, valid_only)

    async def invalidate_token(self, token_jti: str) -> bool:
        """Invalidate a specific token"""
        return await self._store.invalidate_token(token_jti)

    async def invalidate_user_tokens(
            self,
            user_id: UUID,
            token_type: Optional[TokenType] = None
    ) -> int:
        """Invalidate all tokens for a user"""
        return await self._store.invalidate_user_tokens(user_id, token_type)

    async def is_token_valid(self, token_jti: str) -> bool:
        """Check if a token is valid"""
        return await self._store.is_token_valid(token_jti)

    async def cleanup_expired_tokens(self, before_datetime: Optional[datetime] = None) -> int:
        """Clean up expired tokens"""
        if before_datetime is None:
            before_datetime = datetime.now(timezone.utc)
        return await self._store.cleanup_expired_tokens(before_datetime)

    async def count_user_valid_tokens(
            self,
            user_id: UUID,
            token_type: Optional[TokenType] = None
    ) -> int:
        """Count valid tokens for a user"""
        return await self._store.count_user_valid_tokens(user_id, token_type)

    async def logout_user(self, user_id: UUID) -> None:
        """
        Logout user by invalidating all their tokens.
        This is a higher-level operation that builds on the basic token operations.
        """
        invalidated_count = await self.invalidate_user_tokens(user_id)
        if invalidated_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active sessions found"
            )
