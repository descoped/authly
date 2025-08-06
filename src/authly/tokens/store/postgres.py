from datetime import datetime
from uuid import UUID

from psycopg import AsyncConnection

from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.tokens.store.base import TokenStore


class PostgresTokenStore(TokenStore):
    """
    PostgreSQL implementation of TokenStore that wraps TokenRepository.
    Maps between the TokenStore interface and TokenRepository methods.
    """

    @classmethod
    def create(cls, db_connection: AsyncConnection) -> "PostgresTokenStore":
        """Factory method to create PostgresTokenStore instance."""
        return cls(db_connection)

    def __init__(self, db_connection: AsyncConnection):
        self._repo = TokenRepository(db_connection)

    async def create_token(self, token: TokenModel) -> TokenModel:
        """Store a new token."""
        return await self._repo.store_token(token)

    async def get_token(self, token_jti: str) -> TokenModel | None:
        """Retrieve a token by its JTI."""
        return await self._repo.get_by_jti(token_jti)

    async def get_user_tokens(
        self, user_id: UUID, token_type: TokenType | None = None, valid_only: bool = True
    ) -> list[TokenModel]:
        """Get all tokens for a user."""
        return await self._repo.get_user_tokens(user_id, token_type, valid_only)

    async def invalidate_token(self, token_jti: str) -> bool:
        """Invalidate a specific token."""
        try:
            await self._repo.invalidate_token(token_jti)
            return True
        except Exception:
            return False

    async def invalidate_user_tokens(self, user_id: UUID, token_type: TokenType | None = None) -> int:
        """Invalidate all tokens for a user."""
        await self._repo.invalidate_user_tokens(user_id, token_type.value if token_type else None)
        return await self._repo.get_invalidated_token_count(user_id, token_type)

    async def is_token_valid(self, token_jti: str) -> bool:
        """Check if a token is valid."""
        return await self._repo.is_token_valid(token_jti)

    async def cleanup_expired_tokens(self, before_datetime: datetime) -> int:
        """Remove expired tokens from storage."""
        return await self._repo.cleanup_expired_tokens(before_datetime)

    async def count_user_valid_tokens(self, user_id: UUID, token_type: TokenType | None = None) -> int:
        """Count valid tokens for a user."""
        return await self._repo.count_user_valid_tokens(user_id, token_type)
