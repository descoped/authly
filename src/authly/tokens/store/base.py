from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from psycopg import AsyncConnection

from authly.tokens.models import TokenModel, TokenType


class TokenStore(ABC):
    """
    Abstract base class for token storage implementations.
    This interface defines the contract for different token storage backends.
    """

    @classmethod
    @abstractmethod
    def create(cls, db_connection: AsyncConnection) -> "TokenStore":
        """
        Abstract factory method to create TokenStore instance.
        Must be implemented by concrete subclasses.
        """
        pass

    @abstractmethod
    async def create_token(self, token: TokenModel) -> TokenModel:
        """
        Store a new token.

        Args:
            token: TokenModel instance to store

        Returns:
            TokenModel: The stored token

        Raises:
            OperationError: If token creation fails
        """
        pass

    @abstractmethod
    async def get_token(self, token_jti: str) -> TokenModel | None:
        """
        Retrieve a token by its JTI.

        Args:
            token_jti: The JWT ID to look up

        Returns:
            Optional[TokenModel]: The token if found, None otherwise

        Raises:
            OperationError: If token retrieval fails
        """
        pass

    @abstractmethod
    async def get_user_tokens(
        self, user_id: UUID, token_type: TokenType | None = None, valid_only: bool = True
    ) -> list[TokenModel]:
        """
        Get all tokens for a user.

        Args:
            user_id: The user's ID
            token_type: Optional filter by token type
            valid_only: If True, only return non-invalidated tokens

        Returns:
            List[TokenModel]: List of tokens

        Raises:
            OperationError: If token retrieval fails
        """
        pass

    @abstractmethod
    async def invalidate_token(self, token_jti: str) -> bool:
        """
        Invalidate a specific token.

        Args:
            token_jti: The JWT ID of the token to invalidate

        Returns:
            bool: True if token was invalidated, False if token wasn't found

        Raises:
            OperationError: If token invalidation fails
        """
        pass

    @abstractmethod
    async def invalidate_user_tokens(self, user_id: UUID, token_type: TokenType | None = None) -> int:
        """
        Invalidate all tokens for a user.

        Args:
            user_id: The user's ID
            token_type: Optional token type to invalidate

        Returns:
            int: Number of tokens invalidated

        Raises:
            OperationError: If token invalidation fails
        """
        pass

    @abstractmethod
    async def is_token_valid(self, token_jti: str) -> bool:
        """
        Check if a token is valid (exists, not invalidated, not expired).

        Args:
            token_jti: The JWT ID to check

        Returns:
            bool: True if token is valid, False otherwise

        Raises:
            OperationError: If token validation fails
        """
        pass

    @abstractmethod
    async def cleanup_expired_tokens(self, before_datetime: datetime) -> int:
        """
        Remove expired tokens from storage.

        Args:
            before_datetime: Remove tokens that expired before this time

        Returns:
            int: Number of tokens removed

        Raises:
            OperationError: If cleanup fails
        """
        pass

    @abstractmethod
    async def count_user_valid_tokens(self, user_id: UUID, token_type: TokenType | None = None) -> int:
        """
        Count valid tokens for a user.

        Args:
            user_id: The user's ID
            token_type: Optional filter by token type

        Returns:
            int: Number of valid tokens

        Raises:
            OperationError: If counting fails
        """
        pass
