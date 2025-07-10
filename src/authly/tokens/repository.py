from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier, Placeholder
from psycopg_toolkit import BaseRepository, OperationError

from authly.tokens.models import TokenModel, TokenType


# noinspection SqlNoDataSourceInspection
class TokenRepository(BaseRepository[TokenModel, UUID]):
    """Repository for managing tokens in PostgreSQL database"""

    def __init__(self, db_connection: AsyncConnection):
        super().__init__(db_connection=db_connection, table_name="tokens", model_class=TokenModel, primary_key="id")

    async def store_token(self, token_model: TokenModel) -> TokenModel:
        """Store a new token in the database."""
        try:
            return await self.create(token_model)
        except Exception as e:
            raise OperationError(f"Failed to store token: {str(e)}") from e

    async def get_by_jti(self, token_jti: str) -> Optional[TokenModel]:
        """Get a token by its JTI."""
        try:
            query = SQL("SELECT * FROM tokens WHERE {} = {}").format(Identifier("token_jti"), Placeholder())

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [token_jti])
                result = await cur.fetchone()
                return TokenModel(**result) if result else None
        except Exception as e:
            raise OperationError(f"Failed to get token by JTI: {str(e)}") from e

    async def get_user_tokens(
        self, user_id: UUID, token_type: Optional[TokenType] = None, valid_only: bool = True
    ) -> List[TokenModel]:
        """Get all tokens for a user with optional filtering."""
        try:
            conditions = [SQL("{} = {}").format(Identifier("user_id"), Placeholder())]
            params = [user_id]

            if token_type:
                conditions.append(SQL("{} = {}").format(Identifier("token_type"), Placeholder()))
                params.append(token_type.value)

            if valid_only:
                conditions.append(SQL("NOT invalidated"))
                conditions.append(SQL("expires_at > CURRENT_TIMESTAMP"))

            query = SQL("SELECT * FROM tokens WHERE {} ORDER BY created_at DESC").format(SQL(" AND ").join(conditions))

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, params)
                results = await cur.fetchall()
                return [TokenModel(**row) for row in results]
        except Exception as e:
            raise OperationError(f"Failed to get user tokens: {str(e)}") from e

    async def get_invalidated_token_count(self, user_id: UUID, token_type: Optional[TokenType] = None) -> int:
        """Count invalidated tokens for a user."""
        try:
            conditions = [
                SQL("{} = {}").format(Identifier("user_id"), Placeholder()),
                SQL("{} = {}").format(Identifier("invalidated"), Placeholder()),
            ]
            params = [user_id, True]

            if token_type:
                conditions.append(SQL("{} = {}").format(Identifier("token_type"), Placeholder()))
                params.append(token_type.value)

            query = SQL("SELECT COUNT(*) FROM tokens WHERE {}").format(SQL(" AND ").join(conditions))

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, params)
                result = await cur.fetchone()
                return result[0]
        except Exception as e:
            raise OperationError(f"Failed to count invalidated tokens: {str(e)}") from e

    async def invalidate_token(self, token_jti: str) -> None:
        """Invalidate a specific token by its JTI."""
        try:
            query = SQL(
                """
                UPDATE tokens 
                SET invalidated = {}, invalidated_at = {}
                WHERE {} = {} AND {} = {}
            """
            ).format(
                Placeholder(),
                Placeholder(),
                Identifier("token_jti"),
                Placeholder(),
                Identifier("invalidated"),
                Placeholder(),
            )
            params = [True, datetime.now(timezone.utc), token_jti, False]

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, params)
        except Exception as e:
            raise OperationError(f"Failed to invalidate token: {str(e)}") from e

    async def invalidate_user_tokens(self, user_id: UUID, token_type: Optional[str] = None) -> None:
        """Invalidate all tokens for a user, optionally filtered by type."""
        try:
            conditions = [
                SQL("{} = {}").format(Identifier("user_id"), Placeholder()),
                SQL("{} = {}").format(Identifier("invalidated"), Placeholder()),
            ]
            params = [user_id, False]

            if token_type:
                conditions.append(SQL("{} = {}").format(Identifier("token_type"), Placeholder()))
                params.append(token_type)

            query = SQL(
                """
                UPDATE tokens 
                SET invalidated = {}, invalidated_at = {}
                WHERE {}
            """
            ).format(Placeholder(), Placeholder(), SQL(" AND ").join(conditions))

            params = [True, datetime.now(timezone.utc)] + params

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, params)
        except Exception as e:
            raise OperationError(f"Failed to invalidate user tokens: {str(e)}") from e

    async def is_token_valid(self, token_jti: str) -> bool:
        """Check if a token is valid (not invalidated and not expired)."""
        try:
            query = SQL(
                """
                SELECT EXISTS(
                    SELECT 1 FROM tokens 
                    WHERE {} = {} 
                    AND invalidated = false 
                    AND expires_at > CURRENT_TIMESTAMP
                )
            """
            ).format(Identifier("token_jti"), Placeholder())

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [token_jti])
                result = await cur.fetchone()
                return result["exists"] if result else False
        except Exception as e:
            raise OperationError(f"Failed to check token validity: {str(e)}") from e

    async def count_user_valid_tokens(self, user_id: UUID, token_type: Optional[TokenType] = None) -> int:
        """Count valid (not invalidated and not expired) tokens for a user."""
        try:
            conditions = [
                SQL("{} = {}").format(Identifier("user_id"), Placeholder()),
                SQL("NOT invalidated"),
                SQL("expires_at > CURRENT_TIMESTAMP"),
            ]
            params = [user_id]

            if token_type:
                conditions.append(SQL("{} = {}").format(Identifier("token_type"), Placeholder()))
                params.append(token_type.value)

            query = SQL("SELECT COUNT(*) FROM tokens WHERE {}").format(SQL(" AND ").join(conditions))

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, params)
                result = await cur.fetchone()
                return result[0]
        except Exception as e:
            raise OperationError(f"Failed to count valid tokens: {str(e)}") from e

    async def cleanup_expired_tokens(self, before_datetime: datetime) -> int:
        """Remove expired tokens from the database."""
        try:
            query = SQL("DELETE FROM tokens WHERE {} < {}").format(Identifier("expires_at"), Placeholder())

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [before_datetime])
                return cur.rowcount
        except Exception as e:
            raise OperationError(f"Failed to cleanup expired tokens: {str(e)}") from e
