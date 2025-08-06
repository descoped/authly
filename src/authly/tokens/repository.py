from datetime import UTC, datetime
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier, Placeholder
from psycopg_toolkit import BaseRepository, OperationError

from authly.tokens.models import TokenModel, TokenType

# Import database metrics tracking
try:
    from authly.monitoring.metrics import DatabaseTimer

    METRICS_ENABLED = True
except ImportError:
    # Create a no-op context manager for graceful fallback
    class DatabaseTimer:
        def __init__(self, operation: str):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    METRICS_ENABLED = False


# noinspection SqlNoDataSourceInspection
class TokenRepository(BaseRepository[TokenModel, UUID]):
    """Repository for managing tokens in PostgreSQL database"""

    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="tokens",
            model_class=TokenModel,
            primary_key="id",
            # Specify all date/timestamp fields for automatic conversion (v0.2.2)
            date_fields={"created_at", "expires_at", "revoked_at"},
        )

    async def store_token(self, token_model: TokenModel) -> TokenModel:
        """Store a new token in the database."""
        with DatabaseTimer("token_create"):
            try:
                return await self.create(token_model)
            except Exception as e:
                raise OperationError(f"Failed to store token: {e!s}") from e

    async def get_by_jti(self, token_jti: str) -> TokenModel | None:
        """Get a token by its JTI."""
        with DatabaseTimer("token_read_by_jti"):
            try:
                query = SQL("SELECT * FROM tokens WHERE {} = {}").format(Identifier("token_jti"), Placeholder())

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [token_jti])
                    result = await cur.fetchone()
                    return TokenModel(**result) if result else None
            except Exception as e:
                raise OperationError(f"Failed to get token by JTI: {e!s}") from e

    async def get_user_tokens(
        self, user_id: UUID, token_type: TokenType | None = None, valid_only: bool = True
    ) -> list[TokenModel]:
        """Get all tokens for a user with optional filtering."""
        with DatabaseTimer("token_list_user"):
            try:
                conditions = [SQL("{} = {}").format(Identifier("user_id"), Placeholder())]
                params = [user_id]

                if token_type:
                    conditions.append(SQL("{} = {}").format(Identifier("token_type"), Placeholder()))
                    params.append(token_type.value)

                if valid_only:
                    conditions.append(SQL("NOT invalidated"))
                    conditions.append(SQL("expires_at > CURRENT_TIMESTAMP"))

                query = SQL("SELECT * FROM tokens WHERE {} ORDER BY created_at DESC").format(
                    SQL(" AND ").join(conditions)
                )

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, params)
                    results = await cur.fetchall()
                    return [TokenModel(**row) for row in results]
            except Exception as e:
                raise OperationError(f"Failed to get user tokens: {e!s}") from e

    async def get_invalidated_token_count(self, user_id: UUID, token_type: TokenType | None = None) -> int:
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
            raise OperationError(f"Failed to count invalidated tokens: {e!s}") from e

    async def count_active_sessions(self, user_id: UUID) -> int:
        """Count active sessions (valid access tokens) for a user."""
        with DatabaseTimer("token_count_active_sessions"):
            try:
                query = SQL(
                    """
                    SELECT COUNT(*) FROM tokens
                    WHERE {} = {}
                    AND {} = {}
                    AND NOT {}
                    AND {} > CURRENT_TIMESTAMP
                    """
                ).format(
                    Identifier("user_id"),
                    Placeholder(),
                    Identifier("token_type"),
                    Placeholder(),
                    Identifier("invalidated"),
                    Identifier("expires_at"),
                )
                params = [user_id, TokenType.ACCESS.value]

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, params)
                    result = await cur.fetchone()
                    return result[0]
            except Exception as e:
                raise OperationError(f"Failed to count active sessions: {e!s}") from e

    async def invalidate_token(self, token_jti: str) -> None:
        """Invalidate a specific token by its JTI."""
        with DatabaseTimer("token_invalidate"):
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
                params = [True, datetime.now(UTC), token_jti, False]

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, params)
            except Exception as e:
                raise OperationError(f"Failed to invalidate token: {e!s}") from e

    async def invalidate_user_tokens(self, user_id: UUID, token_type: str | None = None) -> None:
        """Invalidate all tokens for a user, optionally filtered by type."""
        with DatabaseTimer("token_invalidate_user"):
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

                params = [True, datetime.now(UTC), *params]

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, params)
            except Exception as e:
                raise OperationError(f"Failed to invalidate user tokens: {e!s}") from e

    async def invalidate_user_sessions(self, user_id: UUID) -> int:
        """Invalidate all active sessions (access tokens) for a user and return count."""
        with DatabaseTimer("token_invalidate_user_sessions"):
            try:
                async with self.db_connection.cursor() as cur:
                    # First count active sessions that will be invalidated
                    count_query = SQL(
                        """
                        SELECT COUNT(*) FROM tokens
                        WHERE {} = {}
                        AND {} = {}
                        AND invalidated = false
                        AND expires_at > CURRENT_TIMESTAMP
                    """
                    ).format(
                        Identifier("user_id"),
                        Placeholder(),
                        Identifier("token_type"),
                        Placeholder(),
                    )

                    await cur.execute(count_query, [user_id, TokenType.ACCESS.value])
                    result = await cur.fetchone()
                    count = result[0] if result else 0

                    # Then invalidate the sessions
                    if count > 0:
                        update_query = SQL(
                            """
                            UPDATE tokens
                            SET invalidated = {}, invalidated_at = {}
                            WHERE {} = {}
                            AND {} = {}
                            AND invalidated = false
                            AND expires_at > CURRENT_TIMESTAMP
                        """
                        ).format(
                            Placeholder(),
                            Placeholder(),
                            Identifier("user_id"),
                            Placeholder(),
                            Identifier("token_type"),
                            Placeholder(),
                        )

                        params = [True, datetime.now(UTC), user_id, TokenType.ACCESS.value]
                        await cur.execute(update_query, params)

                    return count
            except Exception as e:
                raise OperationError(f"Failed to invalidate user sessions: {e!s}") from e

    async def get_user_sessions(
        self, user_id: UUID, skip: int = 0, limit: int = 25, include_inactive: bool = True
    ) -> list[TokenModel]:
        """Get paginated list of user sessions (tokens) with optional filtering."""
        with DatabaseTimer("token_get_user_sessions"):
            try:
                conditions = [SQL("{} = {}").format(Identifier("user_id"), Placeholder())]
                params = [user_id]

                if not include_inactive:
                    conditions.extend(
                        [
                            SQL("NOT invalidated"),
                            SQL("expires_at > CURRENT_TIMESTAMP"),
                        ]
                    )

                query = SQL(
                    """
                    SELECT * FROM tokens
                    WHERE {}
                    ORDER BY created_at DESC
                    LIMIT {} OFFSET {}
                """
                ).format(
                    SQL(" AND ").join(conditions),
                    Placeholder(),
                    Placeholder(),
                )

                params.extend([limit, skip])

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, params)
                    rows = await cur.fetchall()
                    return [TokenModel(**row) for row in rows]
            except Exception as e:
                raise OperationError(f"Failed to get user sessions: {e!s}") from e

    async def count_user_sessions(self, user_id: UUID, include_inactive: bool = True) -> int:
        """Count total number of user sessions with optional filtering."""
        with DatabaseTimer("token_count_user_sessions"):
            try:
                conditions = [SQL("{} = {}").format(Identifier("user_id"), Placeholder())]
                params = [user_id]

                if not include_inactive:
                    conditions.extend(
                        [
                            SQL("NOT invalidated"),
                            SQL("expires_at > CURRENT_TIMESTAMP"),
                        ]
                    )

                query = SQL(
                    """
                    SELECT COUNT(*) FROM tokens
                    WHERE {}
                """
                ).format(SQL(" AND ").join(conditions))

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, params)
                    result = await cur.fetchone()
                    return result[0] if result else 0
            except Exception as e:
                raise OperationError(f"Failed to count user sessions: {e!s}") from e

    async def is_token_valid(self, token_jti: str) -> bool:
        """Check if a token is valid (not invalidated and not expired)."""
        with DatabaseTimer("token_validate"):
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
                raise OperationError(f"Failed to check token validity: {e!s}") from e

    async def count_user_valid_tokens(self, user_id: UUID, token_type: TokenType | None = None) -> int:
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
            raise OperationError(f"Failed to count valid tokens: {e!s}") from e

    async def cleanup_expired_tokens(self, before_datetime: datetime) -> int:
        """Remove expired tokens from the database."""
        with DatabaseTimer("token_cleanup"):
            try:
                query = SQL("DELETE FROM tokens WHERE {} < {}").format(Identifier("expires_at"), Placeholder())

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [before_datetime])
                    return cur.rowcount
            except Exception as e:
                raise OperationError(f"Failed to cleanup expired tokens: {e!s}") from e
