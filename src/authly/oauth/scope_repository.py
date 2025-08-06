import logging
from datetime import UTC, datetime
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL
from psycopg_toolkit import BaseRepository, OperationError, RecordNotFoundError
from psycopg_toolkit.utils import PsycopgHelper

from authly.oauth.models import OAuthScopeModel

logger = logging.getLogger(__name__)

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


class ScopeRepository(BaseRepository[OAuthScopeModel, UUID]):
    """Repository for OAuth 2.1 scope management with PostgreSQL storage"""

    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="oauth_scopes",
            model_class=OAuthScopeModel,
            primary_key="id",
            # Specify all date/timestamp fields for automatic conversion (v0.2.2)
            date_fields={"created_at", "updated_at"},
        )

    async def get_by_scope_name(self, scope_name: str) -> OAuthScopeModel | None:
        """Get scope by scope name"""
        with DatabaseTimer("scope_read_by_name"):
            try:
                query = PsycopgHelper.build_select_query(
                    table_name="oauth_scopes", where_clause={"scope_name": scope_name}
                )
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [scope_name])
                    result = await cur.fetchone()
                    return OAuthScopeModel(**result) if result else None
            except Exception as e:
                logger.error(f"Error in get_by_scope_name: {e}")
                raise OperationError(f"Failed to get scope by name: {e!s}") from e

    async def get_by_scope_names(self, scope_names: list[str]) -> list[OAuthScopeModel]:
        """Get multiple scopes by their names"""
        if not scope_names:
            return []

        with DatabaseTimer("scope_read_by_names"):
            try:
                placeholders = ", ".join(["%s"] * len(scope_names))
                query = f"""
                    SELECT * FROM oauth_scopes
                    WHERE scope_name IN ({placeholders}) AND is_active = true
                    ORDER BY scope_name
                """

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, scope_names)
                    results = await cur.fetchall()
                    return [OAuthScopeModel(**result) for result in results]

            except Exception as e:
                logger.error(f"Error in get_by_scope_names: {e}")
                raise OperationError(f"Failed to get scopes by names: {e!s}") from e

    async def create_scope(self, scope_data: dict) -> OAuthScopeModel:
        """Create a new OAuth scope"""
        with DatabaseTimer("scope_create"):
            try:
                # Set timestamps
                insert_data = scope_data.copy()
                now = datetime.now(UTC)
                insert_data["created_at"] = now
                insert_data["updated_at"] = now

                # Build insert query
                insert_query = PsycopgHelper.build_insert_query(table_name="oauth_scopes", data=insert_data)

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(insert_query + SQL(" RETURNING *"), list(insert_data.values()))
                    result = await cur.fetchone()
                    if result:
                        return OAuthScopeModel(**result)

                raise OperationError("Failed to create scope - no result returned")

            except Exception as e:
                logger.error(f"Error in create_scope: {e}")
                raise OperationError(f"Failed to create scope: {e!s}") from e

    async def update_scope(self, scope_id: UUID, update_data: dict) -> OAuthScopeModel:
        """Update an existing OAuth scope"""
        with DatabaseTimer("scope_update"):
            try:
                # Set updated timestamp
                prepared_data = update_data.copy()
                prepared_data["updated_at"] = datetime.now(UTC)

                # Build update query
                update_query = PsycopgHelper.build_update_query(
                    table_name="oauth_scopes", data=prepared_data, where_clause={"id": scope_id}
                )

                values = [*list(prepared_data.values()), scope_id]

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(update_query + SQL(" RETURNING *"), values)
                    result = await cur.fetchone()
                    if result:
                        return OAuthScopeModel(**result)

                raise RecordNotFoundError(f"Scope with id {scope_id} not found")

            except RecordNotFoundError:
                raise
            except Exception as e:
                logger.error(f"Error in update_scope: {e}")
                raise OperationError(f"Failed to update scope: {e!s}") from e

    async def delete_scope(self, scope_id: UUID) -> bool:
        """Delete an OAuth scope (soft delete by setting is_active=False)"""
        with DatabaseTimer("scope_delete"):
            try:
                update_data = {"is_active": False, "updated_at": datetime.now(UTC)}

                query = PsycopgHelper.build_update_query(
                    table_name="oauth_scopes",
                    data={"is_active": "IS_ACTIVE_PLACEHOLDER", "updated_at": "UPDATED_AT_PLACEHOLDER"},
                    where_clause={"id": "ID_PLACEHOLDER"},
                )

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [False, update_data["updated_at"], scope_id])
                    # Check if any rows were affected
                    return cur.rowcount > 0

            except Exception as e:
                logger.error(f"Error in delete_scope: {e}")
                raise OperationError(f"Failed to delete scope: {e!s}") from e

    async def get_active_scopes(self, limit: int = 100, offset: int = 0) -> list[OAuthScopeModel]:
        """Get all active OAuth scopes with pagination"""
        with DatabaseTimer("scope_list_active"):
            try:
                query = """
                    SELECT * FROM oauth_scopes
                    WHERE is_active = true
                    ORDER BY scope_name
                    LIMIT %s OFFSET %s
                """

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [limit, offset])
                    results = await cur.fetchall()
                    return [OAuthScopeModel(**result) for result in results]

            except Exception as e:
                logger.error(f"Error in get_active_scopes: {e}")
                raise OperationError(f"Failed to get active scopes: {e!s}") from e

    async def get_default_scopes(self) -> list[OAuthScopeModel]:
        """Get all default scopes (granted automatically)"""
        try:
            query = """
                SELECT * FROM oauth_scopes
                WHERE is_default = true AND is_active = true
                ORDER BY scope_name
            """

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query)
                results = await cur.fetchall()
                return [OAuthScopeModel(**result) for result in results]

        except Exception as e:
            logger.error(f"Error in get_default_scopes: {e}")
            raise OperationError(f"Failed to get default scopes: {e!s}") from e

    async def scope_exists(self, scope_name: str) -> bool:
        """Check if a scope exists by name"""
        try:
            query = "SELECT 1 FROM oauth_scopes WHERE scope_name = %s AND is_active = true"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [scope_name])
                result = await cur.fetchone()
                return result is not None

        except Exception as e:
            logger.error(f"Error in scope_exists: {e}")
            raise OperationError(f"Failed to check scope existence: {e!s}") from e

    async def validate_scope_names(self, scope_names: list[str]) -> set[str]:
        """Validate scope names and return set of valid ones"""
        if not scope_names:
            return set()

        with DatabaseTimer("scope_validate_names"):
            try:
                placeholders = ", ".join(["%s"] * len(scope_names))
                query = f"""
                    SELECT scope_name FROM oauth_scopes
                    WHERE scope_name IN ({placeholders}) AND is_active = true
                """

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, scope_names)
                    results = await cur.fetchall()
                    return {row[0] for row in results}

            except Exception as e:
                logger.error(f"Error in validate_scope_names: {e}")
                raise OperationError(f"Failed to validate scope names: {e!s}") from e

    async def get_scopes_for_client(self, client_id: UUID) -> list[OAuthScopeModel]:
        """Get all scopes associated with a specific client"""
        try:
            query = """
                SELECT s.* FROM oauth_scopes s
                JOIN oauth_client_scopes cs ON s.id = cs.scope_id
                WHERE cs.client_id = %s AND s.is_active = true
                ORDER BY s.scope_name
            """

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [client_id])
                results = await cur.fetchall()
                return [OAuthScopeModel(**result) for result in results]

        except Exception as e:
            logger.error(f"Error in get_scopes_for_client: {e}")
            raise OperationError(f"Failed to get scopes for client: {e!s}") from e

    async def get_scopes_for_token(self, token_id: UUID) -> list[OAuthScopeModel]:
        """Get all scopes associated with a specific token"""
        try:
            query = """
                SELECT s.* FROM oauth_scopes s
                JOIN oauth_token_scopes ts ON s.id = ts.scope_id
                WHERE ts.token_id = %s AND s.is_active = true
                ORDER BY s.scope_name
            """

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [token_id])
                results = await cur.fetchall()
                return [OAuthScopeModel(**result) for result in results]

        except Exception as e:
            logger.error(f"Error in get_scopes_for_token: {e}")
            raise OperationError(f"Failed to get scopes for token: {e!s}") from e

    async def associate_token_scopes(self, token_id: UUID, scope_ids: list[UUID]) -> int:
        """Associate multiple scopes with a token"""
        if not scope_ids:
            return 0

        try:
            now = datetime.now(UTC)
            values = []
            placeholders = []

            for scope_id in scope_ids:
                values.extend([token_id, scope_id, now])
                placeholders.append("(%s, %s, %s)")

            query = f"""
                INSERT INTO oauth_token_scopes (token_id, scope_id, created_at)
                VALUES {", ".join(placeholders)}
                ON CONFLICT (token_id, scope_id) DO NOTHING
            """

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, values)
                return cur.rowcount

        except Exception as e:
            logger.error(f"Error in associate_token_scopes: {e}")
            raise OperationError(f"Failed to associate token scopes: {e!s}") from e

    async def remove_token_scopes(self, token_id: UUID) -> int:
        """Remove all scope associations for a token"""
        try:
            query = "DELETE FROM oauth_token_scopes WHERE token_id = %s"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [token_id])
                return cur.rowcount

        except Exception as e:
            logger.error(f"Error in remove_token_scopes: {e}")
            raise OperationError(f"Failed to remove token scopes: {e!s}") from e

    async def count_active_scopes(self) -> int:
        """Count the total number of active OAuth scopes"""
        try:
            query = "SELECT COUNT(*) FROM oauth_scopes WHERE is_active = true"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query)
                result = await cur.fetchone()
                return result[0] if result else 0

        except Exception as e:
            logger.error(f"Error in count_active_scopes: {e}")
            raise OperationError(f"Failed to count active scopes: {e!s}") from e
