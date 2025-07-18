import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL
from psycopg_toolkit import BaseRepository, OperationError, RecordNotFoundError
from psycopg_toolkit.utils import PsycopgHelper

from authly.auth import get_password_hash
from authly.oauth.models import OAuthClientModel

logger = logging.getLogger(__name__)


class ClientRepository(BaseRepository[OAuthClientModel, UUID]):
    """Repository for OAuth 2.1 client management with PostgreSQL storage"""

    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection, table_name="oauth_clients", model_class=OAuthClientModel, primary_key="id"
        )

    def _process_client_result(self, result: dict) -> dict:
        """Process database result and convert arrays, handle missing OIDC fields"""
        # Convert PostgreSQL arrays to Python lists
        result["redirect_uris"] = list(result["redirect_uris"]) if result["redirect_uris"] else []
        result["grant_types"] = list(result["grant_types"]) if result["grant_types"] else []
        result["response_types"] = list(result["response_types"]) if result["response_types"] else []
        result["request_uris"] = list(result["request_uris"]) if result["request_uris"] else []
        result["contacts"] = list(result["contacts"]) if result["contacts"] else []

        # Handle missing OIDC fields with defaults
        if "id_token_signed_response_alg" not in result or result["id_token_signed_response_alg"] is None:
            result["id_token_signed_response_alg"] = "RS256"
        if "subject_type" not in result or result["subject_type"] is None:
            result["subject_type"] = "public"
        if "application_type" not in result or result["application_type"] is None:
            result["application_type"] = "web"
        if "require_auth_time" not in result or result["require_auth_time"] is None:
            result["require_auth_time"] = False

        return result

    async def get_by_client_id(self, client_id: str) -> Optional[OAuthClientModel]:
        """Get OAuth client by client_id"""
        try:
            query = PsycopgHelper.build_select_query(table_name="oauth_clients", where_clause={"client_id": client_id})
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [client_id])
                result = await cur.fetchone()
                if result:
                    result = dict(result)
                    result = self._process_client_result(result)
                    return OAuthClientModel(**result)
                return None
        except Exception as e:
            logger.error(f"Error in get_by_client_id: {e}")
            raise OperationError(f"Failed to get client by client_id: {str(e)}") from e

    async def create_client(self, client_data: dict) -> OAuthClientModel:
        """Create a new OAuth client"""
        try:
            # Prepare data for insertion
            insert_data = client_data.copy()

            # Handle client secret hashing
            if "client_secret" in insert_data:
                client_secret = insert_data.pop("client_secret")
                if client_secret:  # Only hash if secret is provided
                    insert_data["client_secret_hash"] = get_password_hash(client_secret)
                else:
                    insert_data["client_secret_hash"] = None

            # Handle array fields for PostgreSQL
            if "redirect_uris" in insert_data:
                insert_data["redirect_uris"] = list(insert_data["redirect_uris"])
            if "grant_types" in insert_data:
                insert_data["grant_types"] = [
                    gt.value if hasattr(gt, "value") else str(gt) for gt in insert_data["grant_types"]
                ]
            if "response_types" in insert_data:
                insert_data["response_types"] = [
                    rt.value if hasattr(rt, "value") else str(rt) for rt in insert_data["response_types"]
                ]

            # Handle OIDC array fields
            if "request_uris" in insert_data:
                insert_data["request_uris"] = list(insert_data["request_uris"]) if insert_data["request_uris"] else []
            if "contacts" in insert_data:
                insert_data["contacts"] = list(insert_data["contacts"]) if insert_data["contacts"] else []

            # Build insert query with database-generated timestamps for consistency
            # Remove any manually set timestamps to use NOW() from database
            insert_data.pop("created_at", None)
            insert_data.pop("updated_at", None)

            # Build columns and values for the insert
            columns = list(insert_data.keys()) + ["created_at", "updated_at"]
            values_placeholders = ["%s"] * len(insert_data) + ["NOW()", "NOW()"]
            values = list(insert_data.values())

            insert_query = SQL("INSERT INTO oauth_clients ({}) VALUES ({})").format(
                SQL(", ").join(SQL('"{}"'.format(col)) for col in columns),
                SQL(", ").join(SQL(placeholder) for placeholder in values_placeholders),
            )

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(insert_query + SQL(" RETURNING *"), values)
                result = await cur.fetchone()
                if result:
                    result = dict(result)
                    result = self._process_client_result(result)
                    return OAuthClientModel(**result)

            raise OperationError("Failed to create client - no result returned")

        except Exception as e:
            logger.error(f"Error in create_client: {e}")
            raise OperationError(f"Failed to create client: {str(e)}") from e

    async def update_client(self, client_id: UUID, update_data: dict) -> OAuthClientModel:
        """Update an existing OAuth client"""
        try:
            # Prepare update data
            prepared_data = update_data.copy()

            # Handle array fields
            if "redirect_uris" in prepared_data:
                prepared_data["redirect_uris"] = list(prepared_data["redirect_uris"])
            if "grant_types" in prepared_data:
                prepared_data["grant_types"] = [
                    gt.value if hasattr(gt, "value") else str(gt) for gt in prepared_data["grant_types"]
                ]
            if "response_types" in prepared_data:
                prepared_data["response_types"] = [
                    rt.value if hasattr(rt, "value") else str(rt) for rt in prepared_data["response_types"]
                ]

            # Handle OIDC array fields
            if "request_uris" in prepared_data:
                prepared_data["request_uris"] = (
                    list(prepared_data["request_uris"]) if prepared_data["request_uris"] else []
                )
            if "contacts" in prepared_data:
                prepared_data["contacts"] = list(prepared_data["contacts"]) if prepared_data["contacts"] else []

            # Set updated timestamp using NOW() for accurate timing
            # We need to do this in the query, not in Python, to ensure proper ordering

            # Build a custom query that includes NOW() for updated_at
            set_clauses = []
            values = []

            for key, value in prepared_data.items():
                set_clauses.append(f'"{key}" = %s')
                values.append(value)

            # Add updated_at with clock_timestamp() for precise timing
            set_clauses.append('"updated_at" = clock_timestamp()')

            # Add client_id for WHERE clause
            values.append(client_id)

            update_query = SQL("UPDATE oauth_clients SET {} WHERE id = %s").format(
                SQL(", ").join(SQL(clause) for clause in set_clauses)
            )

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(update_query + SQL(" RETURNING *"), values)
                result = await cur.fetchone()
                if result:
                    result = dict(result)
                    result = self._process_client_result(result)
                    return OAuthClientModel(**result)

            raise RecordNotFoundError(f"Client with id {client_id} not found")

        except RecordNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Error in update_client: {e}")
            raise OperationError(f"Failed to update client: {str(e)}") from e

    async def delete_client(self, client_id: UUID) -> bool:
        """Delete an OAuth client (soft delete by setting is_active=False)"""
        try:
            # Use direct SQL to properly set updated_at with NOW()
            query = SQL("UPDATE oauth_clients SET is_active = %s, updated_at = NOW() WHERE id = %s RETURNING id")

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [False, client_id])
                result = await cur.fetchone()
                return result is not None

        except Exception as e:
            logger.error(f"Error in delete_client: {e}")
            raise OperationError(f"Failed to delete client: {str(e)}") from e

    async def get_active_clients(self, limit: int = 100, offset: int = 0) -> List[OAuthClientModel]:
        """Get all active OAuth clients with pagination"""
        try:
            query = """
                SELECT * FROM oauth_clients 
                WHERE is_active = true 
                ORDER BY created_at DESC 
                LIMIT %s OFFSET %s
            """

            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [limit, offset])
                results = await cur.fetchall()

                clients = []
                for result in results:
                    result = dict(result)
                    # Convert PostgreSQL arrays to Python lists
                    result["redirect_uris"] = list(result["redirect_uris"]) if result["redirect_uris"] else []
                    result["grant_types"] = list(result["grant_types"]) if result["grant_types"] else []
                    result["response_types"] = list(result["response_types"]) if result["response_types"] else []
                    result["request_uris"] = list(result["request_uris"]) if result["request_uris"] else []
                    result["contacts"] = list(result["contacts"]) if result["contacts"] else []
                    clients.append(OAuthClientModel(**result))

                return clients

        except Exception as e:
            logger.error(f"Error in get_active_clients: {e}")
            raise OperationError(f"Failed to get active clients: {str(e)}") from e

    async def count_active_clients(self) -> int:
        """Count the total number of active OAuth clients"""
        try:
            query = "SELECT COUNT(*) FROM oauth_clients WHERE is_active = true"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query)
                result = await cur.fetchone()
                return result[0] if result else 0

        except Exception as e:
            logger.error(f"Error in count_active_clients: {e}")
            raise OperationError(f"Failed to count active clients: {str(e)}") from e

    async def client_exists(self, client_id: str) -> bool:
        """Check if a client exists by client_id"""
        try:
            query = "SELECT 1 FROM oauth_clients WHERE client_id = %s AND is_active = true"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [client_id])
                result = await cur.fetchone()
                return result is not None

        except Exception as e:
            logger.error(f"Error in client_exists: {e}")
            raise OperationError(f"Failed to check client existence: {str(e)}") from e

    async def get_client_scopes(self, client_id: UUID) -> List[str]:
        """Get all scope names associated with a client"""
        try:
            query = """
                SELECT s.scope_name 
                FROM oauth_scopes s
                JOIN oauth_client_scopes cs ON s.id = cs.scope_id
                WHERE cs.client_id = %s AND s.is_active = true
                ORDER BY s.scope_name
            """

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [client_id])
                results = await cur.fetchall()
                return [row[0] for row in results]

        except Exception as e:
            logger.error(f"Error in get_client_scopes: {e}")
            raise OperationError(f"Failed to get client scopes: {str(e)}") from e

    async def add_client_scope(self, client_id: UUID, scope_id: UUID) -> bool:
        """Associate a scope with a client"""
        try:
            query = """
                INSERT INTO oauth_client_scopes (client_id, scope_id, created_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (client_id, scope_id) DO NOTHING
                RETURNING id
            """

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [client_id, scope_id, datetime.now(timezone.utc)])
                result = await cur.fetchone()
                return result is not None

        except Exception as e:
            logger.error(f"Error in add_client_scope: {e}")
            raise OperationError(f"Failed to add client scope: {str(e)}") from e

    async def remove_client_scope(self, client_id: UUID, scope_id: UUID) -> bool:
        """Remove a scope association from a client"""
        try:
            query = "DELETE FROM oauth_client_scopes WHERE client_id = %s AND scope_id = %s"

            async with self.db_connection.cursor() as cur:
                await cur.execute(query, [client_id, scope_id])
                return cur.rowcount > 0

        except Exception as e:
            logger.error(f"Error in remove_client_scope: {e}")
            raise OperationError(f"Failed to remove client scope: {str(e)}") from e

    async def associate_client_scopes(self, client_id: UUID, scope_ids: List[UUID]) -> int:
        """Associate multiple scopes with a client"""
        try:
            if not scope_ids:
                return 0

            # Build bulk insert query
            insert_data = []
            now = datetime.now(timezone.utc)
            for scope_id in scope_ids:
                insert_data.append({"client_id": client_id, "scope_id": scope_id, "created_at": now})

            # Use the first data item as template
            query = PsycopgHelper.build_insert_query(
                table_name="oauth_client_scopes", data=insert_data[0], batch_size=len(insert_data)
            )

            # Prepare values for batch insert
            values = []
            for data in insert_data:
                values.extend([data["client_id"], data["scope_id"], data["created_at"]])

            async with self.db_connection.cursor() as cur:
                await cur.execute(query + SQL(" ON CONFLICT (client_id, scope_id) DO NOTHING"), values)
                return cur.rowcount

        except Exception as e:
            logger.error(f"Error in associate_client_scopes: {e}")
            raise OperationError(f"Failed to associate client scopes: {str(e)}") from e
