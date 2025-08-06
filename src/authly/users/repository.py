import logging
from datetime import UTC, datetime
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL, Placeholder
from psycopg_toolkit import BaseRepository, OperationError, RecordNotFoundError
from psycopg_toolkit.utils import PsycopgHelper

from authly.users import UserModel

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


class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="users",
            model_class=UserModel,
            primary_key="id",
            # Enable automatic JSON detection for address field
            auto_detect_json=True,
            # Specify date/timestamp fields for automatic conversion (v0.2.2)
            # Note: birthdate is kept as string per OIDC spec (YYYY-MM-DD format)
            date_fields={"created_at", "updated_at", "last_login"},
        )

    async def get_by_username(self, username: str) -> UserModel | None:
        with DatabaseTimer("user_read_by_username"):
            try:
                query = PsycopgHelper.build_select_query(table_name="users", where_clause={"username": username})
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [username])
                    result = await cur.fetchone()
                    if result:
                        return UserModel(**result)
                    return None
            except Exception as e:
                logger.error(f"Error in get_by_username: {e}")
                raise OperationError(f"Failed to get user by username: {e!s}") from e

    async def get_by_email(self, email: str) -> UserModel | None:
        with DatabaseTimer("user_read_by_email"):
            try:
                query = PsycopgHelper.build_select_query(table_name="users", where_clause={"email": email})
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [email])
                    result = await cur.fetchone()
                    if result:
                        return UserModel(**result)
                    return None
            except Exception as e:
                logger.error(f"Error in get_by_email: {e}")
                raise OperationError(f"Failed to get user by email: {e!s}") from e

    async def update_last_login(self, user_id: UUID) -> UserModel:
        with DatabaseTimer("user_update_last_login"):
            try:
                query = PsycopgHelper.build_update_query(
                    table_name="users",
                    data={"last_login": "CURRENT_TIMESTAMP_PLACEHOLDER"},
                    where_clause={"id": "USER_ID_PLACEHOLDER"},
                )
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query + SQL(" RETURNING *"), [datetime.now(UTC), user_id])
                    result = await cur.fetchone()
                    if not result:
                        raise RecordNotFoundError(f"User with id {user_id} not found")
                    return UserModel(**result)
            except Exception as e:
                logger.error(f"Error in update_last_login: {e}")
                if isinstance(e, RecordNotFoundError):
                    raise
                raise OperationError(f"Failed to update last login: {e!s}") from e

    async def get_paginated(self, skip: int = 0, limit: int = 100) -> list[UserModel]:
        """Get paginated list of users.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return (default 100)

        Returns:
            List of user models
        """
        # noinspection SqlDialectInspection,SqlNoDataSourceInspection
        query = SQL(
            """
            SELECT *
            FROM users
            ORDER BY created_at DESC
            LIMIT {} OFFSET {}
        """
        ).format(Placeholder(), Placeholder())

        with DatabaseTimer("user_list_paginated"):
            try:
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [limit, skip])
                    results = await cur.fetchall()
                    return [UserModel(**row) for row in results]
            except Exception as e:
                logger.error(f"Error in get_paginated: {e}")
                raise OperationError(f"Failed to get paginated users: {e!s}") from e

    async def get_filtered_paginated(
        self, filters: dict | None = None, skip: int = 0, limit: int = 100
    ) -> list[UserModel]:
        """
        Get paginated list of users with advanced filtering.

        Args:
            filters: Dictionary of filter criteria
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of filtered user models
        """
        where_conditions, params = self._build_filter_conditions(filters or {})

        query_parts = ["SELECT * FROM users"]

        if where_conditions:
            query_parts.append("WHERE " + " AND ".join(where_conditions))

        query_parts.extend(["ORDER BY created_at DESC", f"LIMIT {limit} OFFSET {skip}"])

        query = SQL(" ".join(query_parts))

        with DatabaseTimer("user_list_filtered_paginated"):
            try:
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, params)
                    results = await cur.fetchall()
                    return [UserModel(**row) for row in results]
            except Exception as e:
                logger.error(f"Error in get_filtered_paginated: {e}")
                raise OperationError(f"Failed to get filtered paginated users: {e!s}") from e

    async def count_filtered(self, filters: dict | None = None) -> int:
        """
        Count total users matching filter criteria.

        Args:
            filters: Dictionary of filter criteria

        Returns:
            Total count of matching users
        """
        where_conditions, params = self._build_filter_conditions(filters or {})

        query_parts = ["SELECT COUNT(*) FROM users"]

        if where_conditions:
            query_parts.append("WHERE " + " AND ".join(where_conditions))

        query = SQL(" ".join(query_parts))

        with DatabaseTimer("user_count_filtered"):
            try:
                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, params)
                    result = await cur.fetchone()
                    return result[0] if result else 0
            except Exception as e:
                logger.error(f"Error in count_filtered: {e}")
                raise OperationError(f"Failed to count filtered users: {e!s}") from e

    def _build_filter_conditions(self, filters: dict) -> tuple[list[str], list]:
        """
        Build WHERE conditions and parameters from filter dictionary.

        Args:
            filters: Dictionary of filter criteria

        Returns:
            Tuple of (conditions list, parameters list)
        """
        conditions = []
        params = []

        # Text search filters (case-insensitive partial match)
        if filters.get("username"):
            conditions.append("username ILIKE %s")
            params.append(f"%{filters['username']}%")

        if filters.get("email"):
            conditions.append("email ILIKE %s")
            params.append(f"%{filters['email']}%")

        if filters.get("given_name"):
            conditions.append("given_name ILIKE %s")
            params.append(f"%{filters['given_name']}%")

        if filters.get("family_name"):
            conditions.append("family_name ILIKE %s")
            params.append(f"%{filters['family_name']}%")

        # Boolean status filters
        for bool_field in ["is_active", "is_admin", "is_verified", "requires_password_change"]:
            if bool_field in filters and filters[bool_field] is not None:
                conditions.append(f"{bool_field} = %s")
                params.append(filters[bool_field])

        # Date range filters
        if filters.get("created_after"):
            conditions.append("created_at >= %s")
            params.append(filters["created_after"])

        if filters.get("created_before"):
            conditions.append("created_at <= %s")
            params.append(filters["created_before"])

        if filters.get("last_login_after"):
            conditions.append("last_login >= %s")
            params.append(filters["last_login_after"])

        if filters.get("last_login_before"):
            conditions.append("last_login <= %s")
            params.append(filters["last_login_before"])

        # OIDC profile filters
        if filters.get("locale"):
            conditions.append("locale = %s")
            params.append(filters["locale"])

        if filters.get("zoneinfo"):
            conditions.append("zoneinfo = %s")
            params.append(filters["zoneinfo"])

        return conditions, params

    async def get_admin_users(self) -> list[UserModel]:
        """
        Get all users with admin privileges.

        Returns:
            List of admin users
        """
        query = SQL("SELECT * FROM users WHERE is_admin = %s ORDER BY created_at DESC")

        with DatabaseTimer("user_list_admins"):
            try:
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [True])
                    results = await cur.fetchall()
                    return [UserModel(**row) for row in results]
            except Exception as e:
                logger.error(f"Error in get_admin_users: {e}")
                raise OperationError(f"Failed to get admin users: {e!s}") from e

    async def get_optimized_admin_listing(
        self, filters: dict | None = None, skip: int = 0, limit: int = 100
    ) -> tuple[list[dict], int, int]:
        """
        Get optimized paginated admin user listing with session counts using CTE.

        This method uses a Common Table Expression (CTE) to:
        1. Filter users efficiently
        2. Include session counts inline
        3. Get total count and data in a single query
        4. Minimize database round trips

        Args:
            filters: Dictionary of filter criteria
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            Tuple of (user_list_with_sessions, total_count, active_users_count)
        """
        where_conditions, params = self._build_filter_conditions(filters or {})

        # Build the optimized CTE query
        base_where = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""

        query = SQL(f"""
            WITH filtered_users AS (
                -- Filter users based on criteria
                SELECT
                    u.*,
                    -- Count active sessions for each user inline
                    COALESCE(
                        (SELECT COUNT(*)
                         FROM tokens t
                         WHERE t.user_id = u.id
                           AND t.token_type = 'access'
                           AND NOT t.invalidated
                           AND t.expires_at > CURRENT_TIMESTAMP),
                        0
                    ) as active_sessions
                FROM users u
                {base_where}
            ),
            counts AS (
                -- Get various counts in parallel
                SELECT
                    COUNT(*) as total_count,
                    COUNT(*) FILTER (WHERE is_active = true) as active_count
                FROM filtered_users
            )
            -- Main query with pagination
            SELECT
                fu.*,
                c.total_count,
                c.active_count
            FROM filtered_users fu
            CROSS JOIN counts c
            ORDER BY fu.created_at DESC
            LIMIT %s OFFSET %s
        """)

        # Add pagination parameters
        query_params = [*params, limit, skip]

        with DatabaseTimer("user_optimized_admin_listing"):
            try:
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, query_params)
                    results = await cur.fetchall()

                    if not results:
                        return [], 0, 0

                    # Extract counts from first row (all rows have same count values)
                    total_count = results[0]["total_count"]
                    active_count = results[0]["active_count"]

                    # Clean up the user data (remove count fields)
                    users = []
                    for row in results:
                        user_data = dict(row)
                        # Remove the count fields from user data
                        user_data.pop("total_count", None)
                        user_data.pop("active_count", None)
                        users.append(user_data)

                    return users, total_count, active_count

            except Exception as e:
                logger.error(f"Error in get_optimized_admin_listing: {e}")
                raise OperationError(f"Failed to get optimized admin listing: {e!s}") from e

    async def get_user_with_session_count(self, user_id: UUID) -> dict | None:
        """
        Get a single user with their active session count efficiently.

        Args:
            user_id: User ID to retrieve

        Returns:
            User data dict with active_sessions field, or None if not found
        """
        query = SQL("""
            SELECT
                u.*,
                COALESCE(
                    (SELECT COUNT(*)
                     FROM tokens t
                     WHERE t.user_id = u.id
                       AND t.token_type = 'access'
                       AND NOT t.invalidated
                       AND t.expires_at > CURRENT_TIMESTAMP),
                    0
                ) as active_sessions
            FROM users u
            WHERE u.id = %s
        """)

        with DatabaseTimer("user_read_with_session_count"):
            try:
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [user_id])
                    result = await cur.fetchone()
                    return dict(result) if result else None
            except Exception as e:
                logger.error(f"Error in get_user_with_session_count: {e}")
                raise OperationError(f"Failed to get user with session count: {e!s}") from e
