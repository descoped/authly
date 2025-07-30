import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL, Placeholder
from psycopg_toolkit import BaseRepository, OperationError, RecordNotFoundError
from psycopg_toolkit.utils import PsycopgHelper

from authly.users import UserModel

logger = logging.getLogger(__name__)


class UserRepository(BaseRepository[UserModel, UUID]):
    def __init__(self, db_connection: AsyncConnection):
        super().__init__(db_connection=db_connection, table_name="users", model_class=UserModel, primary_key="id")

    async def get_by_username(self, username: str) -> Optional[UserModel]:
        try:
            query = PsycopgHelper.build_select_query(table_name="users", where_clause={"username": username})
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [username])
                result = await cur.fetchone()
                return UserModel(**result) if result else None
        except Exception as e:
            logger.error(f"Error in get_by_username: {e}")
            raise OperationError(f"Failed to get user by username: {str(e)}") from e

    async def get_by_email(self, email: str) -> Optional[UserModel]:
        try:
            query = PsycopgHelper.build_select_query(table_name="users", where_clause={"email": email})
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [email])
                result = await cur.fetchone()
                return UserModel(**result) if result else None
        except Exception as e:
            logger.error(f"Error in get_by_email: {e}")
            raise OperationError(f"Failed to get user by email: {str(e)}") from e

    async def update_last_login(self, user_id: UUID) -> UserModel:
        try:
            query = PsycopgHelper.build_update_query(
                table_name="users",
                data={"last_login": "CURRENT_TIMESTAMP_PLACEHOLDER"},
                where_clause={"id": "USER_ID_PLACEHOLDER"},
            )
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query + SQL(" RETURNING *"), [datetime.now(timezone.utc), user_id])
                result = await cur.fetchone()
                if not result:
                    raise RecordNotFoundError(f"User with id {user_id} not found")
                return UserModel(**result)
        except Exception as e:
            logger.error(f"Error in update_last_login: {e}")
            if isinstance(e, RecordNotFoundError):
                raise
            raise OperationError(f"Failed to update last login: {str(e)}") from e

    async def get_paginated(self, skip: int = 0, limit: int = 100) -> List[UserModel]:
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

        try:
            async with self.db_connection.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, [limit, skip])
                results = await cur.fetchall()
                return [UserModel(**row) for row in results]
        except Exception as e:
            logger.error(f"Error in get_paginated: {e}")
            raise OperationError(f"Failed to get paginated users: {str(e)}")
