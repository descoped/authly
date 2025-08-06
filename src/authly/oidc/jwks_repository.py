"""
JWKS Repository for database persistence of JSON Web Keys.

This module provides database operations for storing and retrieving
JWKS keys for OpenID Connect ID token signing and verification.
"""

import json
import logging
from datetime import UTC, datetime

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL
from psycopg_toolkit.exceptions import OperationError
from psycopg_toolkit.utils import PsycopgHelper

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


class JWKSKeyModel:
    """Model representing a JWKS key stored in database."""

    def __init__(
        self,
        kid: str,
        key_data: dict,
        key_type: str,
        algorithm: str,
        key_use: str = "sig",
        is_active: bool = True,
        created_at: datetime = None,
        expires_at: datetime = None,
        key_size: int = None,
        curve: str = None,
    ):
        self.kid = kid
        self.key_data = key_data
        self.key_type = key_type
        self.algorithm = algorithm
        self.key_use = key_use
        self.is_active = is_active
        self.created_at = created_at or datetime.now(UTC)
        self.expires_at = expires_at
        self.key_size = key_size
        self.curve = curve


class JWKSRepository:
    """Repository for JWKS key database operations."""

    def __init__(self, db_connection: AsyncConnection):
        """Initialize repository with database connection."""
        self.db_connection = db_connection

    async def store_key(self, key_model: JWKSKeyModel) -> bool:
        """
        Store a JWKS key in the database.

        Args:
            key_model: JWKS key model to store

        Returns:
            bool: True if stored successfully
        """
        with DatabaseTimer("jwks_key_create"):
            try:
                insert_data = {
                    "kid": key_model.kid,
                    "key_data": json.dumps(key_model.key_data),
                    "key_type": key_model.key_type,
                    "algorithm": key_model.algorithm,
                    "key_use": key_model.key_use,
                    "is_active": key_model.is_active,
                    "created_at": key_model.created_at,
                    "expires_at": key_model.expires_at,
                    "key_size": key_model.key_size,
                    "curve": key_model.curve,
                }

                # Build insert query
                insert_query = PsycopgHelper.build_insert_query(table_name="oidc_jwks_keys", data=insert_data)

                async with self.db_connection.cursor() as cur:
                    await cur.execute(insert_query, list(insert_data.values()))

                logger.info(f"Stored JWKS key with kid: {key_model.kid}")
                return True

            except Exception as e:
                logger.error(f"Error storing JWKS key: {e}")
                raise OperationError(f"Failed to store JWKS key: {e!s}") from e

    async def get_key_by_kid(self, kid: str) -> JWKSKeyModel | None:
        """
        Retrieve a JWKS key by key ID.

        Args:
            kid: Key ID to retrieve

        Returns:
            JWKSKeyModel or None if not found
        """
        with DatabaseTimer("jwks_key_read_by_kid"):
            try:
                query = SQL("SELECT * FROM oidc_jwks_keys WHERE kid = %s")

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, (kid,))
                    result = await cur.fetchone()

                    if result:
                        return JWKSKeyModel(
                            kid=result["kid"],
                            key_data=json.loads(result["key_data"]),
                            key_type=result["key_type"],
                            algorithm=result["algorithm"],
                            key_use=result["key_use"],
                            is_active=result["is_active"],
                            created_at=result["created_at"],
                            expires_at=result["expires_at"],
                            key_size=result["key_size"],
                            curve=result["curve"],
                        )

                    return None

            except Exception as e:
                logger.error(f"Error retrieving JWKS key by kid {kid}: {e}")
                raise OperationError(f"Failed to retrieve JWKS key: {e!s}") from e

    async def get_active_keys(self) -> list[JWKSKeyModel]:
        """
        Retrieve all active JWKS keys.

        Returns:
            List of active JWKSKeyModel instances
        """
        with DatabaseTimer("jwks_key_list_active"):
            try:
                query = SQL("SELECT * FROM oidc_jwks_keys WHERE is_active = true ORDER BY created_at DESC")

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query)
                    results = await cur.fetchall()

                    keys = []
                    for result in results:
                        keys.append(
                            JWKSKeyModel(
                                kid=result["kid"],
                                key_data=json.loads(result["key_data"]),
                                key_type=result["key_type"],
                                algorithm=result["algorithm"],
                                key_use=result["key_use"],
                                is_active=result["is_active"],
                                created_at=result["created_at"],
                                expires_at=result["expires_at"],
                                key_size=result["key_size"],
                                curve=result["curve"],
                            )
                        )

                    return keys

            except Exception as e:
                logger.error(f"Error retrieving active JWKS keys: {e}")
                raise OperationError(f"Failed to retrieve active JWKS keys: {e!s}") from e

    async def deactivate_key(self, kid: str) -> bool:
        """
        Deactivate a JWKS key.

        Args:
            kid: Key ID to deactivate

        Returns:
            bool: True if deactivated successfully
        """
        with DatabaseTimer("jwks_key_deactivate"):
            try:
                query = SQL("UPDATE oidc_jwks_keys SET is_active = false WHERE kid = %s")

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, (kid,))

                logger.info(f"Deactivated JWKS key with kid: {kid}")
                return True

            except Exception as e:
                logger.error(f"Error deactivating JWKS key {kid}: {e}")
                raise OperationError(f"Failed to deactivate JWKS key: {e!s}") from e

    async def cleanup_expired_keys(self) -> int:
        """
        Remove expired JWKS keys from database.

        Returns:
            int: Number of keys removed
        """
        with DatabaseTimer("jwks_key_cleanup"):
            try:
                query = SQL("DELETE FROM oidc_jwks_keys WHERE expires_at IS NOT NULL AND expires_at < %s")

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, (datetime.now(UTC),))
                    rows_affected = cur.rowcount

                logger.info(f"Cleaned up {rows_affected} expired JWKS keys")
                return rows_affected

            except Exception as e:
                logger.error(f"Error cleaning up expired JWKS keys: {e}")
                raise OperationError(f"Failed to cleanup expired JWKS keys: {e!s}") from e
