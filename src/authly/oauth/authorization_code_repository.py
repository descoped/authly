import logging
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.sql import SQL
from psycopg_toolkit import BaseRepository, OperationError
from psycopg_toolkit.utils import PsycopgHelper

from authly.oauth.models import OAuthAuthorizationCodeModel

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


class AuthorizationCodeRepository(BaseRepository[OAuthAuthorizationCodeModel, UUID]):
    """Repository for OAuth 2.1 authorization code management with PKCE support"""

    def __init__(self, db_connection: AsyncConnection):
        super().__init__(
            db_connection=db_connection,
            table_name="oauth_authorization_codes",
            model_class=OAuthAuthorizationCodeModel,
            primary_key="id",
            # Specify all date/timestamp fields for automatic conversion (v0.2.2)
            date_fields={"created_at", "expires_at", "used_at"},
        )

    async def create_authorization_code(self, code_data: dict) -> OAuthAuthorizationCodeModel:
        """
        Create a new authorization code from dictionary data.
        """
        with DatabaseTimer("authorization_code_create"):
            try:
                # Set timestamps if not provided
                insert_data = code_data.copy()
                now = datetime.now(UTC)
                if "created_at" not in insert_data:
                    insert_data["created_at"] = now
                if "is_used" not in insert_data:
                    insert_data["is_used"] = False

                # Build insert query
                insert_query = PsycopgHelper.build_insert_query(
                    table_name="oauth_authorization_codes", data=insert_data
                )

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(insert_query + SQL(" RETURNING *"), list(insert_data.values()))
                    result = await cur.fetchone()
                    if result:
                        return OAuthAuthorizationCodeModel(**result)

                raise OperationError("Failed to create authorization code - no result returned")

            except Exception as e:
                logger.error(f"Error in create_authorization_code: {e}")
                raise OperationError(f"Failed to create authorization code: {e!s}") from e

    async def create_authorization_code_with_params(
        self,
        client_id: UUID,
        user_id: UUID,
        redirect_uri: str,
        scope: str | None,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state: str | None = None,
        nonce: str | None = None,
        expires_in_minutes: int = 10,
    ) -> OAuthAuthorizationCodeModel:
        """
        Create a new authorization code with PKCE parameters.
        OAuth 2.1 requires codes to expire quickly (max 10 minutes).
        """
        try:
            # Generate cryptographically secure authorization code
            code = secrets.token_urlsafe(32)

            # Calculate expiration time
            now = datetime.now(UTC)
            expires_at = now + timedelta(minutes=expires_in_minutes)

            code_data = {
                "code": code,
                "client_id": client_id,
                "user_id": user_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "expires_at": expires_at,
                "created_at": now,
                "is_used": False,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "state": state,
                "nonce": nonce,
            }

            # Use the dictionary method
            return await self.create_authorization_code(code_data)

        except Exception as e:
            logger.error(f"Error in create_authorization_code_with_params: {e}")
            raise OperationError(f"Failed to create authorization code: {e!s}") from e

    async def get_by_code(self, code: str) -> OAuthAuthorizationCodeModel | None:
        """Get authorization code by code value"""
        with DatabaseTimer("authorization_code_read_by_code"):
            try:
                query = PsycopgHelper.build_select_query(
                    table_name="oauth_authorization_codes", where_clause={"code": code}
                )
                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [code])
                    result = await cur.fetchone()
                    return OAuthAuthorizationCodeModel(**result) if result else None
            except Exception as e:
                logger.error(f"Error in get_by_code: {e}")
                raise OperationError(f"Failed to get authorization code: {e!s}") from e

    async def consume_authorization_code(self, code: str) -> OAuthAuthorizationCodeModel | None:
        """
        Mark authorization code as used and return it.
        This operation is atomic to prevent race conditions.
        """
        return await self.use_authorization_code(code)

    async def use_authorization_code(self, code: str) -> OAuthAuthorizationCodeModel | None:
        """
        Mark authorization code as used and return it.
        This operation is atomic to prevent race conditions.
        """
        with DatabaseTimer("authorization_code_consume"):
            try:
                now = datetime.now(UTC)

                # Update code as used and return the record
                query = """
                    UPDATE oauth_authorization_codes
                    SET is_used = true, used_at = %s
                    WHERE code = %s AND is_used = false
                    RETURNING *
                """

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [now, code])
                    result = await cur.fetchone()
                    return OAuthAuthorizationCodeModel(**result) if result else None

            except Exception as e:
                logger.error(f"Error in use_authorization_code: {e}")
                raise OperationError(f"Failed to use authorization code: {e!s}") from e

    async def validate_and_consume_code(
        self, code: str, client_id: UUID, redirect_uri: str, code_verifier: str
    ) -> OAuthAuthorizationCodeModel | None:
        """
        Validate authorization code with PKCE verification and mark as used.
        This is the main method for OAuth 2.1 token exchange.
        """
        try:
            # First, get the code (but don't mark as used yet)
            auth_code = await self.get_by_code(code)
            if not auth_code:
                logger.warning(f"Authorization code not found: {code}")
                return None

            # Validate the code hasn't been used
            if auth_code.is_used:
                logger.warning(f"Authorization code already used: {code}")
                return None

            # Validate the code hasn't expired
            if auth_code.is_expired():
                logger.warning(f"Authorization code expired: {code}")
                return None

            # Validate client_id matches
            if auth_code.client_id != client_id:
                logger.warning(f"Client ID mismatch for code: {code}")
                return None

            # Validate redirect_uri matches
            if auth_code.redirect_uri != redirect_uri:
                logger.warning(f"Redirect URI mismatch for code: {code}")
                return None

            # Validate PKCE code verifier
            if not self._verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                logger.warning(f"PKCE verification failed for code: {code}")
                return None

            # All validations passed - mark code as used
            used_code = await self.use_authorization_code(code)
            if used_code:
                logger.info(f"Authorization code successfully validated and consumed: {code}")
                return used_code
            else:
                logger.error(f"Failed to mark authorization code as used: {code}")
                return None

        except Exception as e:
            logger.error(f"Error in validate_and_consume_code: {e}")
            raise OperationError(f"Failed to validate and consume authorization code: {e!s}") from e

    async def verify_pkce_challenge(self, code: str, code_verifier: str) -> bool:
        """
        Verify PKCE challenge for an authorization code.

        Args:
            code: Authorization code
            code_verifier: PKCE code verifier to validate

        Returns:
            True if PKCE verification succeeds
        """
        try:
            auth_code = await self.get_by_code(code)
            if not auth_code:
                return False

            return self._verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method)

        except Exception as e:
            logger.error(f"Error in verify_pkce_challenge: {e}")
            return False

    def _verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
        """
        Verify PKCE code verifier against code challenge.
        OAuth 2.1 only supports S256 method.
        """
        import base64
        import hashlib

        if method != "S256":
            logger.error(f"Unsupported PKCE method: {method}")
            return False

        try:
            # Generate SHA256 hash of the verifier
            verifier_hash = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            # Base64url encode the hash
            calculated_challenge = base64.urlsafe_b64encode(verifier_hash).decode("utf-8").rstrip("=")

            # Compare with stored challenge
            return calculated_challenge == code_challenge

        except Exception as e:
            logger.error(f"Error in PKCE verification: {e}")
            return False

    async def cleanup_expired_codes(self, before_datetime: datetime | None = None) -> int:
        """Clean up expired authorization codes"""
        if before_datetime is None:
            before_datetime = datetime.now(UTC)

        with DatabaseTimer("authorization_code_cleanup"):
            try:
                query = "DELETE FROM oauth_authorization_codes WHERE expires_at < %s"

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [before_datetime])
                    deleted_count = cur.rowcount

                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} expired authorization codes")

                return deleted_count

            except Exception as e:
                logger.error(f"Error in cleanup_expired_codes: {e}")
                raise OperationError(f"Failed to cleanup expired codes: {e!s}") from e

    async def get_codes_for_user(self, user_id: UUID, limit: int = 10) -> list[OAuthAuthorizationCodeModel]:
        """Get recent authorization codes for a user (for debugging/auditing)"""
        with DatabaseTimer("authorization_code_list_user"):
            try:
                query = """
                    SELECT * FROM oauth_authorization_codes
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                """

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [user_id, limit])
                    results = await cur.fetchall()
                    return [OAuthAuthorizationCodeModel(**result) for result in results]

            except Exception as e:
                logger.error(f"Error in get_codes_for_user: {e}")
                raise OperationError(f"Failed to get codes for user: {e!s}") from e

    async def get_codes_for_client(self, client_id: UUID, limit: int = 10) -> list[OAuthAuthorizationCodeModel]:
        """Get recent authorization codes for a client (for debugging/auditing)"""
        with DatabaseTimer("authorization_code_list_client"):
            try:
                query = """
                    SELECT * FROM oauth_authorization_codes
                    WHERE client_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                """

                async with self.db_connection.cursor(row_factory=dict_row) as cur:
                    await cur.execute(query, [client_id, limit])
                    results = await cur.fetchall()
                    return [OAuthAuthorizationCodeModel(**result) for result in results]

            except Exception as e:
                logger.error(f"Error in get_codes_for_client: {e}")
                raise OperationError(f"Failed to get codes for client: {e!s}") from e

    async def revoke_codes_for_user(self, user_id: UUID) -> int:
        """Revoke all unused authorization codes for a user"""
        with DatabaseTimer("authorization_code_revoke_user"):
            try:
                now = datetime.now(UTC)
                query = """
                    UPDATE oauth_authorization_codes
                    SET is_used = true, used_at = %s
                    WHERE user_id = %s AND is_used = false
                """

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [now, user_id])
                    return cur.rowcount

            except Exception as e:
                logger.error(f"Error in revoke_codes_for_user: {e}")
                raise OperationError(f"Failed to revoke codes for user: {e!s}") from e

    async def revoke_codes_for_client(self, client_id: UUID) -> int:
        """Revoke all unused authorization codes for a client"""
        with DatabaseTimer("authorization_code_revoke_client"):
            try:
                now = datetime.now(UTC)
                query = """
                    UPDATE oauth_authorization_codes
                    SET is_used = true, used_at = %s
                    WHERE client_id = %s AND is_used = false
                """

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [now, client_id])
                    return cur.rowcount

            except Exception as e:
                logger.error(f"Error in revoke_codes_for_client: {e}")
                raise OperationError(f"Failed to revoke codes for client: {e!s}") from e

    async def count_active_codes(self) -> int:
        """Count active (unused and not expired) authorization codes"""
        with DatabaseTimer("authorization_code_count"):
            try:
                now = datetime.now(UTC)
                query = """
                    SELECT COUNT(*) FROM oauth_authorization_codes
                    WHERE is_used = false AND expires_at > %s
                """

                async with self.db_connection.cursor() as cur:
                    await cur.execute(query, [now])
                    result = await cur.fetchone()
                    return result[0] if result else 0

            except Exception as e:
                logger.error(f"Error in count_active_codes: {e}")
                raise OperationError(f"Failed to count active codes: {e!s}") from e
