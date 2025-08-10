"""
OAuth 2.0 Client Credentials Grant Implementation.

This module implements the client credentials grant type for machine-to-machine
authentication as specified in RFC 6749 Section 4.4.

The client credentials grant is used when:
- The client is acting on its own behalf (not on behalf of a user)
- Machine-to-machine authentication is needed
- No user interaction is required

Security requirements:
- Only confidential clients can use this grant type
- Client must authenticate using client_secret
- No refresh tokens are issued
"""

import logging
import time
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from jose import jwt

from authly.auth import create_access_token
from authly.config import AuthlyConfig
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """Custom exception for OAuth errors."""

    def __init__(self, error: str, error_description: str = None, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code
        super().__init__(error_description or error)


# Import metrics if available
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    METRICS_ENABLED = False
    metrics = None


class ClientCredentialsGrantHandler:
    """
    Handler for OAuth 2.0 Client Credentials grant type.

    This handler processes client credentials grant requests,
    validates client authentication, and issues access tokens
    for machine-to-machine authentication.
    """

    def __init__(
        self,
        client_repo: ClientRepository,
        scope_repo: ScopeRepository,
        token_repo: TokenRepository,
        config: AuthlyConfig,
    ):
        """
        Initialize the client credentials grant handler.

        Args:
            client_repo: Repository for OAuth client operations
            scope_repo: Repository for scope operations
            token_repo: Repository for token storage
            config: Authly configuration
        """
        self.client_repo = client_repo
        self.scope_repo = scope_repo
        self.token_repo = token_repo
        self.config = config

    async def handle_client_credentials_grant(
        self,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> dict:
        """
        Process a client credentials grant request.

        Args:
            client_id: The client identifier
            client_secret: The client secret for authentication
            scope: Optional requested scopes (space-separated)

        Returns:
            Token response dictionary containing access_token, token_type, expires_in, and scope

        Raises:
            HTTPException: If client authentication fails or request is invalid
        """
        start_time = time.time()

        # Validate client exists
        client = await self.client_repo.get_by_client_id(client_id)
        if not client:
            logger.warning(f"Client credentials grant failed: client {client_id} not found")
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("client_credentials", client_id, "client_not_found", duration)
            # Return 401 for invalid client credentials (client not found is same as invalid credentials)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")

        # Verify client is confidential (only confidential clients can use client_credentials)
        if client.client_type != ClientType.CONFIDENTIAL:
            logger.warning(f"Client credentials grant failed: client {client_id} is not confidential")
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("client_credentials", client_id, "client_not_confidential", duration)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client credentials grant requires a confidential client",
            )

        # Verify client secret
        from authly.auth import verify_password

        if not client.client_secret_hash or not verify_password(client_secret, client.client_secret_hash):
            logger.warning(f"Client credentials grant failed: invalid secret for client {client_id}")
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("client_credentials", client_id, "invalid_secret", duration)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")

        # Check if client_credentials is in allowed grant types
        if client.grant_types and "client_credentials" not in client.grant_types:
            logger.warning(f"Client credentials grant failed: grant type not allowed for client {client_id}")
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_oauth_token_request("client_credentials", client_id, "grant_type_not_allowed", duration)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client is not authorized to use client_credentials grant",
            )

        # Validate and filter scopes
        granted_scopes = await self._validate_scopes(client, scope)

        # Generate access token (no refresh token for client_credentials)
        access_token = await self._create_client_access_token(
            client_id=client_id,
            client_uuid=client.id,
            scope=granted_scopes,
        )

        # Track successful client credentials grant
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_oauth_token_request("client_credentials", client_id, "success", duration)
            metrics.track_login_attempt("success", "client_credentials", client_id)

        logger.info(f"Client credentials grant successful for client {client_id}")

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_expire_minutes * 60,
            "scope": granted_scopes if granted_scopes else None,
        }

    async def _validate_scopes(self, client, requested_scope: str | None) -> str | None:
        """
        Validate and filter requested scopes against client's allowed scopes.

        Args:
            client: The OAuth client
            requested_scope: Space-separated string of requested scopes

        Returns:
            Space-separated string of granted scopes, or None if no scopes

        Raises:
            HTTPException: If requested scopes are invalid
        """
        if not requested_scope:
            # No specific scopes requested, use client's default scopes if any
            return client.scope if client.scope else None

        requested_scopes = set(requested_scope.split())
        original_requested = requested_scopes.copy()

        # Get all valid scopes from repository
        all_scopes = await self.scope_repo.list_scopes()
        valid_scope_names = {scope.scope_name for scope in all_scopes if scope.is_active}

        # Check if any requested scopes are invalid
        requested_scopes - valid_scope_names

        # Filter to valid scopes that exist in the system
        requested_scopes = requested_scopes & valid_scope_names

        # Get client's allowed scopes from oauth_client_scopes table
        client_scopes = await self.scope_repo.get_scopes_for_client(client.id)

        if client_scopes:
            # If client has specific allowed scopes, filter to those
            allowed_scope_names = {scope.scope_name for scope in client_scopes}
            granted_scopes = requested_scopes & allowed_scope_names
        else:
            # If no specific scopes are configured for client, check against client's default scopes
            if client.scope:
                allowed_scope_names = set(client.scope.split())
                granted_scopes = requested_scopes & allowed_scope_names
            else:
                # No allowed scopes configured - reject all
                granted_scopes = set()

        # If no valid scopes remain after filtering, return error
        if original_requested and not granted_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_scope",
                    "error_description": "The requested scope is invalid, unknown, or malformed",
                },
            )

        return " ".join(granted_scopes) if granted_scopes else None

    async def _create_client_access_token(
        self,
        client_id: str,
        client_uuid: UUID,
        scope: str | None = None,
    ) -> str:
        """
        Create an access token for a client (no user context).

        Args:
            client_id: The client identifier string
            client_uuid: The client's UUID from database
            scope: Optional granted scopes

        Returns:
            JWT access token string
        """
        import secrets

        # Generate unique JTI
        access_jti = secrets.token_hex(self.config.token_hex_length)

        # Prepare token data (no user subject for client credentials)
        access_data = {
            "client_id": client_id,
            "jti": access_jti,
            "token_use": "access",
        }

        # Add scope if provided
        if scope:
            access_data["scope"] = scope

        # Create JWT token
        access_token = create_access_token(
            data=access_data,
            secret_key=self.config.secret_key,
            algorithm=self.config.algorithm,
            expires_delta=self.config.access_token_expire_minutes,
            config=self.config,
        )

        # Decode to get expiry time
        access_payload = jwt.decode(access_token, self.config.secret_key, algorithms=[self.config.algorithm])

        # Store the token in the database (user_id is NULL for client credentials)
        token_model = TokenModel(
            id=uuid4(),
            user_id=None,  # No user for client credentials
            client_id=client_uuid,
            token_jti=access_jti,
            token_type=TokenType.ACCESS,
            token_value=access_token,
            scope=scope,
            expires_at=datetime.fromtimestamp(access_payload["exp"], UTC),
            created_at=datetime.now(UTC),
            invalidated=False,
        )

        try:
            await self.token_repo.store_token(token_model)
            logger.info(f"Stored client credentials token for client {client_id}")
        except Exception as e:
            # Log error but don't fail - token is still valid even if storage fails
            logger.error(f"Failed to store client credentials token: {e}")

        return access_token


async def handle_client_credentials_grant(
    client_id: str,
    client_secret: str,
    scope: str | None,
    client_repo: ClientRepository,
    scope_repo: ScopeRepository,
    token_repo: TokenRepository,
    config: AuthlyConfig,
) -> dict:
    """
    Convenience function to handle client credentials grant.

    This function creates a handler and processes the grant request.

    Args:
        client_id: The client identifier
        client_secret: The client secret
        scope: Optional requested scopes
        client_repo: Client repository
        scope_repo: Scope repository
        token_repo: Token repository
        config: Authly configuration

    Returns:
        Token response dictionary
    """
    handler = ClientCredentialsGrantHandler(
        client_repo=client_repo,
        scope_repo=scope_repo,
        token_repo=token_repo,
        config=config,
    )

    return await handler.handle_client_credentials_grant(
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
    )
