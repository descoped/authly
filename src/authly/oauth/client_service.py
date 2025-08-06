"""OAuth 2.1 client service layer for business logic."""

import logging
import secrets
import time
from uuid import UUID

from fastapi import HTTPException, status

from authly.auth.core import get_password_hash, verify_password
from authly.config import AuthlyConfig
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    GrantType,
    OAuthClientCreateRequest,
    OAuthClientCredentialsResponse,
    OAuthClientModel,
    OAuthClientResponse,
    ResponseType,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)

# Import metrics for client operation tracking
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    logger.debug("Metrics collection not available in client service")
    METRICS_ENABLED = False
    metrics = None


class ClientService:
    """
    Service layer for OAuth 2.1 client management business logic.

    Handles client registration, authentication, secret management,
    and scope assignment following OAuth 2.1 security requirements.
    """

    def __init__(self, client_repo: ClientRepository, scope_repo: ScopeRepository, config: AuthlyConfig):
        self._client_repo = client_repo
        self._scope_repo = scope_repo
        self._config = config

    async def create_client(self, request: OAuthClientCreateRequest) -> OAuthClientCredentialsResponse:
        """
        Create a new OAuth 2.1 client with secure credential generation.

        Args:
            request: Client creation request with metadata

        Returns:
            OAuthClientCredentialsResponse: Client credentials (includes secret for confidential clients)

        Raises:
            HTTPException: If validation fails or client creation errors
        """
        start_time = time.time()

        try:
            # Generate unique client_id
            client_id = f"client_{secrets.token_urlsafe(16)}"

            # Ensure client_id is unique (rare collision check)
            while await self._client_repo.client_exists(client_id):
                client_id = f"client_{secrets.token_urlsafe(16)}"

            # Generate client secret for confidential clients
            client_secret = None
            client_secret_hash = None

            if request.client_type == ClientType.CONFIDENTIAL:
                try:
                    client_secret_length = self._config.client_secret_length
                except RuntimeError:
                    # Fallback for tests without full Authly initialization
                    client_secret_length = 32
                client_secret = secrets.token_urlsafe(client_secret_length)
                client_secret_hash = get_password_hash(client_secret)

            # Set default values based on client type
            grant_types = request.grant_types or [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN]
            response_types = request.response_types or [ResponseType.CODE]

            # Set token endpoint auth method based on client type
            if request.token_endpoint_auth_method is None:
                if request.client_type == ClientType.PUBLIC:
                    token_endpoint_auth_method = TokenEndpointAuthMethod.NONE
                else:
                    token_endpoint_auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
            else:
                token_endpoint_auth_method = request.token_endpoint_auth_method

            # Validate auth method matches client type
            if request.client_type == ClientType.PUBLIC and token_endpoint_auth_method != TokenEndpointAuthMethod.NONE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Public clients must use 'none' token endpoint auth method",
                )

            if (
                request.client_type == ClientType.CONFIDENTIAL
                and token_endpoint_auth_method == TokenEndpointAuthMethod.NONE
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Confidential clients cannot use 'none' token endpoint auth method",
                )

            # Validate redirect URIs
            self._validate_redirect_uris(request.redirect_uris, request.client_type)

            # Validate requested scopes exist
            if request.scope:
                await self._validate_scope_string(request.scope)

            # Validate OIDC specific fields
            self._validate_oidc_fields(request)

            # Set OIDC defaults
            id_token_signed_response_alg = request.id_token_signed_response_alg or "RS256"
            subject_type = request.subject_type or "public"
            application_type = request.application_type or "web"
            request_uris = request.request_uris or []
            contacts = request.contacts or []

            # Create client data
            client_data = {
                "client_id": client_id,
                "client_secret_hash": client_secret_hash,
                "client_name": request.client_name,
                "client_type": request.client_type,
                "redirect_uris": request.redirect_uris,
                "grant_types": grant_types,
                "response_types": response_types,
                "scope": request.scope,
                "require_pkce": request.require_pkce,
                "token_endpoint_auth_method": token_endpoint_auth_method,
                "client_uri": request.client_uri,
                "logo_uri": request.logo_uri,
                "tos_uri": request.tos_uri,
                "policy_uri": request.policy_uri,
                "software_id": request.software_id,
                "software_version": request.software_version,
                "is_active": True,
                # OpenID Connect specific fields
                "id_token_signed_response_alg": id_token_signed_response_alg,
                "subject_type": subject_type,
                "sector_identifier_uri": request.sector_identifier_uri,
                "require_auth_time": request.require_auth_time,
                "default_max_age": request.default_max_age,
                "initiate_login_uri": request.initiate_login_uri,
                "request_uris": request_uris,
                "application_type": application_type,
                "contacts": contacts,
            }

            # Create client in database
            created_client = await self._client_repo.create_client(client_data)

            # Associate scopes if specified
            if request.scope:
                await self._assign_scopes_to_client(created_client.id, request.scope)

            logger.info(f"Created OAuth client: {client_id} ({request.client_type.value})")

            # Track successful client creation
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_client_operation(
                    operation="create_client",
                    status="success",
                    client_type=request.client_type.value,
                    duration=duration,
                )

            return OAuthClientCredentialsResponse(
                client_id=client_id,
                client_secret=client_secret,  # Only returned once during creation
                client_type=request.client_type,
                client_name=request.client_name,
            )

        except HTTPException:
            # Track validation errors
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_client_operation(
                    operation="create_client",
                    status="validation_error",
                    client_type=request.client_type.value,
                    duration=duration,
                )
            raise
        except Exception as e:
            # Track general creation errors
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_client_operation(
                    operation="create_client",
                    status="error",
                    client_type=getattr(request, "client_type", "unknown").value
                    if hasattr(getattr(request, "client_type", None), "value")
                    else "unknown",
                    duration=duration,
                )

            logger.error(f"Error creating OAuth client: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create OAuth client"
            ) from None

    async def authenticate_client(
        self,
        client_id: str,
        client_secret: str | None = None,
        auth_method: TokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
    ) -> OAuthClientModel | None:
        """
        Authenticate OAuth client credentials.

        Args:
            client_id: The client identifier
            client_secret: The client secret (None for public clients)
            auth_method: Authentication method used

        Returns:
            OAuthClientModel if authenticated, None if authentication fails
        """
        start_time = time.time()

        try:
            # Get client from database
            client = await self._client_repo.get_by_client_id(client_id)
            if not client or not client.is_active:
                logger.warning(f"Client authentication failed - client not found or inactive: {client_id}")

                # Track client not found or inactive
                if METRICS_ENABLED and metrics:
                    duration = time.time() - start_time
                    metrics.track_client_operation(
                        operation="authenticate_client",
                        status="client_not_found",
                        client_id=client_id,
                        auth_method=auth_method.value,
                        duration=duration,
                    )
                return None

            # Check if auth method matches client configuration
            if client.token_endpoint_auth_method != auth_method:
                logger.warning(
                    f"Auth method mismatch for client {client_id}: expected {client.token_endpoint_auth_method}, got {auth_method}"
                )

                # Track auth method mismatch
                if METRICS_ENABLED and metrics:
                    duration = time.time() - start_time
                    metrics.track_client_operation(
                        operation="authenticate_client",
                        status="auth_method_mismatch",
                        client_id=client_id,
                        client_type=client.client_type.value,
                        auth_method=auth_method.value,
                        duration=duration,
                    )
                return None

            # Handle public clients (no secret verification)
            if client.client_type == ClientType.PUBLIC:
                if client_secret is not None:
                    logger.warning(f"Public client {client_id} provided secret when none expected")

                    # Track public client providing secret
                    if METRICS_ENABLED and metrics:
                        duration = time.time() - start_time
                        metrics.track_client_operation(
                            operation="authenticate_client",
                            status="public_client_secret_provided",
                            client_id=client_id,
                            client_type=client.client_type.value,
                            auth_method=auth_method.value,
                            duration=duration,
                        )
                    return None

                if auth_method != TokenEndpointAuthMethod.NONE:
                    logger.warning(f"Public client {client_id} used invalid auth method: {auth_method}")

                    # Track public client invalid auth method
                    if METRICS_ENABLED and metrics:
                        duration = time.time() - start_time
                        metrics.track_client_operation(
                            operation="authenticate_client",
                            status="public_client_invalid_auth",
                            client_id=client_id,
                            client_type=client.client_type.value,
                            auth_method=auth_method.value,
                            duration=duration,
                        )
                    return None

                # Track successful public client authentication
                if METRICS_ENABLED and metrics:
                    duration = time.time() - start_time
                    metrics.track_client_operation(
                        operation="authenticate_client",
                        status="success",
                        client_id=client_id,
                        client_type=client.client_type.value,
                        auth_method=auth_method.value,
                        duration=duration,
                    )
                return client

            # Handle confidential clients (secret verification required)
            if client.client_type == ClientType.CONFIDENTIAL:
                if client_secret is None:
                    logger.warning(f"Confidential client {client_id} missing required secret")

                    # Track missing secret for confidential client
                    if METRICS_ENABLED and metrics:
                        duration = time.time() - start_time
                        metrics.track_client_operation(
                            operation="authenticate_client",
                            status="confidential_client_missing_secret",
                            client_id=client_id,
                            client_type=client.client_type.value,
                            auth_method=auth_method.value,
                            duration=duration,
                        )
                    return None

                if not client.client_secret_hash:
                    logger.error(f"Confidential client {client_id} has no stored secret hash")

                    # Track missing secret hash
                    if METRICS_ENABLED and metrics:
                        duration = time.time() - start_time
                        metrics.track_client_operation(
                            operation="authenticate_client",
                            status="confidential_client_no_hash",
                            client_id=client_id,
                            client_type=client.client_type.value,
                            auth_method=auth_method.value,
                            duration=duration,
                        )
                    return None

                # Verify client secret
                if not verify_password(client_secret, client.client_secret_hash):
                    logger.warning(f"Invalid client secret for confidential client: {client_id}")

                    # Track invalid secret
                    if METRICS_ENABLED and metrics:
                        duration = time.time() - start_time
                        metrics.track_client_operation(
                            operation="authenticate_client",
                            status="invalid_secret",
                            client_id=client_id,
                            client_type=client.client_type.value,
                            auth_method=auth_method.value,
                            duration=duration,
                        )
                    return None

                # Track successful confidential client authentication
                if METRICS_ENABLED and metrics:
                    duration = time.time() - start_time
                    metrics.track_client_operation(
                        operation="authenticate_client",
                        status="success",
                        client_id=client_id,
                        client_type=client.client_type.value,
                        auth_method=auth_method.value,
                        duration=duration,
                    )
                return client

            logger.error(f"Unknown client type for client {client_id}: {client.client_type}")

            # Track unknown client type
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_client_operation(
                    operation="authenticate_client",
                    status="unknown_client_type",
                    client_id=client_id,
                    client_type=str(client.client_type),
                    auth_method=auth_method.value,
                    duration=duration,
                )
            return None

        except Exception as e:
            # Track authentication error
            if METRICS_ENABLED and metrics:
                duration = time.time() - start_time
                metrics.track_client_operation(
                    operation="authenticate_client",
                    status="error",
                    client_id=client_id,
                    auth_method=auth_method.value,
                    duration=duration,
                )

            logger.error(f"Error authenticating client {client_id}: {e}")
            return None

    async def get_client_by_id(self, client_id: str) -> OAuthClientResponse | None:
        """Get client information by client_id (without sensitive data)"""
        try:
            client = await self._client_repo.get_by_client_id(client_id)
            if not client or not client.is_active:
                return None

            return OAuthClientResponse(
                id=client.id,
                client_id=client.client_id,
                client_name=client.client_name,
                client_type=client.client_type,
                redirect_uris=client.redirect_uris,
                grant_types=client.grant_types,
                response_types=client.response_types,
                scope=client.scope,
                created_at=client.created_at,
                updated_at=client.updated_at,
                is_active=client.is_active,
                require_pkce=client.require_pkce,
                token_endpoint_auth_method=client.token_endpoint_auth_method,
                client_uri=client.client_uri,
                logo_uri=client.logo_uri,
                tos_uri=client.tos_uri,
                policy_uri=client.policy_uri,
                software_id=client.software_id,
                software_version=client.software_version,
            )

        except Exception as e:
            logger.error(f"Error getting client {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve client"
            ) from None

    async def update_client(
        self, client_id: str, update_data: dict, requesting_admin: bool = False
    ) -> OAuthClientResponse:
        """
        Update client information.

        Args:
            client_id: Client identifier
            update_data: Fields to update
            requesting_admin: Whether request is from admin (allows sensitive updates)

        Returns:
            Updated client information
        """
        try:
            # Get existing client
            existing_client = await self._client_repo.get_by_client_id(client_id)
            if not existing_client:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

            # Filter allowed updates based on permissions
            allowed_fields = {
                "client_name",
                "redirect_uris",
                "client_uri",
                "logo_uri",
                "tos_uri",
                "policy_uri",
                "software_version",
            }

            if requesting_admin:
                allowed_fields.update(
                    {
                        "grant_types",
                        "response_types",
                        "scope",
                        "require_pkce",
                        "token_endpoint_auth_method",
                        "is_active",
                    }
                )

            # Filter update data to only allowed fields
            filtered_data = {k: v for k, v in update_data.items() if k in allowed_fields}

            if not filtered_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields to update")

            # Validate redirect URIs if being updated
            if "redirect_uris" in filtered_data:
                self._validate_redirect_uris(filtered_data["redirect_uris"], existing_client.client_type)

            # Validate scopes if being updated
            if filtered_data.get("scope"):
                await self._validate_scope_string(filtered_data["scope"])

            # Update client
            updated_client = await self._client_repo.update_client(existing_client.id, filtered_data)

            # Update scope associations if scope changed
            if "scope" in filtered_data:
                await self._assign_scopes_to_client(updated_client.id, filtered_data["scope"])

            logger.info(f"Updated OAuth client: {client_id}")

            return OAuthClientResponse(
                id=updated_client.id,
                client_id=updated_client.client_id,
                client_name=updated_client.client_name,
                client_type=updated_client.client_type,
                redirect_uris=updated_client.redirect_uris,
                grant_types=updated_client.grant_types,
                response_types=updated_client.response_types,
                scope=updated_client.scope,
                created_at=updated_client.created_at,
                updated_at=updated_client.updated_at,
                is_active=updated_client.is_active,
                require_pkce=updated_client.require_pkce,
                token_endpoint_auth_method=updated_client.token_endpoint_auth_method,
                client_uri=updated_client.client_uri,
                logo_uri=updated_client.logo_uri,
                tos_uri=updated_client.tos_uri,
                policy_uri=updated_client.policy_uri,
                software_id=updated_client.software_id,
                software_version=updated_client.software_version,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating client {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update client"
            ) from None

    async def deactivate_client(self, client_id: str) -> bool:
        """Deactivate (soft delete) an OAuth client"""
        try:
            existing_client = await self._client_repo.get_by_client_id(client_id)
            if not existing_client:
                return False

            success = await self._client_repo.delete_client(existing_client.id)
            if success:
                logger.info(f"Deactivated OAuth client: {client_id}")

            return success

        except Exception as e:
            logger.error(f"Error deactivating client {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to deactivate client"
            ) from None

    async def list_clients(self, limit: int = 100, offset: int = 0) -> list[OAuthClientResponse]:
        """List active OAuth clients with pagination"""
        try:
            clients = await self._client_repo.get_active_clients(limit=limit, offset=offset)

            return [
                OAuthClientResponse(
                    id=client.id,
                    client_id=client.client_id,
                    client_name=client.client_name,
                    client_type=client.client_type,
                    redirect_uris=client.redirect_uris,
                    grant_types=client.grant_types,
                    response_types=client.response_types,
                    scope=client.scope,
                    created_at=client.created_at,
                    updated_at=client.updated_at,
                    is_active=client.is_active,
                    require_pkce=client.require_pkce,
                    token_endpoint_auth_method=client.token_endpoint_auth_method,
                    client_uri=client.client_uri,
                    logo_uri=client.logo_uri,
                    tos_uri=client.tos_uri,
                    policy_uri=client.policy_uri,
                    software_id=client.software_id,
                    software_version=client.software_version,
                )
                for client in clients
            ]

        except Exception as e:
            logger.error(f"Error listing clients: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list clients"
            ) from None

    async def get_client_scopes(self, client_id: str) -> list[str]:
        """Get all scope names associated with a client"""
        try:
            client = await self._client_repo.get_by_client_id(client_id)
            if not client:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

            return await self._client_repo.get_client_scopes(client.id)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting client scopes for {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get client scopes"
            ) from None

    def _validate_redirect_uris(self, redirect_uris: list[str], client_type: ClientType) -> None:
        """Validate redirect URIs according to OAuth 2.1 security requirements"""
        if not redirect_uris:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one redirect URI is required")

        for uri in redirect_uris:
            # Basic URI validation
            try:
                redirect_uri_max_length = self._config.redirect_uri_max_length
            except RuntimeError:
                # Fallback for tests
                redirect_uri_max_length = 2000

            if not uri or len(uri) > redirect_uri_max_length:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid redirect URI: {uri}")

            # Basic scheme validation for all clients
            if "://" not in uri:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid redirect URI - missing scheme: {uri}",
                )

            # OAuth 2.1 security requirements
            if client_type == ClientType.PUBLIC:
                # Public clients can use:
                # 1. HTTPS for web applications
                # 2. Localhost for development/testing
                # 3. Custom schemes for mobile applications (RFC 8252)
                is_https = uri.startswith("https://")
                is_localhost = uri.startswith("http://localhost") or uri.startswith("http://127.0.0.1")
                is_custom_scheme = "://" in uri and not uri.startswith("http://") and not uri.startswith("https://")

                if not (is_https or is_localhost or is_custom_scheme):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Public clients must use HTTPS, localhost, or custom schemes: {uri}",
                    )

            # Prevent loopback abuse
            if "localhost" in uri.lower() and client_type == ClientType.CONFIDENTIAL:
                logger.warning(f"Confidential client using localhost redirect: {uri}")

    async def _validate_scope_string(self, scope_string: str) -> None:
        """Validate that all scopes in space-separated string exist"""
        if not scope_string.strip():
            return

        scope_names = scope_string.split()
        valid_scopes = await self._scope_repo.validate_scope_names(scope_names)

        invalid_scopes = set(scope_names) - valid_scopes
        if invalid_scopes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid scopes: {', '.join(invalid_scopes)}"
            )

    def _validate_oidc_fields(self, request: OAuthClientCreateRequest) -> None:
        """Validate OpenID Connect specific client fields"""

        # Check if this is an OIDC client (has openid scope)
        is_oidc_client = False
        if request.scope:
            scopes = request.scope.split()
            is_oidc_client = "openid" in scopes

        # Validate sector_identifier_uri for pairwise subject type
        if request.subject_type == "pairwise" and not request.sector_identifier_uri and is_oidc_client:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="sector_identifier_uri is required for pairwise subject type",
            )

        # Validate default_max_age
        if request.default_max_age is not None and request.default_max_age < 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="default_max_age must be non-negative")

        # Validate request_uris (if provided)
        if request.request_uris:
            for uri in request.request_uris:
                if not uri.startswith("https://"):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"request_uris must use HTTPS: {uri}"
                    )

        # Validate contacts (basic email format check)
        if request.contacts:
            for contact in request.contacts:
                if "@" not in contact or "." not in contact:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid contact email format: {contact}"
                    )

        # Validate application_type
        if request.application_type and request.application_type not in ["web", "native"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="application_type must be 'web' or 'native'"
            )

    async def _assign_scopes_to_client(self, client_id: UUID, scope_string: str | None) -> None:
        """Assign scopes to a client by creating client-scope associations"""
        if not scope_string:
            return

        scope_names = scope_string.split()
        if not scope_names:
            return

        # Get scope models
        scopes = await self._scope_repo.get_by_scope_names(scope_names)
        scope_ids = [scope.id for scope in scopes]

        # Create associations
        for scope_id in scope_ids:
            await self._client_repo.add_client_scope(client_id, scope_id)

    async def regenerate_client_secret(self, client_id: str) -> str | None:
        """
        Regenerate client secret for confidential clients.

        Returns:
            New client secret if successful, None if client is public or not found
        """
        try:
            client = await self._client_repo.get_by_client_id(client_id)
            if not client or not client.is_active:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

            if client.client_type != ClientType.CONFIDENTIAL:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Only confidential clients can have secrets regenerated",
                )

            # Generate new secret
            new_secret = secrets.token_urlsafe(32)
            new_secret_hash = get_password_hash(new_secret)

            # Update in database
            await self._client_repo.update_client(client.id, {"client_secret_hash": new_secret_hash})

            logger.info(f"Regenerated client secret for: {client_id}")
            return new_secret

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error regenerating client secret for {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to regenerate client secret"
            ) from None
