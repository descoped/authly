"""OAuth 2.1 Authorization Server Discovery Service.

Provides server metadata and capabilities information
according to RFC 8414 and OAuth 2.1 specifications.
"""

import logging
from urllib.parse import urljoin

from authly.oauth.discovery_models import OAuthServerMetadata
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)


class DiscoveryService:
    """
    Service for OAuth 2.1 Authorization Server Discovery.

    Generates server metadata including endpoints, supported features,
    and capabilities according to RFC 8414 and OAuth 2.1 requirements.
    """

    def __init__(self, scope_repo: ScopeRepository | None = None):
        """
        Initialize the discovery service.

        Args:
            scope_repo: Optional scope repository for dynamic scope discovery
        """
        self._scope_repo = scope_repo

    async def get_server_metadata(self, issuer_url: str, api_prefix: str = "/api/v1") -> OAuthServerMetadata:
        """
        Generate OAuth 2.1 server metadata.

        Args:
            issuer_url: The base URL of the authorization server (e.g., https://auth.example.com)
            api_prefix: API version prefix (e.g., /api/v1)

        Returns:
            OAuthServerMetadata: Complete server metadata response
        """
        # Ensure issuer URL doesn't end with slash for consistent URL building
        base_url = issuer_url.rstrip("/")

        # Build endpoint URLs
        authorization_endpoint = urljoin(f"{base_url}{api_prefix}/", "oauth/authorize")
        token_endpoint = urljoin(f"{base_url}{api_prefix}/", "oauth/token")
        revocation_endpoint = urljoin(f"{base_url}{api_prefix}/", "oauth/revoke")

        # Get supported scopes from database if repository is available
        scopes_supported = None
        if self._scope_repo:
            try:
                active_scopes = await self._scope_repo.get_active_scopes(limit=100)
                scopes_supported = [scope.scope_name for scope in active_scopes]
                logger.debug(f"Retrieved {len(scopes_supported)} active scopes for discovery")
            except Exception as e:
                logger.warning(f"Failed to retrieve scopes for discovery: {e}")
                # Continue with None - scopes_supported is optional

        metadata = OAuthServerMetadata(
            issuer=base_url,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            revocation_endpoint=revocation_endpoint,
            # OAuth 2.1 specific settings
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            code_challenge_methods_supported=["S256"],  # OAuth 2.1 requires PKCE with S256
            require_pkce=True,  # OAuth 2.1 requirement
            # Authentication methods supported
            token_endpoint_auth_methods_supported=[
                "client_secret_basic",  # HTTP Basic Auth (preferred)
                "client_secret_post",  # Form parameters
                "none",  # Public clients
            ],
            # Response modes
            response_modes_supported=["query"],  # Standard query parameter response
            # Dynamic scopes from database
            scopes_supported=scopes_supported,
            # UI and documentation
            ui_locales_supported=["en"],
            service_documentation=f"{base_url}/docs" if base_url else None,
        )

        logger.info(f"Generated OAuth 2.1 server metadata for issuer: {base_url}")
        return metadata

    def get_static_metadata(
        self, issuer_url: str, api_prefix: str = "/api/v1", scopes: list[str] | None = None
    ) -> OAuthServerMetadata:
        """
        Generate static server metadata without database access.

        Useful for testing or when database access is not available.

        Args:
            issuer_url: The base URL of the authorization server
            api_prefix: API version prefix
            scopes: Optional list of supported scopes

        Returns:
            OAuthServerMetadata: Server metadata with static configuration
        """
        base_url = issuer_url.rstrip("/")

        return OAuthServerMetadata(
            issuer=base_url,
            authorization_endpoint=urljoin(f"{base_url}{api_prefix}/", "oauth/authorize"),
            token_endpoint=urljoin(f"{base_url}{api_prefix}/", "oauth/token"),
            revocation_endpoint=urljoin(f"{base_url}{api_prefix}/", "oauth/revoke"),
            # OAuth 2.1 defaults
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            code_challenge_methods_supported=["S256"],
            require_pkce=True,
            token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "none"],
            response_modes_supported=["query"],
            scopes_supported=scopes,
            ui_locales_supported=["en"],
            service_documentation=f"{base_url}/docs" if base_url else None,
        )
