"""
OpenID Connect Discovery Service and Models.

This module provides OIDC discovery endpoint implementation according to
OpenID Connect Discovery 1.0 specification.

The OIDC discovery endpoint (.well-known/openid_configuration) extends
OAuth 2.1 server metadata with OpenID Connect specific capabilities.
"""

import logging
from urllib.parse import urljoin

from pydantic import BaseModel, Field

from authly.oauth.discovery_service import DiscoveryService
from authly.oidc.scopes import OIDC_SCOPES

logger = logging.getLogger(__name__)


class OIDCServerMetadata(BaseModel):
    """
    OpenID Connect Discovery metadata response.

    This extends OAuth 2.1 server metadata with OIDC-specific fields
    according to OpenID Connect Discovery 1.0 specification.

    Based on:
    - OpenID Connect Discovery 1.0
    - RFC 8414 (OAuth 2.0 Authorization Server Metadata)
    """

    # Inherit all OAuth 2.1 metadata fields
    issuer: str = Field(..., description="URL using the https scheme that identifies the authorization server")
    authorization_endpoint: str = Field(..., description="URL of the authorization server's authorization endpoint")
    token_endpoint: str = Field(..., description="URL of the authorization server's token endpoint")
    revocation_endpoint: str | None = Field(None, description="URL of the authorization server's revocation endpoint")

    # OAuth 2.1 specific requirements
    response_types_supported: list[str] = Field(
        default=["code"], description="List of OAuth 2.0 response types that this server supports"
    )
    grant_types_supported: list[str] = Field(
        default=["authorization_code", "refresh_token"],
        description="List of OAuth 2.0 grant types that this server supports",
    )
    code_challenge_methods_supported: list[str] = Field(
        default=["S256"], description="List of PKCE code challenge methods supported"
    )
    token_endpoint_auth_methods_supported: list[str] = Field(
        default=["client_secret_basic", "client_secret_post", "none"],
        description="List of client authentication methods supported at the token endpoint",
    )
    scopes_supported: list[str] = Field(
        default_factory=list, description="List of OAuth 2.0 scopes that this server supports"
    )

    # OIDC-specific metadata fields
    userinfo_endpoint: str = Field(..., description="URL of the OP's UserInfo endpoint")
    end_session_endpoint: str | None = Field(
        None,
        description="URL at the OP to which a Relying Party can perform a redirect to request that the End-User be logged out",
    )
    check_session_iframe: str | None = Field(
        None, description="URL of an OP iframe that supports cross-origin communications for session state information"
    )
    frontchannel_logout_supported: bool = Field(default=True, description="Whether the OP supports HTTP-based logout")
    frontchannel_logout_session_supported: bool = Field(
        default=True, description="Whether the OP can pass iss and sid query parameters to identify the RP session"
    )
    jwks_uri: str | None = Field(None, description="URL of the OP's JSON Web Key Set document")

    # OIDC response types (extends OAuth 2.1)
    id_token_signing_alg_values_supported: list[str] = Field(
        default=["RS256"], description="List of JWS signing algorithms supported for ID tokens"
    )

    # OIDC subject types
    subject_types_supported: list[str] = Field(
        default=["public"], description="List of subject identifier types supported"
    )

    # OIDC claims
    claims_supported: list[str] = Field(
        default_factory=list, description="List of claim names supported by the UserInfo endpoint"
    )

    # OIDC features
    claims_parameter_supported: bool = Field(default=False, description="Whether the claims parameter is supported")
    request_parameter_supported: bool = Field(default=False, description="Whether the request parameter is supported")
    request_uri_parameter_supported: bool = Field(
        default=False, description="Whether the request_uri parameter is supported"
    )
    require_request_uri_registration: bool = Field(
        default=False, description="Whether request_uri values used must be pre-registered"
    )

    # OIDC UI locales
    ui_locales_supported: list[str] = Field(default=["en"], description="List of UI locales supported")

    # OIDC additional requirements
    require_pkce: bool = Field(
        default=True, description="Whether PKCE is required for all clients (OAuth 2.1 requirement)"
    )
    response_modes_supported: list[str] = Field(
        default=["query", "fragment"], description="List of response modes supported"
    )


class OIDCDiscoveryService:
    """
    OpenID Connect Discovery Service.

    Generates OIDC server metadata extending OAuth 2.1 capabilities
    according to OpenID Connect Discovery 1.0 specification.
    """

    def __init__(self, oauth_discovery_service: DiscoveryService):
        """
        Initialize the OIDC discovery service.

        Args:
            oauth_discovery_service: OAuth 2.1 discovery service to extend
        """
        self._oauth_discovery = oauth_discovery_service

    async def get_oidc_server_metadata(self, issuer_url: str, api_prefix: str = "/api/v1") -> OIDCServerMetadata:
        """
        Generate OpenID Connect server metadata.

        Args:
            issuer_url: The base URL of the authorization server (e.g., https://auth.example.com)
            api_prefix: API version prefix (e.g., /api/v1)

        Returns:
            OIDCServerMetadata: Complete OIDC server metadata response
        """
        # Get base OAuth 2.1 metadata
        oauth_metadata = await self._oauth_discovery.get_server_metadata(issuer_url, api_prefix)

        # Build OIDC-specific endpoints
        base_url = issuer_url.rstrip("/")

        # Get OIDC scopes and claims
        oidc_scope_names = list(OIDC_SCOPES.keys())

        # Extract all claims from OIDC scopes
        all_claims = set()
        for scope_def in OIDC_SCOPES.values():
            all_claims.update(scope_def.claims)

        # Combine OAuth and OIDC scopes
        combined_scopes = oauth_metadata.scopes_supported + oidc_scope_names

        # Use only OAuth 2.1 response modes (no fragment mode needed for authorization code flow)
        combined_response_modes = oauth_metadata.response_modes_supported

        # Create OIDC metadata response
        oidc_metadata = OIDCServerMetadata(
            # OAuth 2.1 fields (from base metadata)
            issuer=oauth_metadata.issuer,
            authorization_endpoint=oauth_metadata.authorization_endpoint,
            token_endpoint=oauth_metadata.token_endpoint,
            revocation_endpoint=oauth_metadata.revocation_endpoint,
            response_types_supported=oauth_metadata.response_types_supported,  # Only advertise supported flows
            grant_types_supported=oauth_metadata.grant_types_supported,
            code_challenge_methods_supported=oauth_metadata.code_challenge_methods_supported,
            token_endpoint_auth_methods_supported=oauth_metadata.token_endpoint_auth_methods_supported,
            scopes_supported=combined_scopes,
            require_pkce=oauth_metadata.require_pkce,
            response_modes_supported=combined_response_modes,
            # OIDC-specific fields
            userinfo_endpoint=urljoin(base_url, "/oidc/userinfo"),
            end_session_endpoint=urljoin(base_url, f"{api_prefix}/oidc/logout"),
            check_session_iframe=urljoin(base_url, f"{api_prefix}/oidc/session/iframe"),
            frontchannel_logout_supported=True,
            frontchannel_logout_session_supported=True,
            jwks_uri=urljoin(base_url, "/.well-known/jwks.json"),
            id_token_signing_alg_values_supported=["RS256", "HS256"],
            subject_types_supported=["public"],
            claims_supported=sorted(all_claims),
            claims_parameter_supported=False,
            request_parameter_supported=False,
            request_uri_parameter_supported=False,
            require_request_uri_registration=False,
            ui_locales_supported=["en"],
        )

        logger.info(f"Generated OIDC discovery metadata for issuer: {issuer_url}")
        return oidc_metadata

    def get_static_oidc_metadata(self, issuer_url: str = "https://localhost:8000") -> OIDCServerMetadata:
        """
        Get static OIDC metadata for fallback scenarios.

        Args:
            issuer_url: The base URL of the authorization server

        Returns:
            OIDCServerMetadata: Static OIDC server metadata
        """
        base_url = issuer_url.rstrip("/")
        api_prefix = "/api/v1"

        # Static OIDC scopes and claims
        static_scopes = ["openid", "profile", "email", "address", "phone", "read", "write", "admin"]
        static_claims = [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
            "email",
            "email_verified",
            "address",
            "phone_number",
            "phone_number_verified",
        ]

        return OIDCServerMetadata(
            issuer=base_url,
            authorization_endpoint=urljoin(base_url, f"{api_prefix}/oauth/authorize"),
            token_endpoint=urljoin(base_url, f"{api_prefix}/oauth/token"),
            revocation_endpoint=urljoin(base_url, f"{api_prefix}/oauth/revoke"),
            userinfo_endpoint=urljoin(base_url, "/oidc/userinfo"),
            end_session_endpoint=urljoin(base_url, f"{api_prefix}/oidc/logout"),
            check_session_iframe=urljoin(base_url, f"{api_prefix}/oidc/session/iframe"),
            frontchannel_logout_supported=True,
            frontchannel_logout_session_supported=True,
            jwks_uri=urljoin(base_url, "/.well-known/jwks.json"),
            response_types_supported=["code"],  # Only advertise supported flows
            grant_types_supported=["authorization_code", "refresh_token"],
            code_challenge_methods_supported=["S256"],
            token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "none"],
            scopes_supported=static_scopes,
            id_token_signing_alg_values_supported=["RS256", "HS256"],
            subject_types_supported=["public"],
            claims_supported=static_claims,
            claims_parameter_supported=False,
            request_parameter_supported=False,
            request_uri_parameter_supported=False,
            require_request_uri_registration=False,
            ui_locales_supported=["en"],
            require_pkce=True,
            response_modes_supported=["query"],  # Only advertise supported response modes
        )


async def get_oidc_discovery_service(oauth_discovery_service: DiscoveryService) -> OIDCDiscoveryService:
    """
    Factory function to create OIDC discovery service.

    Args:
        oauth_discovery_service: OAuth 2.1 discovery service dependency

    Returns:
        OIDCDiscoveryService: Configured OIDC discovery service
    """
    return OIDCDiscoveryService(oauth_discovery_service)
