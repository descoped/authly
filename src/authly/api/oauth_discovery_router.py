"""OAuth 2.1 Discovery Router.

Provides OAuth 2.1 discovery endpoints at the root level for RFC 8414 compliance.
These endpoints must be accessible without API versioning prefixes.
"""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from authly.api.oauth_router import get_discovery_service
from authly.core.dependencies import get_config
from authly.oauth.discovery_models import OAuthServerMetadata
from authly.oauth.discovery_service import DiscoveryService

logger = logging.getLogger(__name__)

# Create OAuth discovery router (no prefix for RFC 8414 compliance)
oauth_discovery_router = APIRouter(tags=["OAuth 2.1 Discovery"])


def _build_issuer_url(request: Request) -> str:
    """
    Build the issuer URL from the request.

    Args:
        request: FastAPI request object

    Returns:
        str: Complete issuer URL (e.g., https://auth.example.com)
    """
    # Use X-Forwarded-Proto and X-Forwarded-Host headers if available (for reverse proxy setups)
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)

    # Get host, handling the case where it might include port
    host_header = request.headers.get("x-forwarded-host", request.headers.get("host"))

    if host_header:
        # Host header might include port (e.g., "localhost:8000")
        # Parse it to separate hostname and port
        if ":" in host_header:
            host, header_port = host_header.split(":", 1)
            try:
                port_num = int(header_port)
            except ValueError:
                # If port in header is invalid, fall back to request URL
                host = request.url.hostname or "localhost"
                port_num = request.url.port
        else:
            host = host_header
            port_num = request.url.port
    else:
        # Fallback to request URL
        host = request.url.hostname or "localhost"
        port_num = request.url.port

    # Add port only if it's not standard (80 for HTTP, 443 for HTTPS)
    if port_num and not ((scheme == "https" and port_num == 443) or (scheme == "http" and port_num == 80)):
        return f"{scheme}://{host}:{port_num}"
    else:
        return f"{scheme}://{host}"


@oauth_discovery_router.get(
    "/.well-known/oauth-authorization-server",
    response_model=OAuthServerMetadata,
    summary="OAuth 2.1 Authorization Server Discovery",
    description="""
    OAuth 2.1 Authorization Server Metadata endpoint as defined in RFC 8414.

    Returns server capabilities, supported features, and endpoint URLs.
    This endpoint provides essential information for OAuth 2.1 clients to
    discover server capabilities and construct proper authorization requests.

    **Key Features:**
    - OAuth 2.1 compliant metadata
    - PKCE requirement indication (mandatory in OAuth 2.1)
    - Supported grant types and response types
    - Client authentication methods
    - Dynamic scope discovery from database

    **Security:**
    - No authentication required (public endpoint)
    - Rate limiting applied through server configuration

    **RFC 8414 Compliance:**
    - Endpoint accessible at root level without API prefix
    - Standard .well-known path for OAuth server metadata discovery
    """,
    responses={
        200: {
            "description": "OAuth 2.1 server metadata",
            "content": {
                "application/json": {
                    "example": {
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
                        "token_endpoint": "https://auth.example.com/api/v1/oauth/token",
                        "revocation_endpoint": "https://auth.example.com/api/v1/oauth/revoke",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
                        "require_pkce": True,
                        "response_modes_supported": ["query"],
                        "scopes_supported": ["read", "write", "admin"],
                        "ui_locales_supported": ["en"],
                    }
                }
            },
        },
        500: {"description": "Internal server error"},
    },
)
async def oauth_discovery(
    request: Request, discovery_service: DiscoveryService = Depends(get_discovery_service)
) -> OAuthServerMetadata:
    """
    OAuth 2.1 Authorization Server Discovery endpoint.

    Returns metadata about the authorization server's capabilities and endpoints
    according to RFC 8414 and OAuth 2.1 specifications.

    This endpoint is publicly accessible and provides essential information
    for OAuth 2.1 clients to discover server capabilities.

    RFC 8414 Compliance:
    - Accessible at /.well-known/oauth-authorization-server (root level)
    - No API versioning prefix applied to this discovery endpoint
    - Metadata includes properly versioned business endpoint URLs
    """
    try:
        # Get configuration, with fallback
        try:
            config = get_config()
            api_prefix = config.fastapi_api_version_prefix
        except Exception:
            # Fallback for testing or when Authly not initialized
            api_prefix = "/api/v1"

        # Build issuer URL from request
        issuer_url = _build_issuer_url(request)

        # Generate server metadata
        metadata = await discovery_service.get_server_metadata(issuer_url=issuer_url, api_prefix=api_prefix)

        logger.info(f"OAuth discovery request from {request.client.host if request.client else 'unknown'}")

        return metadata

    except Exception as e:
        logger.error(f"Error generating OAuth discovery metadata: {e}")
        # Return a minimal static response on error
        try:
            issuer_url = _build_issuer_url(request)

            static_metadata = DiscoveryService().get_static_metadata(
                issuer_url=issuer_url,
                api_prefix="/api/v1",  # Fallback API prefix
                scopes=["read", "write"],  # Fallback scopes
            )

            logger.warning("Returned static OAuth discovery metadata due to error")
            return static_metadata

        except Exception as fallback_error:
            logger.error(f"Failed to generate fallback discovery metadata: {fallback_error}")
            # This should rarely happen, but we need to handle it gracefully
            return JSONResponse(
                status_code=500,
                content={"error": "internal_server_error", "error_description": "Unable to generate server metadata"},
            )
