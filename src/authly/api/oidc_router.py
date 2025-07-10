"""
OpenID Connect (OIDC) API Router.

Provides OpenID Connect 1.0 endpoints including discovery, UserInfo, and JWKS.
"""

import logging
from typing import List

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import status

from authly.api.oauth_router import get_discovery_service
from authly.api.users_dependencies import get_current_user
from authly.api.users_dependencies import get_token_scopes
from authly.api.users_dependencies import get_userinfo_service
from authly.oauth.discovery_service import DiscoveryService
from authly.oidc.discovery import OIDCDiscoveryService
from authly.oidc.discovery import OIDCServerMetadata
from authly.oidc.userinfo import UserInfoResponse
from authly.oidc.userinfo import UserInfoService
from authly.users.models import UserModel


logger = logging.getLogger(__name__)

# Create OIDC router
oidc_router = APIRouter(tags=["OpenID Connect"])


def get_base_url(request: Request) -> str:
    """
    Extract base URL from request.

    Args:
        request: FastAPI request object

    Returns:
        Base URL as string
    """
    # Handle both direct access and reverse proxy scenarios
    if request.headers.get("x-forwarded-proto"):
        scheme = request.headers.get("x-forwarded-proto", "https")
    else:
        scheme = request.url.scheme

    if request.headers.get("x-forwarded-host"):
        host = request.headers.get("x-forwarded-host")
    else:
        host = request.headers.get("host", request.url.netloc)

    return f"{scheme}://{host}"


@oidc_router.get(
    "/.well-known/openid_configuration",
    response_model=OIDCServerMetadata,
    summary="OpenID Connect Discovery",
    description="""
    OpenID Connect Discovery endpoint as defined in OpenID Connect Discovery 1.0.

    Returns server capabilities, supported features, and endpoint URLs for
    OpenID Connect clients. This endpoint extends OAuth 2.1 server metadata
    with OIDC-specific capabilities.

    **Key Features:**
    - Complete OpenID Connect 1.0 metadata
    - ID token signing algorithms and capabilities
    - UserInfo endpoint information
    - JWKS URI for key discovery
    - Claims and scopes supported
    - Response types and modes for OIDC flows

    **Security:**
    - No authentication required (public endpoint)
    - Rate limiting applied through server configuration
    """,
    responses={
        200: {
            "description": "OpenID Connect server metadata",
            "content": {
                "application/json": {
                    "example": {
                        "issuer": "https://auth.example.com",
                        "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
                        "token_endpoint": "https://auth.example.com/api/v1/auth/token",
                        "userinfo_endpoint": "https://auth.example.com/api/v1/oidc/userinfo",
                        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                        "response_types_supported": ["code", "id_token", "code id_token"],
                        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                        "subject_types_supported": ["public"],
                        "claims_supported": ["sub", "name", "email", "email_verified", "profile"],
                        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "code_challenge_methods_supported": ["S256"],
                        "require_pkce": True,
                    }
                }
            },
        },
        500: {"description": "Internal server error"},
    },
)
async def oidc_discovery(
    request: Request, oauth_discovery_service: DiscoveryService = Depends(get_discovery_service)
) -> OIDCServerMetadata:
    """
    OpenID Connect Discovery endpoint.

    Returns comprehensive OIDC server metadata including OAuth 2.1 capabilities
    extended with OpenID Connect specific features.

    Args:
        request: FastAPI request object for URL extraction
        oauth_discovery_service: OAuth 2.1 discovery service

    Returns:
        OIDCServerMetadata: Complete OIDC server metadata

    Raises:
        HTTPException: If metadata generation fails
    """
    try:
        # Extract base URL from request
        base_url = get_base_url(request)

        # Get API prefix from config (default to /api/v1)
        api_prefix = "/api/v1"

        # Create OIDC discovery service
        oidc_discovery_service = OIDCDiscoveryService(oauth_discovery_service)

        # Generate OIDC server metadata
        metadata = await oidc_discovery_service.get_oidc_server_metadata(issuer_url=base_url, api_prefix=api_prefix)

        logger.info(f"OIDC discovery request from {request.client.host if request.client else 'unknown'}")
        return metadata

    except Exception as e:
        logger.error(f"Error generating OIDC discovery metadata: {e}")

        # Fallback to static metadata to prevent service disruption
        try:
            base_url = get_base_url(request)
            oidc_discovery_service = OIDCDiscoveryService(oauth_discovery_service)
            static_metadata = oidc_discovery_service.get_static_oidc_metadata(base_url)

            logger.warning("Returned static OIDC discovery metadata due to error")
            return static_metadata

        except Exception as fallback_error:
            logger.error(f"Failed to generate fallback OIDC discovery metadata: {fallback_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to generate OIDC discovery metadata"
            )


@oidc_router.get(
    "/oidc/userinfo",
    response_model=UserInfoResponse,
    summary="OpenID Connect UserInfo Endpoint",
    description="""
    OpenID Connect UserInfo endpoint as defined in OIDC Core 1.0 Section 5.3.

    Returns user claims based on the access token and granted scopes.

    **Requirements:**
    - Valid access token with 'openid' scope
    - Token must be active and not revoked

    **Scopes and Claims:**
    - `openid`: Required scope, returns 'sub' claim
    - `profile`: Returns profile claims (name, given_name, family_name, etc.)
    - `email`: Returns email and email_verified claims
    - `phone`: Returns phone_number and phone_number_verified claims
    - `address`: Returns address claim

    **Security:**
    - Bearer token authentication required
    - Only returns claims for granted scopes
    - Respects user privacy through scope-based filtering
    """,
    responses={
        200: {
            "description": "User claims based on granted scopes",
            "content": {
                "application/json": {
                    "example": {
                        "sub": "123e4567-e89b-12d3-a456-426614174000",
                        "name": "John Doe",
                        "given_name": "John",
                        "family_name": "Doe",
                        "email": "john.doe@example.com",
                        "email_verified": True,
                        "preferred_username": "johndoe",
                        "updated_at": 1640995200,
                    }
                }
            },
        },
        401: {"description": "Invalid or expired access token"},
        403: {"description": "Insufficient scope (missing 'openid' scope)"},
        500: {"description": "Internal server error"},
    },
)
async def userinfo_endpoint(
    current_user: UserModel = Depends(get_current_user),
    token_scopes: List[str] = Depends(get_token_scopes),
    userinfo_service: UserInfoService = Depends(get_userinfo_service),
) -> UserInfoResponse:
    """
    OpenID Connect UserInfo endpoint.

    Returns user claims based on the access token and granted scopes.

    Args:
        current_user: Current authenticated user
        token_scopes: Scopes granted to the access token
        userinfo_service: Service for generating UserInfo response

    Returns:
        UserInfoResponse: User claims filtered by granted scopes

    Raises:
        HTTPException: If request is invalid or user access is denied
    """
    try:
        # Validate UserInfo request (requires 'openid' scope)
        if not userinfo_service.validate_userinfo_request(token_scopes):
            logger.warning(f"UserInfo request without 'openid' scope for user {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="UserInfo endpoint requires 'openid' scope",
                headers={"WWW-Authenticate": 'Bearer scope="openid"'},
            )

        # Generate UserInfo response
        userinfo_response = userinfo_service.create_userinfo_response(user=current_user, granted_scopes=token_scopes)

        logger.info(f"UserInfo response generated for user {current_user.id} with scopes {token_scopes}")
        return userinfo_response

    except HTTPException:
        # Re-raise HTTP exceptions without modification
        raise
    except Exception as e:
        logger.error(f"Error generating UserInfo response for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to generate UserInfo response"
        )


@oidc_router.get(
    "/.well-known/jwks.json",
    summary="JSON Web Key Set (JWKS)",
    description="""
    JSON Web Key Set endpoint as defined in RFC 7517.
    
    Returns public keys that clients can use to verify ID token signatures.
    This endpoint is essential for OpenID Connect ID token verification.
    
    **Key Features:**
    - RSA public keys in JWK format
    - Support for key rotation
    - Proper HTTP caching headers
    - No authentication required (public endpoint)
    
    **Usage:**
    - Clients fetch this endpoint to get verification keys
    - Keys are used to verify ID token signatures
    - Cache-Control headers optimize performance
    
    **Security:**
    - Only public keys are exposed
    - No authentication required as per OIDC specification
    - Supports key rotation for enhanced security
    """,
    responses={
        200: {
            "description": "JSON Web Key Set with public keys",
            "content": {
                "application/json": {
                    "example": {
                        "keys": [
                            {
                                "kty": "RSA",
                                "use": "sig",
                                "alg": "RS256",
                                "kid": "key_20250709123456",
                                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP1fOL...",
                                "e": "AQAB",
                            }
                        ]
                    }
                }
            },
        },
        500: {"description": "Internal server error"},
    },
)
async def jwks_endpoint():
    """
    JSON Web Key Set endpoint.

    Returns public keys for ID token signature verification according to
    RFC 7517 and OpenID Connect Core 1.0 specification.

    Returns:
        JWKSModel: JSON Web Key Set with public keys

    Raises:
        HTTPException: If JWKS generation fails
    """
    try:
        from authly.oidc.jwks import get_jwks_response

        # Get JWKS response
        jwks_response = get_jwks_response()

        logger.info("JWKS endpoint accessed successfully")

        # Return with proper caching headers
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content=jwks_response,
            headers={
                "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
            },
        )

    except Exception as e:
        logger.error(f"Error generating JWKS response: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to generate JWKS response"
        )
