"""
OpenID Connect (OIDC) 1.0 implementation for Authly.

This package provides OpenID Connect functionality on top of the OAuth 2.1 foundation,
including ID tokens, UserInfo endpoint, and OIDC discovery.
"""

from .discovery import OIDCDiscoveryService, OIDCServerMetadata, get_oidc_discovery_service
from .id_token import IDTokenClaims, IDTokenGenerator, IDTokenService, create_id_token_service
from .jwks import (
    JWKModel,
    JWKSManager,
    JWKSModel,
    JWKSService,
    RSAKeyPair,
    get_current_signing_key,
    get_jwks_manager,
    get_jwks_response,
)
from .scopes import OIDC_SCOPES, OIDCClaimsMapping, get_oidc_scopes_with_descriptions
from .userinfo import UserInfoResponse, UserInfoService

__all__ = [
    "OIDC_SCOPES",
    "IDTokenClaims",
    "IDTokenGenerator",
    "IDTokenService",
    "JWKModel",
    "JWKSManager",
    "JWKSModel",
    "JWKSService",
    "OIDCClaimsMapping",
    "OIDCDiscoveryService",
    "OIDCServerMetadata",
    "RSAKeyPair",
    "UserInfoResponse",
    "UserInfoService",
    "create_id_token_service",
    "get_current_signing_key",
    "get_jwks_manager",
    "get_jwks_response",
    "get_oidc_discovery_service",
    "get_oidc_scopes_with_descriptions",
]
