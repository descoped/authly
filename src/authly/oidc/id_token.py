"""
OpenID Connect ID Token Generation.

This module implements ID token creation and validation according to the
OpenID Connect Core 1.0 specification. ID tokens are JWT tokens that contain
user authentication information and claims.

ID Token Structure:
- Header: JWT header with algorithm and key ID
- Payload: Claims about the user authentication and identity
- Signature: Cryptographic signature for verification

Required Claims:
- iss (issuer): Identifier for the issuer
- sub (subject): Identifier for the user
- aud (audience): Identifier for the client
- exp (expiration): Expiration time
- iat (issued at): Token issue time

Optional Claims:
- auth_time: Time of authentication
- nonce: Anti-replay nonce
- acr: Authentication Context Class Reference
- amr: Authentication Methods References
- azp: Authorized party (client ID when multiple audiences)
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from jose import JWTError, jwt

from authly.config import AuthlyConfig
from authly.oauth.models import OAuthClientModel
from authly.users.models import UserModel

from .scopes import OIDCClaimsMapping, OIDCStandardClaims

logger = logging.getLogger(__name__)


class IDTokenClaims:
    """Standard ID token claims according to OIDC Core 1.0."""

    # Required claims
    ISS = "iss"  # Issuer
    SUB = "sub"  # Subject
    AUD = "aud"  # Audience
    EXP = "exp"  # Expiration time
    IAT = "iat"  # Issued at time

    # Optional claims
    AUTH_TIME = "auth_time"  # Authentication time
    NONCE = "nonce"  # Anti-replay nonce
    ACR = "acr"  # Authentication Context Class Reference
    AMR = "amr"  # Authentication Methods References
    AZP = "azp"  # Authorized party


class IDTokenGenerator:
    """
    OpenID Connect ID Token generator.

    Generates JWT-based ID tokens containing user claims according to
    granted scopes and OIDC specifications.
    """

    def __init__(self, config: AuthlyConfig):
        """
        Initialize ID token generator.

        Args:
            config: Authly configuration containing JWT settings
        """
        self.config = config
        # For OIDC ID tokens, always use RS256 for interoperability
        self.algorithm = "RS256"
        try:
            self.issuer = config.default_issuer_url
        except (AttributeError, RuntimeError):
            # Fallback for tests or when config not fully initialized
            self.issuer = "https://authly.localhost"
        self.id_token_expire_minutes = 15  # Default ID token expiration

    def generate_id_token(
        self,
        user: UserModel,
        client: OAuthClientModel,
        scopes: list[str],
        nonce: str | None = None,
        auth_time: datetime | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate an ID token for the user.

        Args:
            user: User model containing user information
            client: OAuth client requesting the token
            scopes: List of granted scopes
            nonce: Nonce value for anti-replay protection
            auth_time: Time of authentication
            additional_claims: Additional claims to include

        Returns:
            JWT ID token as string

        Raises:
            HTTPException: If token generation fails
        """
        # Validate that this is an OIDC request
        if not OIDCClaimsMapping.is_oidc_request(scopes):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ID token can only be generated for OIDC requests (must include 'openid' scope)",
            )

        try:
            # Generate token timing
            now = datetime.now(UTC)
            issued_at = now
            expires_at = now + timedelta(minutes=self.id_token_expire_minutes)

            # Build required claims
            claims = {
                IDTokenClaims.ISS: self.issuer,
                IDTokenClaims.SUB: str(user.id),
                IDTokenClaims.AUD: str(client.client_id),
                IDTokenClaims.EXP: int(expires_at.timestamp()),
                IDTokenClaims.IAT: int(issued_at.timestamp()),
            }

            # Add optional claims
            if nonce:
                claims[IDTokenClaims.NONCE] = nonce

            if auth_time:
                claims[IDTokenClaims.AUTH_TIME] = int(auth_time.timestamp())
            else:
                # Use current time if not provided
                claims[IDTokenClaims.AUTH_TIME] = int(now.timestamp())

            # Add user claims based on granted scopes
            user_claims = self._extract_user_claims(user, scopes)
            claims.update(user_claims)

            # Add additional claims if provided
            if additional_claims:
                claims.update(additional_claims)

            # Get RSA private key from JWKS for signing
            from .jwks import get_current_signing_key

            signing_key = get_current_signing_key()

            if not signing_key:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="No signing key available for ID token generation",
                )

            # Serialize private key to PEM format for jose library
            from cryptography.hazmat.primitives import serialization

            private_key_pem = signing_key.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Generate JWT token with RSA key and include key ID in header
            token = jwt.encode(claims, private_key_pem, algorithm=self.algorithm, headers={"kid": signing_key.key_id})

            logger.info(f"Generated ID token for user {user.id} and client {client.client_id}")
            logger.debug(f"ID token claims: {list(claims.keys())}")

            return token

        except JWTError as e:
            logger.error(f"Failed to generate ID token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate ID token"
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error generating ID token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
            ) from e

    def _extract_user_claims(self, user: UserModel, scopes: list[str]) -> dict[str, Any]:
        """
        Extract user claims based on granted scopes.

        Args:
            user: User model
            scopes: List of granted scopes

        Returns:
            Dictionary of user claims
        """
        # Get all claims allowed by the granted scopes
        allowed_claims = OIDCClaimsMapping.get_claims_for_scopes(scopes)

        # Build user claims dictionary
        user_claims = {}

        # Map user model fields to OIDC claims using new OIDC claim fields
        claim_mappings = {
            # Profile scope claims
            OIDCStandardClaims.NAME: self._get_user_name(user),
            OIDCStandardClaims.GIVEN_NAME: getattr(user, "given_name", None),
            OIDCStandardClaims.FAMILY_NAME: getattr(user, "family_name", None),
            OIDCStandardClaims.MIDDLE_NAME: getattr(user, "middle_name", None),
            OIDCStandardClaims.NICKNAME: getattr(user, "nickname", None),
            OIDCStandardClaims.PREFERRED_USERNAME: getattr(user, "preferred_username", None) or user.username,
            OIDCStandardClaims.PROFILE: getattr(user, "profile", None),
            OIDCStandardClaims.PICTURE: getattr(user, "picture", None),
            OIDCStandardClaims.WEBSITE: getattr(user, "website", None),
            OIDCStandardClaims.GENDER: getattr(user, "gender", None),
            OIDCStandardClaims.BIRTHDATE: getattr(user, "birthdate", None),
            OIDCStandardClaims.ZONEINFO: getattr(user, "zoneinfo", None),
            OIDCStandardClaims.LOCALE: getattr(user, "locale", None),
            OIDCStandardClaims.UPDATED_AT: int(user.updated_at.timestamp()) if user.updated_at else None,
            # Email scope claims
            OIDCStandardClaims.EMAIL: user.email,
            OIDCStandardClaims.EMAIL_VERIFIED: user.is_verified,
            # Phone scope claims
            OIDCStandardClaims.PHONE_NUMBER: getattr(user, "phone_number", None),
            OIDCStandardClaims.PHONE_NUMBER_VERIFIED: getattr(user, "phone_number_verified", None),
            # Address scope claims
            OIDCStandardClaims.ADDRESS: getattr(user, "address", None),
        }

        # Add claims that are allowed by scopes and have values
        for claim_name, claim_value in claim_mappings.items():
            if claim_name in allowed_claims and claim_value is not None:
                user_claims[claim_name] = claim_value

        return user_claims

    def _get_user_name(self, user: UserModel) -> str | None:
        """
        Get user's full name from the user model.

        Args:
            user: User model

        Returns:
            User's full name or username as fallback
        """
        # Try to construct full name from OIDC claim fields
        given_name = getattr(user, "given_name", None)
        family_name = getattr(user, "family_name", None)

        if given_name and family_name:
            return f"{given_name} {family_name}"
        elif given_name:
            return given_name
        elif family_name:
            return family_name
        else:
            # Fallback to username if no name components available
            return user.username

    def validate_id_token(self, token: str, client_id: str) -> dict[str, Any]:
        """
        Validate an ID token.

        Args:
            token: JWT ID token to validate
            client_id: Expected client ID (audience)

        Returns:
            Decoded token claims

        Raises:
            HTTPException: If token is invalid
        """
        try:
            # Get the key ID from token header
            unverified_header = jwt.get_unverified_header(token)
            key_id = unverified_header.get("kid")

            if not key_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="ID token missing key ID")

            # Get RSA public key from JWKS for verification
            from .jwks import get_key_for_verification

            key_pair = get_key_for_verification(key_id)

            if not key_pair:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid key ID in token")

            # Serialize public key to PEM format for jose library
            from cryptography.hazmat.primitives import serialization

            public_key_pem = key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Decode and validate token
            claims = jwt.decode(
                token, public_key_pem, algorithms=[self.algorithm], audience=client_id, issuer=self.issuer
            )

            # Additional validation
            self._validate_id_token_claims(claims, client_id)

            return claims

        except JWTError as e:
            logger.warning(f"Invalid ID token: {e}")
            # Check if the error is audience-related
            if "audience" in str(e).lower():
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience") from e
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ID token") from e
        except HTTPException:
            # Re-raise HTTPExceptions as-is (don't wrap in 500)
            raise
        except Exception as e:
            logger.error(f"Error validating ID token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token validation error"
            ) from e

    def _validate_id_token_claims(self, claims: dict[str, Any], expected_client_id: str):
        """
        Validate ID token claims.

        Args:
            claims: Decoded token claims
            expected_client_id: Expected client ID

        Raises:
            HTTPException: If claims are invalid
        """
        # Check required claims
        required_claims = [
            IDTokenClaims.ISS,
            IDTokenClaims.SUB,
            IDTokenClaims.AUD,
            IDTokenClaims.EXP,
            IDTokenClaims.IAT,
        ]

        for claim in required_claims:
            if claim not in claims:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Missing required claim: {claim}")

        # Validate issuer
        if claims[IDTokenClaims.ISS] != self.issuer:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer")

        # Validate audience
        audience = claims[IDTokenClaims.AUD]
        if isinstance(audience, list):
            if expected_client_id not in audience:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience")
        else:
            if audience != expected_client_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience")

        # Validate expiration
        exp = claims[IDTokenClaims.EXP]
        if datetime.now(UTC).timestamp() > exp:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    def extract_user_id(self, token: str) -> UUID:
        """
        Extract user ID from ID token without full validation.

        Args:
            token: JWT ID token

        Returns:
            User ID as UUID

        Raises:
            HTTPException: If token is invalid or missing subject
        """
        try:
            # Decode without verification (for extracting user ID only)
            claims = jwt.get_unverified_claims(token)

            if IDTokenClaims.SUB not in claims:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject claim")

            return UUID(claims[IDTokenClaims.SUB])

        except (JWTError, ValueError) as e:
            logger.warning(f"Failed to extract user ID from token: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format") from None


class IDTokenService:
    """
    Service layer for ID token operations.

    Provides high-level operations for ID token generation and validation
    with proper error handling and logging.
    """

    def __init__(self, config: AuthlyConfig):
        """
        Initialize ID token service.

        Args:
            config: Authly configuration
        """
        self.generator = IDTokenGenerator(config)

    async def create_id_token(
        self,
        user: UserModel,
        client: OAuthClientModel,
        scopes: list[str],
        nonce: str | None = None,
        auth_time: datetime | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Create an ID token for the user.

        Args:
            user: User model
            client: OAuth client
            scopes: Granted scopes
            nonce: Nonce value
            auth_time: Authentication time
            additional_claims: Additional claims

        Returns:
            JWT ID token
        """
        return self.generator.generate_id_token(
            user=user,
            client=client,
            scopes=scopes,
            nonce=nonce,
            auth_time=auth_time,
            additional_claims=additional_claims,
        )

    async def validate_id_token(self, token: str, client_id: str) -> dict[str, Any]:
        """
        Validate an ID token.

        Args:
            token: JWT ID token
            client_id: Expected client ID

        Returns:
            Decoded token claims
        """
        return self.generator.validate_id_token(token, client_id)

    async def get_user_id_from_token(self, token: str) -> UUID:
        """
        Extract user ID from ID token.

        Args:
            token: JWT ID token

        Returns:
            User ID
        """
        return self.generator.extract_user_id(token)


# Utility functions for integration
def create_id_token_service(config: AuthlyConfig) -> IDTokenService:
    """
    Create ID token service instance.

    Args:
        config: Authly configuration

    Returns:
        ID token service
    """
    return IDTokenService(config)


def validate_id_token_scopes(scopes: list[str]) -> bool:
    """
    Validate that scopes are appropriate for ID token generation.

    Args:
        scopes: List of scopes

    Returns:
        True if scopes are valid for ID token generation
    """
    return OIDCClaimsMapping.is_oidc_request(scopes)
