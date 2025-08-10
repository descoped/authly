"""
OAuth 2.0 Token Introspection Implementation (RFC 7662).

This module implements token introspection endpoint that allows resource servers
to query the authorization server about the state and metadata of tokens.

Token introspection provides:
- Validation of token state (active/inactive)
- Token metadata (scope, client_id, username, exp, etc.)
- Support for access and refresh tokens
"""

import logging
from datetime import UTC, datetime
from typing import Any

from jose import JWTError, jwt
from pydantic import BaseModel

from authly.config import AuthlyConfig
from authly.tokens.repository import TokenRepository
from authly.users import UserRepository

logger = logging.getLogger(__name__)


class TokenIntrospectionRequest(BaseModel):
    """Token introspection request model per RFC 7662."""

    token: str
    token_type_hint: str | None = None  # "access_token" or "refresh_token"


class TokenIntrospectionResponse(BaseModel):
    """Token introspection response model per RFC 7662."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: str | None = None
    iss: str | None = None
    jti: str | None = None


class TokenIntrospectionService:
    """
    Service for OAuth 2.0 token introspection.

    Provides token validation and metadata retrieval per RFC 7662.
    """

    def __init__(
        self,
        token_repo: TokenRepository,
        user_repo: UserRepository,
        config: AuthlyConfig,
    ):
        """
        Initialize token introspection service.

        Args:
            token_repo: Repository for token operations
            user_repo: Repository for user operations
            config: Authly configuration
        """
        self.token_repo = token_repo
        self.user_repo = user_repo
        self.config = config

    async def introspect_token(self, token: str, token_type_hint: str | None = None) -> dict[str, Any]:
        """
        Introspect a token and return its metadata.

        Args:
            token: The token to introspect
            token_type_hint: Optional hint about token type

        Returns:
            Dictionary containing token metadata
        """
        try:
            # Try to decode the token to get JTI
            token_data = self._decode_token(token, token_type_hint)

            if not token_data:
                # Token is malformed or expired
                return {"active": False}

            # Get JTI from token
            jti = token_data.get("jti")
            if not jti:
                logger.warning("Token missing JTI claim")
                return {"active": False}

            # Check if token exists and is valid in database
            is_valid = await self.token_repo.is_token_valid(jti)

            if not is_valid:
                return {"active": False}

            # Get stored token for additional metadata
            stored_token = await self.token_repo.get_by_jti(jti)

            if not stored_token:
                return {"active": False}

            # Check if token is expired
            if stored_token.expires_at and stored_token.expires_at < datetime.now(UTC):
                return {"active": False}

            # Build introspection response
            response = {
                "active": True,
                "token_type": "Bearer",
                "jti": jti,
            }

            # Add scope if present
            if stored_token.scope:
                response["scope"] = stored_token.scope
            elif token_data.get("scope"):
                response["scope"] = token_data.get("scope")

            # Add client_id if present
            if stored_token.client_id:
                # Get the actual client_id string from the client
                # stored_token.client_id is a UUID, but we need the string client_id
                response["client_id"] = token_data.get("client_id")
            elif token_data.get("client_id"):
                response["client_id"] = token_data.get("client_id")

            # Add user information if token has user context
            if stored_token.user_id:
                user = await self.user_repo.get_by_id(stored_token.user_id)
                if user:
                    response["username"] = user.username
                    response["sub"] = str(user.id)
            elif token_data.get("sub"):
                response["sub"] = token_data.get("sub")

            # Add token timestamps
            if token_data.get("exp"):
                response["exp"] = token_data.get("exp")
            if token_data.get("iat"):
                response["iat"] = token_data.get("iat")
            if token_data.get("nbf"):
                response["nbf"] = token_data.get("nbf")

            # Add issuer and audience
            if token_data.get("iss"):
                response["iss"] = token_data.get("iss")
            if token_data.get("aud"):
                response["aud"] = token_data.get("aud")

            return response

        except Exception as e:
            logger.error(f"Error during token introspection: {e}")
            # Per RFC 7662, return inactive for any error
            return {"active": False}

    def _decode_token(self, token: str, token_type_hint: str | None) -> dict[str, Any] | None:
        """
        Decode a JWT token without full validation.

        Args:
            token: The token to decode
            token_type_hint: Hint about token type

        Returns:
            Decoded token claims or None if invalid
        """
        try:
            # Determine which secret to use based on hint
            secret = self.config.refresh_secret_key if token_type_hint == "refresh_token" else self.config.secret_key

            # Try to decode with the appropriate secret
            try:
                claims = jwt.decode(
                    token,
                    secret,
                    algorithms=[self.config.algorithm],
                    options={"verify_exp": False},  # We check expiry separately
                )
                return claims
            except JWTError:
                # If first attempt fails and no hint, try refresh token secret
                if not token_type_hint:
                    try:
                        claims = jwt.decode(
                            token,
                            self.config.refresh_secret_key,
                            algorithms=[self.config.algorithm],
                            options={"verify_exp": False},
                        )
                        return claims
                    except JWTError:
                        pass

                return None

        except Exception as e:
            logger.debug(f"Failed to decode token: {e}")
            return None


async def introspect_token_endpoint(
    request: TokenIntrospectionRequest,
    token_repo: TokenRepository,
    user_repo: UserRepository,
    config: AuthlyConfig,
) -> TokenIntrospectionResponse:
    """
    Endpoint handler for token introspection.

    Args:
        request: Introspection request data
        token_repo: Token repository
        user_repo: User repository
        config: Authly configuration

    Returns:
        Token introspection response
    """
    service = TokenIntrospectionService(
        token_repo=token_repo,
        user_repo=user_repo,
        config=config,
    )

    result = await service.introspect_token(token=request.token, token_type_hint=request.token_type_hint)

    return TokenIntrospectionResponse(**result)
