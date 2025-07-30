import logging
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from authly.oauth.client_repository import ClientRepository

from fastapi import HTTPException
from jose import jwt
from jose.exceptions import JWTError
from psycopg_toolkit import RecordNotFoundError
from starlette import status

from authly.auth import create_access_token, create_refresh_token, decode_token
from authly.config import AuthlyConfig
from authly.oidc.scopes import OIDCClaimsMapping
from authly.tokens.models import TokenModel, TokenPairResponse, TokenType
from authly.tokens.repository import TokenRepository
from authly.users import UserModel, UserRepository

logger = logging.getLogger(__name__)


class TokenService:
    """
    Service for managing tokens using TokenRepository directly.
    Simplified architecture that removes unnecessary abstraction layers.
    """

    def __init__(
        self, repository: TokenRepository, config: AuthlyConfig, client_repository: Optional["ClientRepository"] = None
    ):
        self._repo = repository
        self._config = config
        self._client_repo = client_repository

    async def create_token(self, token: TokenModel) -> TokenModel:
        """Create a new token record"""
        return await self._repo.store_token(token)

    async def get_token(self, token_jti: str) -> Optional[TokenModel]:
        """Get a token by its JTI"""
        return await self._repo.get_by_jti(token_jti)

    async def get_user_tokens(
        self, user_id: UUID, token_type: Optional[TokenType] = None, valid_only: bool = True
    ) -> List[TokenModel]:
        """Get all tokens for a user"""
        return await self._repo.get_user_tokens(user_id, token_type, valid_only)

    async def invalidate_token(self, token_jti: str) -> bool:
        """Invalidate a specific token"""
        try:
            await self._repo.invalidate_token(token_jti)
            return True
        except Exception:
            return False

    async def invalidate_user_tokens(self, user_id: UUID, token_type: Optional[TokenType] = None) -> int:
        """Invalidate all tokens for a user"""
        await self._repo.invalidate_user_tokens(user_id, token_type.value if token_type else None)
        return await self._repo.get_invalidated_token_count(user_id, token_type)

    async def is_token_valid(self, token_jti: str) -> bool:
        """Check if a token is valid"""
        return await self._repo.is_token_valid(token_jti)

    async def cleanup_expired_tokens(self, before_datetime: Optional[datetime] = None) -> int:
        """Clean up expired tokens"""
        if before_datetime is None:
            before_datetime = datetime.now(timezone.utc)
        return await self._repo.cleanup_expired_tokens(before_datetime)

    async def count_user_valid_tokens(self, user_id: UUID, token_type: Optional[TokenType] = None) -> int:
        """Count valid tokens for a user"""
        return await self._repo.count_user_valid_tokens(user_id, token_type)

    async def logout_user(self, user_id: UUID) -> None:
        """
        Logout user by invalidating all their tokens.
        This is a higher-level operation that builds on the basic token operations.
        """
        invalidated_count = await self.invalidate_user_tokens(user_id)
        if invalidated_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active sessions found")

    async def create_token_pair(
        self,
        user: UserModel,
        scope: Optional[str] = None,
        client_id: Optional[str] = None,
        oidc_params: Optional[dict] = None,
    ) -> TokenPairResponse:
        """
        Create a new access and refresh token pair for a user, with optional ID token for OIDC flows.

        Args:
            user: The user to create tokens for
            scope: Optional OAuth scopes (space-separated string)
            oidc_params: Optional OIDC parameters for ID token generation

        Returns:
            TokenPairResponse containing the new token pair and optional ID token

        Raises:
            HTTPException: If token creation fails
        """
        try:
            # Generate unique JTIs for both tokens
            access_jti = secrets.token_hex(self._config.token_hex_length)
            refresh_jti = secrets.token_hex(self._config.token_hex_length)

            # Prepare token data
            access_data = {"sub": str(user.id), "jti": access_jti}

            # Add scope to access token if provided (OAuth 2.1 compliance)
            if scope:
                access_data["scope"] = scope

            # Create JWT tokens
            access_token = create_access_token(
                data=access_data,
                secret_key=self._config.secret_key,
                algorithm=self._config.algorithm,
                expires_delta=self._config.access_token_expire_minutes,
                config=self._config,
            )

            refresh_token = create_refresh_token(
                user_id=str(user.id),
                secret_key=self._config.refresh_secret_key,
                jti=refresh_jti,
                config=self._config,
            )

            # Decode tokens to get expiry times
            access_payload = jwt.decode(access_token, self._config.secret_key, algorithms=[self._config.algorithm])
            refresh_payload = jwt.decode(
                refresh_token, self._config.refresh_secret_key, algorithms=[self._config.algorithm]
            )

            # Create token models
            access_token_model = TokenModel(
                id=uuid4(),
                user_id=user.id,
                token_jti=access_jti,
                token_type=TokenType.ACCESS,
                token_value=access_token,
                expires_at=datetime.fromtimestamp(access_payload["exp"], tz=timezone.utc),
                created_at=datetime.now(timezone.utc),
                scope=scope,  # Store scope for OAuth 2.1 compliance
            )

            refresh_token_model = TokenModel(
                id=uuid4(),
                user_id=user.id,
                token_jti=refresh_jti,
                token_type=TokenType.REFRESH,
                token_value=refresh_token,
                expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
                created_at=datetime.now(timezone.utc),
                scope=scope,  # Store scope to preserve during refresh
            )

            # Store both tokens
            await self.create_token(access_token_model)
            await self.create_token(refresh_token_model)

            # Generate ID token if this is an OIDC request
            id_token = None
            if self._is_oidc_request(scope) and client_id:
                id_token = await self._generate_id_token(user, scope, client_id, oidc_params)

            return TokenPairResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                expires_in=self._config.access_token_expire_minutes * 60,
                id_token=id_token,
            )

        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create authentication tokens"
            )

    async def refresh_token_pair(
        self, refresh_token: str, user_repo: UserRepository, client_id: Optional[str] = None
    ) -> TokenPairResponse:
        """
        Create a new token pair using a refresh token, invalidating the old refresh token.

        Args:
            refresh_token: The refresh token to use for creating new tokens
            user_repo: UserRepository instance for user lookups

        Returns:
            TokenPairResponse containing the new token pair

        Raises:
            HTTPException: If token refresh fails
        """
        try:
            # Decode the provided refresh token
            payload = jwt.decode(refresh_token, self._config.refresh_secret_key, algorithms=[self._config.algorithm])

            # Validate token type and extract claims
            if payload.get("type") != "refresh":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

            user_id = payload.get("sub")
            token_jti = payload.get("jti")

            if not user_id or not token_jti:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token claims")

            # Verify token is valid in store and get original token to retrieve scope
            original_token = await self.get_token(token_jti)
            if not original_token or not await self.is_token_valid(token_jti):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid or expired")

            # Extract scope from original token for preservation
            original_scope = original_token.scope

            # Get the user
            try:
                user = await user_repo.get_by_id(UUID(user_id))
            except (ValueError, RecordNotFoundError):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

            if not user.is_active:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive")

            # Generate new JTIs for both tokens
            new_access_jti = secrets.token_hex(self._config.token_hex_length)
            new_refresh_jti = secrets.token_hex(self._config.token_hex_length)

            # Prepare access token data with scope if available
            access_data = {"sub": user_id, "jti": new_access_jti}
            if original_scope:
                access_data["scope"] = original_scope

            # Create new tokens
            new_access_token = create_access_token(
                data=access_data,
                secret_key=self._config.secret_key,
                algorithm=self._config.algorithm,
                expires_delta=self._config.access_token_expire_minutes,
                config=self._config,
            )

            new_refresh_token = create_refresh_token(
                user_id=user_id,
                secret_key=self._config.refresh_secret_key,
                jti=new_refresh_jti,
                config=self._config,
            )

            # Decode new tokens to get expiry times
            access_payload = jwt.decode(new_access_token, self._config.secret_key, algorithms=[self._config.algorithm])
            refresh_payload = jwt.decode(
                new_refresh_token, self._config.refresh_secret_key, algorithms=[self._config.algorithm]
            )

            # Invalidate the old refresh token
            await self.invalidate_token(token_jti)

            # Create new token models
            new_access_model = TokenModel(
                id=uuid4(),
                user_id=UUID(user_id),
                token_jti=new_access_jti,
                token_type=TokenType.ACCESS,
                token_value=new_access_token,
                expires_at=datetime.fromtimestamp(access_payload["exp"], tz=timezone.utc),
                created_at=datetime.now(timezone.utc),
                scope=original_scope,  # Preserve original scope
            )

            new_refresh_model = TokenModel(
                id=uuid4(),
                user_id=UUID(user_id),
                token_jti=new_refresh_jti,
                token_type=TokenType.REFRESH,
                token_value=new_refresh_token,
                expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
                created_at=datetime.now(timezone.utc),
                scope=original_scope,  # Preserve original scope
            )

            # Store the new tokens
            await self.create_token(new_access_model)
            await self.create_token(new_refresh_model)

            # Generate ID token if this is an OIDC request
            id_token = None
            if self._is_oidc_request(original_scope) and client_id:
                # For refresh tokens, we don't have original OIDC params, so pass None
                id_token = await self._generate_id_token(user, original_scope, client_id, None)

            return TokenPairResponse(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                token_type="Bearer",
                expires_in=self._config.access_token_expire_minutes * 60,
                id_token=id_token,
            )

        except HTTPException:
            # Let HTTPExceptions pass through
            raise
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        except Exception:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not refresh tokens")

    async def logout_user_session(self, access_token: str, user_id: UUID) -> int:
        """
        Logout a user session by invalidating all their tokens.

        Args:
            access_token: The current access token
            user_id: The user ID

        Returns:
            Number of tokens invalidated

        Raises:
            HTTPException: If logout fails
        """
        try:
            # Decode current access token to get JTI
            payload = jwt.decode(access_token, self._config.secret_key, algorithms=[self._config.algorithm])
            current_jti = payload.get("jti")

            # Invalidate current token first if JTI exists
            if current_jti:
                await self.invalidate_token(current_jti)

            # Invalidate all user tokens (both access and refresh)
            invalidated_count = await self.invalidate_user_tokens(user_id)

            return invalidated_count

        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
        except Exception:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout operation failed")

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """
        Revoke a token according to RFC 7009 OAuth 2.0 Token Revocation.

        Args:
            token: The token to revoke (JWT string)
            token_type_hint: Optional hint ("access_token" or "refresh_token")

        Returns:
            bool: True if token was successfully revoked, False if token was invalid

        Notes:
            - If revoking a refresh token, also revokes related access tokens
            - If revoking an access token, only revokes that specific token
            - Returns False for invalid tokens (don't raise exceptions per RFC 7009)
        """
        try:
            # Try to decode as access token first (most common case)
            token_payload = None
            token_type = None

            # Use hint to optimize token lookup if provided
            if token_type_hint == "refresh_token":
                # Try refresh token first
                try:
                    token_payload = decode_token(token, self._config.refresh_secret_key, self._config.algorithm)
                    if token_payload.get("type") == "refresh":
                        token_type = TokenType.REFRESH
                except ValueError:
                    pass

                # If refresh failed, try access token
                if token_payload is None:
                    try:
                        token_payload = decode_token(token, self._config.secret_key, self._config.algorithm)
                        token_type = TokenType.ACCESS
                    except ValueError:
                        return False
            else:
                # Try access token first (default case)
                try:
                    token_payload = decode_token(token, self._config.secret_key, self._config.algorithm)
                    token_type = TokenType.ACCESS
                except ValueError:
                    # If access failed, try refresh token
                    try:
                        token_payload = decode_token(token, self._config.refresh_secret_key, self._config.algorithm)
                        if token_payload.get("type") == "refresh":
                            token_type = TokenType.REFRESH
                    except ValueError:
                        return False

            if token_payload is None or token_type is None:
                return False

            # Extract JTI from token
            jti = token_payload.get("jti")
            if not jti:
                return False

            # Check if token exists and is valid in database
            if not await self.is_token_valid(jti):
                # Token doesn't exist or already invalidated
                return False

            # Revoke the token
            success = await self.invalidate_token(jti)

            # If this is a refresh token, also revoke related access tokens
            if success and token_type == TokenType.REFRESH:
                user_id = token_payload.get("sub")
                if user_id:
                    try:
                        user_uuid = UUID(user_id)
                        # Invalidate all access tokens for this user
                        # This is a simplified approach - a more sophisticated implementation
                        # could track token families or authorization grants
                        await self.invalidate_user_tokens(user_uuid, TokenType.ACCESS)
                        logger.info(f"Revoked refresh token and related access tokens for user {user_uuid}")
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid user ID in refresh token: {user_id}")

            if success:
                logger.info(f"Successfully revoked {token_type.value} token with JTI: {jti}")

            return success

        except Exception as e:
            # Log error but don't raise exception per RFC 7009
            logger.error(f"Error during token revocation: {str(e)}")
            return False

    def _is_oidc_request(self, scope: Optional[str]) -> bool:
        """
        Check if this is an OpenID Connect request (contains 'openid' scope).

        Args:
            scope: Space-separated scopes string

        Returns:
            True if this is an OIDC request
        """
        if not scope:
            return False

        scopes = scope.split()
        return OIDCClaimsMapping.is_oidc_request(scopes)

    async def _generate_id_token(
        self, user: UserModel, scope: str, client_id: str, oidc_params: Optional[dict] = None
    ) -> Optional[str]:
        """
        Generate an ID token for OpenID Connect flows.

        Args:
            user: The user to create ID token for
            scope: Granted scopes (space-separated string)
            client_id: Client ID for token generation
            oidc_params: Optional OIDC parameters from authorization code

        Returns:
            JWT ID token string or None if client repository not available
        """
        # Skip ID token generation if no client repository available
        if not self._client_repo:
            logger.warning("Client repository not available for ID token generation")
            return None

        try:
            # Import here to avoid circular imports
            from authly.oidc.id_token import create_id_token_service

            # Create ID token service
            id_token_service = create_id_token_service(self._config)

            # Get client from repository by client_id string
            client = await self._client_repo.get_by_client_id(client_id)
            if not client:
                logger.warning(f"Client {client_id} not found for ID token generation")
                return None

            # Extract scopes
            scopes = scope.split() if scope else []

            # Extract OIDC parameters
            nonce = oidc_params.get("nonce") if oidc_params else None
            max_age = oidc_params.get("max_age") if oidc_params else None
            acr_values = oidc_params.get("acr_values") if oidc_params else None

            # Generate ID token
            id_token = await id_token_service.create_id_token(user=user, client=client, scopes=scopes, nonce=nonce)
            return id_token

        except Exception as e:
            logger.error(f"Error generating ID token: {e}")
            return None
