"""OAuth 2.1 Authorization Service.

Handles authorization code generation, validation, and OAuth 2.1 authorization flow business logic.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    AuthorizationError,
    CodeChallengeMethod,
    OAuthAuthorizationErrorResponse,
    OAuthAuthorizationRequest,
    OAuthAuthorizationResponse,
    OAuthClientModel,
    Prompt,
    ResponseMode,
    ResponseType,
    UserConsentRequest,
)
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)


class AuthorizationService:
    """Service for OAuth 2.1 authorization flow operations."""

    def __init__(
        self,
        client_repo: ClientRepository,
        scope_repo: ScopeRepository,
        auth_code_repo: AuthorizationCodeRepository,
    ):
        self.client_repo = client_repo
        self.scope_repo = scope_repo
        self.auth_code_repo = auth_code_repo

    async def validate_authorization_request(
        self, request: OAuthAuthorizationRequest
    ) -> Tuple[bool, Optional[str], Optional[OAuthClientModel]]:
        """
        Validate OAuth 2.1 authorization request with OpenID Connect support.

        Args:
            request: Authorization request to validate

        Returns:
            Tuple of (is_valid, error_code, client_model)
        """
        try:
            # Validate response type (OAuth 2.1 only supports 'code')
            if request.response_type != ResponseType.CODE:
                return False, AuthorizationError.UNSUPPORTED_RESPONSE_TYPE, None

            # Validate PKCE parameters (OAuth 2.1 mandatory)
            if not request.validate_pkce_params():
                return False, AuthorizationError.INVALID_REQUEST, None

            # Validate OpenID Connect parameters if present
            if not request.validate_oidc_params():
                return False, AuthorizationError.INVALID_REQUEST, None

            # Get and validate client
            client = await self.client_repo.get_by_client_id(request.client_id)
            if not client:
                logger.warning(f"Authorization request for unknown client: {request.client_id}")
                return False, AuthorizationError.UNAUTHORIZED_CLIENT, None

            if not client.is_active:
                logger.warning(f"Authorization request for inactive client: {request.client_id}")
                return False, AuthorizationError.UNAUTHORIZED_CLIENT, None

            # Validate redirect URI
            if not client.is_redirect_uri_allowed(request.redirect_uri):
                logger.warning(f"Invalid redirect URI for client {request.client_id}: {request.redirect_uri}")
                return False, AuthorizationError.INVALID_REQUEST, None

            # Validate response type support
            if not client.supports_response_type(request.response_type):
                return False, AuthorizationError.UNSUPPORTED_RESPONSE_TYPE, None

            # Validate scopes if provided
            if request.scope:
                requested_scopes = request.get_scope_list()
                valid_scopes = await self.scope_repo.validate_scope_names(requested_scopes)
                if not valid_scopes:
                    return False, AuthorizationError.INVALID_SCOPE, None

            # OpenID Connect specific validation
            if request.is_oidc_request():
                # For OIDC requests, validate that openid scope is present
                if "openid" not in request.get_scope_list():
                    logger.warning(f"OIDC request without openid scope: {request.client_id}")
                    return False, AuthorizationError.INVALID_SCOPE, None

                # If prompt=none, additional checks should be performed
                if request.prompt == Prompt.NONE:
                    # In a real implementation, you would check if the user is already authenticated
                    # and has given consent for the requested scopes
                    logger.info(f"OIDC prompt=none request for client {request.client_id}")

            return True, None, client

        except Exception as e:
            logger.error(f"Error validating authorization request: {e}")
            return False, AuthorizationError.SERVER_ERROR, None

    async def generate_authorization_code(self, consent_request: UserConsentRequest) -> Optional[str]:
        """
        Generate an authorization code after user consent.

        Args:
            consent_request: User consent information

        Returns:
            Generated authorization code or None if failed
        """
        try:
            if not consent_request.approved:
                return None

            # Generate secure authorization code
            try:
                from authly import get_config

                config = get_config()
                auth_code_length = config.authorization_code_length
            except RuntimeError:
                # Fallback for tests without full Authly initialization
                auth_code_length = 32
            auth_code = secrets.token_urlsafe(auth_code_length)

            # Calculate expiration (OAuth 2.1 recommends short-lived codes, max 10 minutes)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

            # Determine granted scopes
            granted_scope = None
            if consent_request.approved_scopes:
                granted_scope = " ".join(consent_request.approved_scopes)
            elif consent_request.scope:
                # User approved all requested scopes
                granted_scope = consent_request.scope

            # Store authorization code with OpenID Connect parameters
            auth_code_data = {
                "code": auth_code,
                "client_id": await self._get_client_uuid(consent_request.client_id),
                "user_id": consent_request.user_id,
                "redirect_uri": consent_request.redirect_uri,
                "scope": granted_scope,
                "expires_at": expires_at,
                "code_challenge": consent_request.code_challenge,
                "code_challenge_method": consent_request.code_challenge_method,
                "is_used": False,
                # OpenID Connect parameters
                "nonce": consent_request.nonce,
                "state": consent_request.state,
                "response_mode": consent_request.response_mode,
                "display": consent_request.display,
                "prompt": consent_request.prompt,
                "max_age": consent_request.max_age,
                "ui_locales": consent_request.ui_locales,
                "id_token_hint": consent_request.id_token_hint,
                "login_hint": consent_request.login_hint,
                "acr_values": consent_request.acr_values,
            }

            created_code = await self.auth_code_repo.create_authorization_code(auth_code_data)
            if created_code:
                logger.info(f"Generated authorization code for client {consent_request.client_id}")
                return auth_code

            return None

        except Exception as e:
            logger.error(f"Error generating authorization code: {e}")
            return None

    async def exchange_authorization_code(
        self, code: str, client_id: str, redirect_uri: str, code_verifier: str
    ) -> Tuple[bool, Optional[dict], Optional[str]]:
        """
        Exchange authorization code for tokens (token endpoint logic).

        Args:
            code: Authorization code to exchange
            client_id: Client identifier
            redirect_uri: Redirect URI from original request
            code_verifier: PKCE code verifier

        Returns:
            Tuple of (success, code_data, error_message)
        """
        try:
            # Get authorization code
            auth_code = await self.auth_code_repo.get_by_code(code)
            if not auth_code:
                return False, None, "Invalid authorization code"

            # Validate code is not expired or used
            if not auth_code.is_valid():
                return False, None, "Authorization code expired or already used"

            # Get client UUID for comparison
            client_uuid = await self._get_client_uuid(client_id)
            if not client_uuid or auth_code.client_id != client_uuid:
                return False, None, "Invalid client for authorization code"

            # Validate redirect URI matches
            if auth_code.redirect_uri != redirect_uri:
                return False, None, "Redirect URI mismatch"

            # Verify PKCE code verifier
            if not self._verify_pkce_challenge(code_verifier, auth_code.code_challenge):
                return False, None, "Invalid PKCE code verifier"

            # Mark code as used
            success = await self.auth_code_repo.consume_authorization_code(code)
            if not success:
                return False, None, "Failed to consume authorization code"

            # Return code data for token generation with OpenID Connect parameters
            return (
                True,
                {
                    "user_id": auth_code.user_id,
                    "client_id": auth_code.client_id,
                    "scope": auth_code.scope,
                    "nonce": auth_code.nonce,
                    "max_age": auth_code.max_age,
                    "acr_values": auth_code.acr_values,
                },
                None,
            )

        except Exception as e:
            logger.error(f"Error exchanging authorization code: {e}")
            return False, None, "Server error"

    async def create_authorization_response(
        self, request: OAuthAuthorizationRequest, auth_code: Optional[str] = None, error: Optional[str] = None
    ) -> OAuthAuthorizationResponse:
        """
        Create authorization response (success or error).

        Args:
            request: Original authorization request
            auth_code: Generated authorization code (if successful)
            error: Error code (if failed)

        Returns:
            Authorization response
        """
        if auth_code:
            return OAuthAuthorizationResponse(code=auth_code, state=request.state)
        else:
            return OAuthAuthorizationResponse(
                error=error or AuthorizationError.SERVER_ERROR,
                error_description=self._get_error_description(error),
                state=request.state,
            )

    async def create_authorization_error_response(
        self, error: str, description: Optional[str] = None, state: Optional[str] = None
    ) -> OAuthAuthorizationErrorResponse:
        """
        Create authorization error response.

        Args:
            error: Error code
            description: Error description
            state: State parameter from request

        Returns:
            Authorization error response
        """
        return OAuthAuthorizationErrorResponse(
            error=error, error_description=description or self._get_error_description(error), state=state
        )

    async def get_requested_scopes(self, scope_string: Optional[str], client: OAuthClientModel) -> List[str]:
        """
        Get validated requested scopes.

        Args:
            scope_string: Requested scopes (space-separated)
            client: OAuth client

        Returns:
            List of valid scope names
        """
        if not scope_string:
            # Return default scopes if no specific scopes requested
            default_scopes = await self.scope_repo.get_default_scopes()
            return [scope.scope_name for scope in default_scopes]

        requested_scopes = scope_string.split()
        valid_scopes = await self.scope_repo.validate_scope_names(requested_scopes)

        if valid_scopes:
            return requested_scopes
        else:
            # Fall back to default scopes if requested scopes are invalid
            default_scopes = await self.scope_repo.get_default_scopes()
            return [scope.scope_name for scope in default_scopes]

    def _verify_pkce_challenge(self, code_verifier: str, code_challenge: str) -> bool:
        """
        Verify PKCE code challenge using S256 method.

        Args:
            code_verifier: Code verifier provided by client
            code_challenge: Code challenge from authorization request

        Returns:
            True if PKCE verification succeeds
        """
        try:
            # OAuth 2.1 only supports S256 method
            # code_challenge = BASE64URL(SHA256(code_verifier))
            import base64

            # Calculate SHA256 hash of code verifier
            digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()

            # Base64URL encode (without padding)
            calculated_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

            return calculated_challenge == code_challenge

        except Exception as e:
            logger.error(f"Error verifying PKCE challenge: {e}")
            return False

    async def _get_client_uuid(self, client_id: str) -> Optional[UUID]:
        """Get client UUID from client_id string."""
        try:
            client = await self.client_repo.get_by_client_id(client_id)
            return client.id if client else None
        except Exception:
            return None

    def _get_error_description(self, error: Optional[str]) -> str:
        """Get human-readable error description."""
        error_descriptions = {
            AuthorizationError.INVALID_REQUEST: "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.",
            AuthorizationError.UNAUTHORIZED_CLIENT: "The client is not authorized to request an authorization code using this method.",
            AuthorizationError.ACCESS_DENIED: "The resource owner or authorization server denied the request.",
            AuthorizationError.UNSUPPORTED_RESPONSE_TYPE: "The authorization server does not support obtaining an authorization code using this method.",
            AuthorizationError.INVALID_SCOPE: "The requested scope is invalid, unknown, or malformed.",
            AuthorizationError.SERVER_ERROR: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
            AuthorizationError.TEMPORARILY_UNAVAILABLE: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
        }

        return error_descriptions.get(error, "Unknown error occurred.")
