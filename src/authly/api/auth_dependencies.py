import base64
import logging
from asyncio import Lock
from dataclasses import dataclass
from typing import Final

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer

from authly.api.rate_limiter import RateLimiter
from authly.config import AuthlyConfig
from authly.core.dependencies import get_config, get_database_connection
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import OAuthClientModel
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.service import TokenService

logger = logging.getLogger(__name__)

# Import authentication metrics tracking
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    logger.debug("Metrics collection not available in auth dependencies")
    METRICS_ENABLED = False
    metrics = None


@dataclass(frozen=True)
class OAuth2State:
    oauth: Final[OAuth2PasswordBearer]
    token_url: Final[str]


class DeferredOAuth2PasswordBearer:
    def __init__(self):
        self._state: OAuth2State | None = None
        self._lock = Lock()
        self._init_error: Exception | None = None

    def get_token_url(self, request: Request = None) -> str:
        """Get the token URL."""
        try:
            # Try to get from the global resource manager instance
            from authly.core.dependencies import _resource_manager_instance

            if _resource_manager_instance is not None:
                config = _resource_manager_instance.get_config()
                return f"{config.fastapi_api_version_prefix}/oauth/token"
            else:
                # Fallback to direct environment variable reading
                import os

                api_prefix = os.getenv("AUTHLY_API_VERSION_PREFIX", "/api/v1")
                return f"{api_prefix}/oauth/token"
        except Exception as e:
            self._init_error = e
            raise

    async def initialize(self, request: Request = None) -> OAuth2State:
        """Thread-safe, retry-safe initialization"""
        if self._init_error:
            self._init_error = None

        async with self._lock:
            if self._state is None:
                try:
                    token_url = self.get_token_url(request)
                    oauth = OAuth2PasswordBearer(tokenUrl=token_url, auto_error=True)
                    self._state = OAuth2State(oauth=oauth, token_url=token_url)
                except Exception as e:
                    self._init_error = e
                    raise HTTPException(status_code=503, detail="Authentication service temporarily unavailable") from e

        return self._state

    async def __call__(self, request: Request) -> str:
        """
        This is the method that FastAPI will call as a dependency.
        It needs to return the token string, not the OAuth2PasswordBearer instance.
        """
        state = await self.initialize(request)
        return await state.oauth(request)


# Single instance
oauth2_scheme = DeferredOAuth2PasswordBearer()

# HTTP Basic scheme for client authentication
basic_auth_scheme = HTTPBasic(auto_error=False)


def get_rate_limiter():
    return RateLimiter()


async def get_client_repository(db_connection=Depends(get_database_connection)) -> "ClientRepository":
    """
    Get an instance of the ClientRepository.

    Dependencies:
        - Database connection from resource manager
    """
    from authly.oauth.client_repository import ClientRepository

    return ClientRepository(db_connection)


async def get_scope_repository(db_connection=Depends(get_database_connection)) -> "ScopeRepository":
    """
    Get an instance of the ScopeRepository.

    Dependencies:
        - Database connection from resource manager
    """
    from authly.oauth.scope_repository import ScopeRepository

    return ScopeRepository(db_connection)


async def get_authorization_code_repository(
    db_connection=Depends(get_database_connection),
) -> "AuthorizationCodeRepository":
    """
    Get an instance of the AuthorizationCodeRepository.

    Dependencies:
        - Database connection from resource manager
    """
    from authly.oauth.authorization_code_repository import AuthorizationCodeRepository

    return AuthorizationCodeRepository(db_connection)


async def get_authorization_service(
    client_repo: "ClientRepository" = Depends(get_client_repository),
    scope_repo: "ScopeRepository" = Depends(get_scope_repository),
    auth_code_repo: "AuthorizationCodeRepository" = Depends(get_authorization_code_repository),
) -> "AuthorizationService":
    """
    Get an instance of the AuthorizationService.

    Dependencies:
        - Client repository from get_client_repository
        - Scope repository from get_scope_repository
        - Authorization code repository from get_authorization_code_repository
    """
    from authly.oauth.authorization_service import AuthorizationService

    return AuthorizationService(client_repo, scope_repo, auth_code_repo)


async def get_client_service(
    client_repo: "ClientRepository" = Depends(get_client_repository),
    scope_repo: "ScopeRepository" = Depends(get_scope_repository),
    config: "AuthlyConfig" = Depends(get_config),
) -> "ClientService":
    """
    Get an instance of the ClientService.

    Dependencies:
        - Client repository from get_client_repository
        - Scope repository from get_scope_repository
        - Configuration from get_config
    """
    from authly.oauth.client_service import ClientService

    return ClientService(client_repo, scope_repo, config)


async def get_token_service_with_client(
    db_connection=Depends(get_database_connection),
    config: "AuthlyConfig" = Depends(get_config),
) -> "TokenService":
    """
    Get TokenService instance with client repository for ID token generation.

    Dependencies:
        - Database connection from resource manager
        - Configuration from get_config
    """
    from authly.oauth.client_repository import ClientRepository
    from authly.tokens.repository import TokenRepository
    from authly.tokens.service import TokenService

    token_repo = TokenRepository(db_connection)
    client_repo = ClientRepository(db_connection)

    return TokenService(token_repo, config, client_repo)


def _parse_basic_auth_header(authorization: str) -> tuple[str, str | None]:
    """
    Parse Basic Authentication header.

    Args:
        authorization: Authorization header value

    Returns:
        Tuple of (client_id, client_secret)

    Raises:
        HTTPException: If header format is invalid
    """
    try:
        if not authorization.startswith("Basic "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format",
                headers={"WWW-Authenticate": "Basic"},
            )

        # Decode base64 credentials
        encoded_credentials = authorization[6:]  # Remove "Basic " prefix
        decoded_bytes = base64.b64decode(encoded_credentials)
        decoded_str = decoded_bytes.decode("utf-8")

        # Split client_id:client_secret
        if ":" not in decoded_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials format",
                headers={"WWW-Authenticate": "Basic"},
            )

        client_id, client_secret = decoded_str.split(":", 1)

        if not client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client ID is required",
                headers={"WWW-Authenticate": "Basic"},
            )

        # Return None for empty secret (public clients)
        return client_id, client_secret if client_secret else None

    except UnicodeDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials encoding",
            headers={"WWW-Authenticate": "Basic"},
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials format",
            headers={"WWW-Authenticate": "Basic"},
        ) from e


async def get_current_client(
    request: Request,
    client_service: "ClientService" = Depends(get_client_service),
    basic_credentials: HTTPBasicCredentials | None = Depends(basic_auth_scheme),
) -> "OAuthClientModel":
    """
    Get the current authenticated OAuth client.

    Supports multiple authentication methods:
    - HTTP Basic Authentication (RFC 6749 Section 2.3.1)
    - Request body parameters (client_id, client_secret) - for compatibility
    - Public clients (client_id only)

    Dependencies:
        - HTTP request object
        - Client service from get_client_service
        - Optional HTTP Basic credentials

    Returns:
        OAuthClientModel: The authenticated client

    Raises:
        HTTPException: If client authentication fails
    """
    import time

    start_time = time.time()
    from authly.oauth.models import TokenEndpointAuthMethod

    client_id = None
    client_secret = None
    auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    # Try HTTP Basic Authentication first (preferred method)
    if basic_credentials:
        client_id = basic_credentials.username
        client_secret = basic_credentials.password if basic_credentials.password else None
        auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    # Fallback: Check Authorization header manually for edge cases
    elif "authorization" in request.headers:
        authorization = request.headers["authorization"]
        if authorization.lower().startswith("basic "):
            client_id, client_secret = _parse_basic_auth_header(authorization)
            auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

    # Fallback: Check request body for client credentials (form data or JSON)
    if not client_id:
        try:
            # Check content type header
            content_type = None
            if hasattr(request.headers, "get"):
                content_type = request.headers.get("content-type")
            elif "content-type" in request.headers:
                content_type = request.headers["content-type"]

            # Try to get form data
            if content_type == "application/x-www-form-urlencoded":
                form_data = await request.form()
                client_id = form_data.get("client_id")
                client_secret = form_data.get("client_secret")
                auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_POST

            # Try to get JSON data
            elif content_type == "application/json":
                json_data = await request.json()
                client_id = json_data.get("client_id")
                client_secret = json_data.get("client_secret")
                auth_method = TokenEndpointAuthMethod.CLIENT_SECRET_POST

        except Exception:
            # Ignore body parsing errors, continue with header-based auth
            pass

    # Check if we have at least a client_id
    if not client_id:
        # Track missing client credentials
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            metrics.track_client_authentication(
                "unknown", "missing_credentials", auth_method.value if auth_method else "unknown"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Handle public clients (no secret)
    if client_secret is None:
        auth_method = TokenEndpointAuthMethod.NONE

    # Authenticate the client
    try:
        authenticated_client = await client_service.authenticate_client(
            client_id=client_id, client_secret=client_secret, auth_method=auth_method
        )

        if not authenticated_client:
            # Track client authentication failure
            if METRICS_ENABLED and metrics:
                time.time() - start_time
                metrics.track_client_authentication(client_id, "authentication_failed", auth_method.value)
            logger.warning(f"Client authentication failed for client_id: {client_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

        # Track successful client authentication
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            metrics.track_client_authentication(client_id, "success", auth_method.value)

        return authenticated_client

    except HTTPException:
        # Re-raise HTTPExceptions (like authentication failures) as-is
        raise
    except Exception as e:
        # Track client authentication error
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            metrics.track_client_authentication(
                client_id or "unknown", "error", auth_method.value if auth_method else "unknown"
            )
        logger.error(f"Error during client authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Client authentication service error"
        ) from None
