"""
Admin API Client for HTTP-based admin operations.

This module provides an HTTP client for all admin API endpoints, supporting
authentication, token management, and secure credential storage.
"""

import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel

from authly.oauth.models import (
    OAuthClientCreateRequest,
    OAuthClientCredentialsResponse,
    OAuthClientModel,
    OAuthScopeModel,
)

logger = logging.getLogger(__name__)


class AdminAPIError(Exception):
    """Custom exception for Admin API errors with user-friendly messages."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)


class TokenInfo(BaseModel):
    """Token information with expiration tracking."""

    access_token: str
    refresh_token: str | None = None
    expires_at: datetime
    token_type: str = "Bearer"
    scope: str | None = None


class AdminAPIClient:
    """HTTP client for Authly admin API operations."""

    def __init__(self, base_url: str, token_file: Path | None = None, timeout: float = 30.0, verify_ssl: bool = True):
        """
        Initialize the admin API client.

        Args:
            base_url: Base URL of the Authly API (e.g., "http://localhost:8000")
            token_file: Path to store tokens (defaults to ~/.authly/tokens.json)
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Token storage
        if token_file is None:
            config_dir = Path.home() / ".authly"
            config_dir.mkdir(exist_ok=True)
            self.token_file = config_dir / "tokens.json"
        else:
            self.token_file = Path(token_file)
            self.token_file.parent.mkdir(parents=True, exist_ok=True)

        # HTTP client
        self.client = httpx.AsyncClient(timeout=timeout, verify=verify_ssl, follow_redirects=True)

        # Current token info
        self._token_info: TokenInfo | None = None
        self._load_tokens()

    def _load_tokens(self) -> None:
        """Load tokens from file if they exist."""
        if self.token_file.exists():
            try:
                with open(self.token_file) as f:
                    data = json.load(f)
                    # Convert expires_at string to datetime
                    if "expires_at" in data:
                        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
                    self._token_info = TokenInfo(**data)
                    logger.debug("Loaded tokens from %s", self.token_file)
            except Exception as e:
                logger.warning("Failed to load tokens: %s", e)
                self._token_info = None

    def _save_tokens(self) -> None:
        """Save tokens to file."""
        if self._token_info:
            try:
                data = self._token_info.model_dump()
                # Convert datetime to ISO format string
                if "expires_at" in data:
                    data["expires_at"] = data["expires_at"].isoformat()

                # Write with restricted permissions
                with open(self.token_file, "w") as f:
                    json.dump(data, f, indent=2)

                # Set file permissions to 600 (read/write for owner only)
                os.chmod(self.token_file, 0o600)
                logger.debug("Saved tokens to %s", self.token_file)
            except Exception as e:
                logger.error("Failed to save tokens: %s", e)

    def _clear_tokens(self) -> None:
        """Clear stored tokens."""
        self._token_info = None
        if self.token_file.exists():
            try:
                self.token_file.unlink()
                logger.debug("Cleared tokens from %s", self.token_file)
            except Exception as e:
                logger.warning("Failed to delete token file: %s", e)

    @property
    def is_authenticated(self) -> bool:
        """Check if client has valid authentication."""
        if not self._token_info:
            return False

        # Check if token is expired (with 1 minute buffer)
        now = datetime.now(UTC)
        buffer = timedelta(minutes=1)
        return now < (self._token_info.expires_at - buffer)

    async def _request(
        self,
        method: str,
        path: str,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        form_data: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make an HTTP request to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (will be joined with base_url)
            json_data: JSON data for request body
            params: Query parameters
            authenticated: Whether to include authentication header
            form_data: Form data for request body (for OAuth endpoints)

        Returns:
            HTTP response

        Raises:
            httpx.HTTPStatusError: If request fails
        """
        url = urljoin(self.base_url, path)

        headers = {}
        if authenticated and self._token_info:
            headers["Authorization"] = f"{self._token_info.token_type} {self._token_info.access_token}"

        # Use form data if provided, otherwise use json data
        if form_data is not None:
            response = await self.client.request(method=method, url=url, data=form_data, params=params, headers=headers)
        else:
            response = await self.client.request(method=method, url=url, json=json_data, params=params, headers=headers)

        # Handle HTTP errors with meaningful messages
        if response.status_code >= 400:
            await self._handle_api_error(response, method, path)

        return response

    async def _handle_api_error(self, response: httpx.Response, method: str, path: str) -> None:
        """Handle API errors and raise meaningful exceptions."""
        status_code = response.status_code

        # Try to get error details from response body
        try:
            error_data = response.json()
            # Check for OAuth error format first (from token endpoint)
            if "error" in error_data:
                error_message = error_data.get("error_description", error_data.get("error", ""))
            else:
                # Standard FastAPI error format
                error_message = error_data.get("detail", "")
                if isinstance(error_message, list) and error_message:
                    # Handle FastAPI validation errors
                    error_message = error_message[0].get("msg", str(error_message[0]))
                elif not error_message:
                    error_message = error_data.get("message", "")
        except (ValueError, KeyError):
            error_message = response.text or ""

        # Provide context-specific error messages
        if status_code == 400:
            # Check if this is an authentication failure from OAuth token endpoint
            if "oauth/token" in path.lower() and "incorrect username or password" in error_message.lower():
                raise AdminAPIError(
                    "Authentication failed. Please login again with 'python -m authly admin login'.", status_code=401
                )
            elif "scope" in path.lower():
                if "already exists" in error_message.lower() or "duplicate" in error_message.lower():
                    # Extract scope name from error or request data
                    scope_name = self._extract_scope_name_from_error(error_message, response)
                    raise AdminAPIError(
                        f"Scope '{scope_name}' already exists. Please choose a different name.", status_code=400
                    )
                elif "invalid" in error_message.lower():
                    raise AdminAPIError(f"Invalid scope data: {error_message}", status_code=400)
                else:
                    raise AdminAPIError(
                        f"Invalid scope request: {error_message or 'Please check your input and try again.'}",
                        status_code=400,
                    )

            elif "client" in path.lower():
                if "already exists" in error_message.lower() or "duplicate" in error_message.lower():
                    client_name = self._extract_client_name_from_error(error_message, response)
                    raise AdminAPIError(
                        f"Client '{client_name}' already exists. Please choose a different name.", status_code=400
                    )
                elif "redirect" in error_message.lower():
                    raise AdminAPIError(f"Invalid redirect URI: {error_message}", status_code=400)
                else:
                    raise AdminAPIError(
                        f"Invalid client request: {error_message or 'Please check your input and try again.'}",
                        status_code=400,
                    )

            else:
                raise AdminAPIError(
                    f"Bad request: {error_message or 'Please check your input and try again.'}", status_code=400
                )

        elif status_code == 401:
            raise AdminAPIError(
                "Authentication failed. Please login again with 'python -m authly admin login'.", status_code=401
            )

        elif status_code == 403:
            raise AdminAPIError("Access denied. You don't have permission to perform this operation.", status_code=403)

        elif status_code == 404:
            if "scope" in path.lower():
                raise AdminAPIError("Scope not found.", status_code=404)
            elif "client" in path.lower():
                raise AdminAPIError("Client not found.", status_code=404)
            else:
                raise AdminAPIError("Resource not found.", status_code=404)

        elif status_code == 409:
            raise AdminAPIError(
                f"Resource conflict: {error_message or 'The resource already exists.'}", status_code=409
            )

        elif status_code >= 500:
            raise AdminAPIError(
                f"Server error: {error_message or 'The server encountered an error. Please try again later.'}",
                status_code=status_code,
            )

        else:
            # Fallback for other status codes
            raise AdminAPIError(f"Request failed: {error_message or f'HTTP {status_code}'}", status_code=status_code)

    def _extract_scope_name_from_error(self, error_message: str, response: httpx.Response) -> str:
        """Extract scope name from error message or request."""
        # Try to get scope name from error message
        if "'" in error_message:
            parts = error_message.split("'")
            if len(parts) >= 2:
                return parts[1]

        # Fallback: try to get from request data
        try:
            if hasattr(response, "request") and response.request.content:
                request_data = json.loads(response.request.content)
                return request_data.get("scope_name", "unknown")
        except Exception:
            pass

        return "unknown"

    def _extract_client_name_from_error(self, error_message: str, response: httpx.Response) -> str:
        """Extract client name from error message or request."""
        # Try to get client name from error message
        if "'" in error_message:
            parts = error_message.split("'")
            if len(parts) >= 2:
                return parts[1]

        # Fallback: try to get from request data
        try:
            if hasattr(response, "request") and response.request.content:
                request_data = json.loads(response.request.content)
                return request_data.get("client_name", "unknown")
        except Exception:
            pass

        return "unknown"

    async def login(self, username: str, password: str, scope: str | None = None) -> TokenInfo:
        """
        Authenticate with username and password.

        Args:
            username: Admin username
            password: Admin password
            scope: Optional OAuth scopes to request

        Returns:
            Token information

        Raises:
            httpx.HTTPStatusError: If authentication fails
        """
        # Use Resource Owner Password Credentials flow
        data = {"grant_type": "password", "username": username, "password": password}

        if scope:
            data["scope"] = scope

        response = await self._request("POST", "/api/v1/oauth/token", form_data=data, authenticated=False)

        token_data = response.json()

        # Calculate expiration time
        expires_in = token_data.get("expires_in", 3600)  # Default 1 hour
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

        self._token_info = TokenInfo(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope"),
        )

        self._save_tokens()
        logger.info("Successfully authenticated as %s", username)

        return self._token_info

    async def logout(self) -> None:
        """
        Logout and clear stored tokens.

        Attempts to revoke tokens on server if possible.
        """
        if self._token_info and self._token_info.access_token:
            try:
                # Try to revoke the access token
                await self._request(
                    "POST",
                    "/api/v1/oauth/revoke",
                    json_data={"token": self._token_info.access_token, "token_type_hint": "access_token"},
                )
                logger.info("Successfully revoked access token")
            except Exception as e:
                logger.warning("Failed to revoke access token: %s", e)

            if self._token_info.refresh_token:
                try:
                    # Try to revoke the refresh token
                    await self._request(
                        "POST",
                        "/api/v1/oauth/revoke",
                        json_data={"token": self._token_info.refresh_token, "token_type_hint": "refresh_token"},
                    )
                    logger.info("Successfully revoked refresh token")
                except Exception as e:
                    logger.warning("Failed to revoke refresh token: %s", e)

        # Clear local tokens
        self._clear_tokens()
        logger.info("Logged out and cleared tokens")

    async def refresh_token(self) -> TokenInfo:
        """
        Refresh the access token using the refresh token.

        Returns:
            New token information

        Raises:
            ValueError: If no refresh token is available
            httpx.HTTPStatusError: If refresh fails
        """
        if not self._token_info or not self._token_info.refresh_token:
            raise ValueError("No refresh token available")

        response = await self._request(
            "POST",
            "/api/v1/oauth/refresh",
            json_data={"grant_type": "refresh_token", "refresh_token": self._token_info.refresh_token},
            authenticated=False,
        )

        token_data = response.json()

        # Calculate expiration time
        expires_in = token_data.get("expires_in", 3600)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

        self._token_info = TokenInfo(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token", self._token_info.refresh_token),
            expires_at=expires_at,
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope", self._token_info.scope),
        )

        self._save_tokens()
        logger.info("Successfully refreshed token")

        return self._token_info

    async def ensure_authenticated(self) -> None:
        """
        Ensure the client is authenticated, refreshing token if needed.

        Raises:
            ValueError: If not authenticated and cannot refresh
        """
        if not self._token_info:
            raise ValueError("Not authenticated. Please login first.")

        if not self.is_authenticated:
            # Try to refresh
            if self._token_info.refresh_token:
                try:
                    await self.refresh_token()
                except Exception as e:
                    raise ValueError(f"Failed to refresh token: {e}") from e
            else:
                raise ValueError("Token expired and no refresh token available. Please login again.")

    # Admin API Methods

    async def get_status(self) -> dict[str, Any]:
        """Get admin API status and system information."""
        await self.ensure_authenticated()
        response = await self._request("GET", "/admin/status")
        return response.json()

    async def get_health(self) -> dict[str, str]:
        """Get admin API health check."""
        # Health check doesn't require authentication
        response = await self._request("GET", "/admin/health", authenticated=False)
        return response.json()

    # Client Management

    async def list_clients(self, active_only: bool = True, limit: int = 100, offset: int = 0) -> list[OAuthClientModel]:
        """List OAuth clients."""
        await self.ensure_authenticated()

        response = await self._request(
            "GET", "/admin/clients", params={"active_only": active_only, "limit": limit, "offset": offset}
        )

        clients_data = response.json()
        return [OAuthClientModel(**client) for client in clients_data]

    async def create_client(self, request: OAuthClientCreateRequest) -> tuple[OAuthClientModel, str | None]:
        """
        Create a new OAuth client.

        Returns:
            Tuple of (client, client_secret). client_secret is None for public clients.
        """
        await self.ensure_authenticated()

        response = await self._request("POST", "/admin/clients", json_data=request.model_dump())

        # Admin router returns OAuthClientCredentialsResponse directly
        data = response.json()

        # Convert to OAuthClientModel (the credentials response has fewer fields)
        # We need to fetch the full client details to get the complete model
        client_id = data["client_id"]
        client_secret = data.get("client_secret")

        # Get full client details
        full_client = await self.get_client(client_id)

        return full_client, client_secret

    async def get_client(self, client_id: str) -> OAuthClientModel:
        """Get OAuth client by ID."""
        await self.ensure_authenticated()

        response = await self._request("GET", f"/admin/clients/{client_id}")
        return OAuthClientModel(**response.json())

    async def update_client(self, client_id: str, update_data: dict[str, Any]) -> OAuthClientModel:
        """Update OAuth client."""
        await self.ensure_authenticated()

        response = await self._request("PUT", f"/admin/clients/{client_id}", json_data=update_data)

        return OAuthClientModel(**response.json())

    async def regenerate_client_secret(self, client_id: str) -> OAuthClientCredentialsResponse:
        """Regenerate client secret for confidential client."""
        await self.ensure_authenticated()

        response = await self._request("POST", f"/admin/clients/{client_id}/regenerate-secret")

        return OAuthClientCredentialsResponse(**response.json())

    async def delete_client(self, client_id: str) -> dict[str, str]:
        """Delete (deactivate) OAuth client."""
        await self.ensure_authenticated()

        response = await self._request("DELETE", f"/admin/clients/{client_id}")
        return response.json()

    # Scope Management

    async def list_scopes(self, active_only: bool = True, limit: int = 100, offset: int = 0) -> list[OAuthScopeModel]:
        """List OAuth scopes."""
        await self.ensure_authenticated()

        response = await self._request(
            "GET", "/admin/scopes", params={"active_only": active_only, "limit": limit, "offset": offset}
        )

        scopes_data = response.json()
        return [OAuthScopeModel(**scope) for scope in scopes_data]

    async def create_scope(self, name: str, description: str, is_default: bool = False) -> OAuthScopeModel:
        """Create a new OAuth scope."""
        await self.ensure_authenticated()

        response = await self._request(
            "POST",
            "/admin/scopes",
            json_data={
                "scope_name": name,  # Admin router expects 'scope_name'
                "description": description,
                "is_default": is_default,
            },
        )

        return OAuthScopeModel(**response.json())

    async def get_default_scopes(self) -> list[OAuthScopeModel]:
        """Get default OAuth scopes."""
        await self.ensure_authenticated()

        response = await self._request("GET", "/admin/scopes/defaults")
        scopes_data = response.json()
        return [OAuthScopeModel(**scope) for scope in scopes_data]

    async def get_scope(self, scope_name: str) -> OAuthScopeModel:
        """Get OAuth scope by name."""
        await self.ensure_authenticated()

        response = await self._request("GET", f"/admin/scopes/{scope_name}")
        return OAuthScopeModel(**response.json())

    async def update_scope(
        self,
        scope_name: str,
        description: str | None = None,
        is_default: bool | None = None,
        is_active: bool | None = None,
    ) -> OAuthScopeModel:
        """Update OAuth scope."""
        await self.ensure_authenticated()

        update_data = {}
        if description is not None:
            update_data["description"] = description
        if is_default is not None:
            update_data["is_default"] = is_default
        if is_active is not None:
            update_data["is_active"] = is_active

        response = await self._request("PUT", f"/admin/scopes/{scope_name}", json_data=update_data)

        return OAuthScopeModel(**response.json())

    async def delete_scope(self, scope_name: str) -> dict[str, str]:
        """Delete (deactivate) OAuth scope."""
        await self.ensure_authenticated()

        response = await self._request("DELETE", f"/admin/scopes/{scope_name}")
        return response.json()

    # User Management

    async def list_users(
        self, active_only: bool = True, admin_only: bool = False, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List users (admin users only for now)."""
        await self.ensure_authenticated()

        response = await self._request(
            "GET",
            "/admin/users",
            params={"active_only": active_only, "admin_only": admin_only, "limit": limit, "offset": offset},
        )

        return response.json()

    # Context Manager Support

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - close HTTP client."""
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
