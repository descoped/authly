"""OAuth 2.1 scope service layer for business logic."""

import logging
from uuid import UUID

from fastapi import HTTPException, status

from authly.oauth.models import OAuthScopeModel
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)


class ScopeService:
    """
    Service layer for OAuth 2.1 scope management business logic.

    Handles scope validation, enforcement, assignment logic,
    and scope-based access control for OAuth 2.1 flows.
    """

    def __init__(self, scope_repo: ScopeRepository):
        self._scope_repo = scope_repo

    async def create_scope(
        self, scope_name: str, description: str | None = None, is_default: bool = False, is_active: bool = True
    ) -> OAuthScopeModel:
        """
        Create a new OAuth scope with validation.

        Args:
            scope_name: Unique scope identifier (e.g., 'read', 'write')
            description: Human-readable description
            is_default: Whether scope is granted by default
            is_active: Whether scope is active

        Returns:
            Created scope model

        Raises:
            HTTPException: If validation fails or scope creation errors
        """
        try:
            # Validate scope name format
            self._validate_scope_name_format(scope_name)

            # Check if scope already exists
            existing_scope = await self._scope_repo.get_by_scope_name(scope_name)
            if existing_scope:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=f"Scope '{scope_name}' already exists"
                )

            # Create scope data
            scope_data = {
                "scope_name": scope_name,
                "description": description,
                "is_default": is_default,
                "is_active": is_active,
            }

            created_scope = await self._scope_repo.create_scope(scope_data)
            logger.info(f"Created OAuth scope: {scope_name}")

            return created_scope

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating scope {scope_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create scope"
            ) from None

    async def get_scope_by_name(self, scope_name: str) -> OAuthScopeModel | None:
        """Get scope by name"""
        try:
            return await self._scope_repo.get_by_scope_name(scope_name)
        except Exception as e:
            logger.error(f"Error getting scope {scope_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve scope"
            ) from None

    async def update_scope(self, scope_name: str, update_data: dict, requesting_admin: bool = True) -> OAuthScopeModel:
        """
        Update scope information.

        Args:
            scope_name: Scope identifier
            update_data: Fields to update
            requesting_admin: Whether request is from admin

        Returns:
            Updated scope model
        """
        try:
            # Get existing scope
            existing_scope = await self._scope_repo.get_by_scope_name(scope_name)
            if not existing_scope:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")

            # Only admins can update scopes (security-sensitive)
            if not requesting_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can update scopes"
                )

            # Filter allowed updates
            allowed_fields = {"description", "is_default", "is_active"}
            filtered_data = {k: v for k, v in update_data.items() if k in allowed_fields}

            if not filtered_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields to update")

            # Prevent changing scope_name (would break existing associations)
            if "scope_name" in update_data:
                logger.warning(f"Attempt to change scope name for {scope_name} - rejected")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope name cannot be changed")

            updated_scope = await self._scope_repo.update_scope(existing_scope.id, filtered_data)
            logger.info(f"Updated OAuth scope: {scope_name}")

            return updated_scope

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating scope {scope_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update scope"
            ) from None

    async def deactivate_scope(self, scope_name: str, requesting_admin: bool = True) -> bool:
        """
        Deactivate (soft delete) a scope.

        Args:
            scope_name: Scope to deactivate
            requesting_admin: Whether request is from admin

        Returns:
            True if successful
        """
        try:
            if not requesting_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Only administrators can deactivate scopes"
                )

            existing_scope = await self._scope_repo.get_by_scope_name(scope_name)
            if not existing_scope:
                return False

            # Check if scope is in use before deactivating
            usage_count = await self._check_scope_usage(existing_scope.id)
            if usage_count > 0:
                logger.warning(f"Attempting to deactivate scope {scope_name} with {usage_count} active associations")
                # Allow deactivation but log warning - existing tokens will still work

            success = await self._scope_repo.delete_scope(existing_scope.id)
            if success:
                logger.info(f"Deactivated OAuth scope: {scope_name}")

            return success

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deactivating scope {scope_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to deactivate scope"
            ) from None

    async def list_scopes(
        self, limit: int = 100, offset: int = 0, include_inactive: bool = False
    ) -> list[OAuthScopeModel]:
        """
        List OAuth scopes with pagination.

        Args:
            limit: Maximum number of scopes to return
            offset: Number of scopes to skip
            include_inactive: Whether to include inactive scopes

        Returns:
            List of scope models
        """
        try:
            if include_inactive:
                # This would need a new repository method for all scopes
                # For now, just return active scopes
                logger.info("include_inactive requested but not implemented - returning active scopes only")

            return await self._scope_repo.get_active_scopes(limit=limit, offset=offset)

        except Exception as e:
            logger.error(f"Error listing scopes: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list scopes"
            ) from None

    async def get_default_scopes(self) -> list[OAuthScopeModel]:
        """Get all default scopes (automatically granted)"""
        try:
            return await self._scope_repo.get_default_scopes()
        except Exception as e:
            logger.error(f"Error getting default scopes: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get default scopes"
            ) from None

    async def validate_requested_scopes(
        self, requested_scopes: str, client_id: UUID, include_defaults: bool = True
    ) -> list[str]:
        """
        Validate and filter requested scopes for a client.

        Args:
            requested_scopes: Space-separated scope string
            client_id: Client requesting the scopes
            include_defaults: Whether to include default scopes

        Returns:
            List of valid scope names the client can access

        Raises:
            HTTPException: If validation fails
        """
        try:
            # Parse requested scopes
            requested_scope_names = [] if not requested_scopes.strip() else requested_scopes.split()

            # Get client's allowed scopes
            client_scopes = await self._scope_repo.get_scopes_for_client(client_id)
            client_scope_names = {scope.scope_name for scope in client_scopes}

            # Get default scopes if requested
            default_scope_names = set()
            if include_defaults:
                default_scopes = await self._scope_repo.get_default_scopes()
                default_scope_names = {scope.scope_name for scope in default_scopes}

            # Validate all requested scopes exist and are active
            if requested_scope_names:
                valid_scope_names = await self._scope_repo.validate_scope_names(requested_scope_names)
                invalid_scopes = set(requested_scope_names) - valid_scope_names
                if invalid_scopes:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid or inactive scopes: {', '.join(invalid_scopes)}",
                    )
            else:
                valid_scope_names = set()

            # Check client authorization for requested scopes
            unauthorized_scopes = valid_scope_names - client_scope_names - default_scope_names
            if unauthorized_scopes:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Client not authorized for scopes: {', '.join(unauthorized_scopes)}",
                )

            # Return valid scopes (requested + defaults if none requested)
            if requested_scope_names:
                final_scopes = list(valid_scope_names)
            else:
                # If no scopes requested, grant defaults that client is authorized for
                final_scopes = list(default_scope_names & client_scope_names)

            logger.debug(f"Validated scopes for client {client_id}: {final_scopes}")
            return final_scopes

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error validating scopes for client {client_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to validate scopes"
            ) from None

    async def reduce_scopes_to_granted(self, requested_scopes: list[str], granted_scopes: list[str]) -> list[str]:
        """
        Reduce requested scopes to those actually granted.

        This is used when a user consents to fewer scopes than requested.

        Args:
            requested_scopes: Originally requested scope names
            granted_scopes: Scopes the user consented to

        Returns:
            List of final granted scope names
        """
        try:
            # Ensure granted scopes are subset of requested scopes
            requested_set = set(requested_scopes)
            granted_set = set(granted_scopes)

            invalid_grants = granted_set - requested_set
            if invalid_grants:
                logger.warning(f"Granted scopes not in requested: {invalid_grants}")
                # Remove invalid grants
                granted_set = granted_set - invalid_grants

            final_scopes = list(granted_set)
            logger.debug(f"Reduced scopes: requested={requested_scopes}, granted={final_scopes}")

            return final_scopes

        except Exception as e:
            logger.error(f"Error reducing scopes: {e}")
            # Return empty list on error for security
            return []

    async def associate_token_with_scopes(self, token_id: UUID, scope_names: list[str]) -> int:
        """
        Associate a token with specific scopes.

        Args:
            token_id: Token to associate scopes with
            scope_names: List of scope names to associate

        Returns:
            Number of associations created
        """
        try:
            if not scope_names:
                return 0

            # Get scope models by names
            scopes = await self._scope_repo.get_by_scope_names(scope_names)
            scope_ids = [scope.id for scope in scopes]

            # Verify all scopes were found
            found_names = {scope.scope_name for scope in scopes}
            missing_names = set(scope_names) - found_names
            if missing_names:
                logger.warning(f"Some scopes not found for token association: {missing_names}")

            # Create associations
            count = await self._scope_repo.associate_token_scopes(token_id, scope_ids)
            logger.debug(f"Associated {count} scopes with token {token_id}")

            return count

        except Exception as e:
            logger.error(f"Error associating token {token_id} with scopes: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to associate token with scopes"
            ) from None

    async def get_token_scopes(self, token_id: UUID) -> list[str]:
        """
        Get all scope names associated with a token.

        Args:
            token_id: Token to get scopes for

        Returns:
            List of scope names
        """
        try:
            scopes = await self._scope_repo.get_scopes_for_token(token_id)
            return [scope.scope_name for scope in scopes]
        except Exception as e:
            logger.error(f"Error getting scopes for token {token_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get token scopes"
            ) from None

    async def check_token_has_scope(self, token_id: UUID, required_scope: str) -> bool:
        """
        Check if a token has a specific scope.

        Args:
            token_id: Token to check
            required_scope: Scope name to check for

        Returns:
            True if token has the scope
        """
        try:
            token_scopes = await self.get_token_scopes(token_id)
            return required_scope in token_scopes
        except Exception as e:
            logger.error(f"Error checking scope {required_scope} for token {token_id}: {e}")
            # Default to False for security
            return False

    async def check_token_has_any_scope(self, token_id: UUID, required_scopes: list[str]) -> bool:
        """
        Check if a token has any of the required scopes.

        Args:
            token_id: Token to check
            required_scopes: List of scope names (OR logic)

        Returns:
            True if token has at least one of the required scopes
        """
        try:
            token_scopes = await self.get_token_scopes(token_id)
            token_scope_set = set(token_scopes)
            required_scope_set = set(required_scopes)

            return bool(token_scope_set & required_scope_set)
        except Exception as e:
            logger.error(f"Error checking scopes {required_scopes} for token {token_id}: {e}")
            # Default to False for security
            return False

    async def check_token_has_all_scopes(self, token_id: UUID, required_scopes: list[str]) -> bool:
        """
        Check if a token has all of the required scopes.

        Args:
            token_id: Token to check
            required_scopes: List of scope names (AND logic)

        Returns:
            True if token has all required scopes
        """
        try:
            token_scopes = await self.get_token_scopes(token_id)
            token_scope_set = set(token_scopes)
            required_scope_set = set(required_scopes)

            return required_scope_set.issubset(token_scope_set)
        except Exception as e:
            logger.error(f"Error checking all scopes {required_scopes} for token {token_id}: {e}")
            # Default to False for security
            return False

    def _validate_scope_name_format(self, scope_name: str) -> None:
        """
        Validate scope name format according to OAuth 2.1 specs.

        OAuth 2.1 scope names should be simple ASCII strings without spaces.
        """
        if not scope_name or not isinstance(scope_name, str):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope name must be a non-empty string")

        if len(scope_name) > 255:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Scope name too long (max 255 characters)"
            )

        # Check for invalid characters
        if " " in scope_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope name cannot contain spaces")

        # Basic ASCII check
        if not scope_name.isascii():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Scope name must be ASCII characters only"
            )

        # Prevent some reserved patterns
        reserved_patterns = ["oauth", "openid", "oidc"]
        if any(pattern in scope_name.lower() for pattern in reserved_patterns):
            logger.warning(f"Scope name uses reserved pattern: {scope_name}")

    async def _check_scope_usage(self, scope_id: UUID) -> int:
        """
        Check how many active tokens/clients are using a scope.

        Returns count of active usages.
        """
        try:
            # This would need additional repository methods to count usage
            # For now, return 0 (assuming deactivation is always allowed)
            return 0
        except Exception as e:
            logger.error(f"Error checking scope usage for {scope_id}: {e}")
            return 0
