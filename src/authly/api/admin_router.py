"""
Admin API Router for Authly authentication service.

This router provides authenticated admin endpoints that mirror the CLI operations,
enabling API-first administration of OAuth clients, scopes, and system management.

Authentication is handled through the OAuth 2.1 flow using /api/v1/oauth/token
with admin credentials. Admin users are identified by the is_admin flag and
have access to additional administrative operations.

Available endpoints:
- System status and health checks
- OAuth client management (CRUD operations)
- OAuth scope management (CRUD operations)
- OpenID Connect client configuration
- User management operations

Advanced admin features:
- Comprehensive user management
- OAuth client configuration
- OIDC settings management
"""

import logging
import math
from datetime import UTC
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from psycopg import AsyncConnection
from psycopg_toolkit import RecordNotFoundError

from authly.admin.cache import AdminCacheService
from authly.admin.errors import AdminValidationError
from authly.admin.models import (
    AdminSessionListResponse,
    AdminSessionResponse,
    AdminUserCreateRequest,
    AdminUserCreateResponse,
    AdminUserListResponse,
    AdminUserResponse,
    AdminUserUpdateRequest,
)
from authly.api.admin_dependencies import (
    require_admin_client_read,
    require_admin_client_write,
    require_admin_scope_read,
    require_admin_scope_write,
    require_admin_system_read,
    require_admin_user_read,
    require_admin_user_write,
)
from authly.api.users_dependencies import get_user_service
from authly.config import AuthlyConfig
from authly.core.backend_factory import BackendFactory
from authly.core.dependencies import get_config, get_database_connection, get_resource_manager
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import (
    OAuthClientCreateRequest,
    OAuthClientCredentialsResponse,
    OAuthClientModel,
    OAuthScopeModel,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.oauth.scope_service import ScopeService
from authly.users.models import UserModel
from authly.users.service import UserService

logger = logging.getLogger(__name__)

# Admin API Router
admin_router = APIRouter(prefix="/admin", tags=["admin"])


# Admin cache service dependency
async def get_admin_cache(
    resource_manager: AuthlyResourceManager = Depends(get_resource_manager), config: AuthlyConfig = Depends(get_config)
) -> AdminCacheService:
    """Get admin cache service with proper backend."""
    factory = BackendFactory(resource_manager)
    cache_backend = await factory.create_cache_backend()
    return AdminCacheService(cache_backend, config)


# ============================================================================
# SYSTEM MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/health")
async def admin_health():
    """Admin API health check endpoint."""
    return {"status": "healthy", "service": "authly-admin-api"}


@admin_router.get("/status")
async def get_system_status(
    conn: AsyncConnection = Depends(get_database_connection),
    config=Depends(get_config),
    _admin: UserModel = Depends(require_admin_system_read),
):
    """
    Get comprehensive system status and configuration.
    Mirrors the CLI 'status' command functionality.
    """
    try:
        # Test database connection
        result = await conn.execute("SELECT version();")
        db_version = await result.fetchone()
        db_status = {"connected": True, "version": db_version[0] if db_version else "Unknown"}
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        db_status = {"connected": False, "error": str(e)}

    # Get service statistics
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)

        clients = await client_repo.get_active_clients()
        scopes = await scope_repo.get_active_scopes()

        stats = {
            "oauth_clients": len(clients),
            "oauth_scopes": len(scopes),
            "active_clients": len([c for c in clients if c.is_active]),
            "active_scopes": len([s for s in scopes if s.is_active]),
        }
    except Exception as e:
        logger.error(f"Failed to get service statistics: {e}")
        stats = {"error": str(e)}

    # Get configuration info (non-sensitive)
    config_status = {
        "valid": True,
        "api_prefix": config.fastapi_api_version_prefix,
        "jwt_algorithm": config.algorithm,
        "access_token_expiry_minutes": config.access_token_expire_minutes,
        "refresh_token_expiry_days": config.refresh_token_expire_days,
    }

    return {
        "status": "operational",
        "database": db_status,
        "configuration": config_status,
        "statistics": stats,
        "timestamp": "2025-01-06T12:00:00Z",  # Will be replaced with actual timestamp
    }


@admin_router.get("/dashboard/stats")
async def get_admin_dashboard_stats(
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_system_read),
    cache_service: AdminCacheService = Depends(get_admin_cache),
    user_service: UserService = Depends(get_user_service),
):
    """
    Get cached dashboard statistics for admin overview.

    This endpoint provides aggregated statistics with caching to ensure
    fast dashboard loading. Statistics include:
    - Total users, active users, admin users
    - Unverified users requiring attention
    - Recent activity metrics

    Cache TTL: 60 seconds
    Requires admin:system:read scope.
    """
    # Try to get from cache first
    cached_stats = await cache_service.get_dashboard_stats()
    if cached_stats:
        logger.debug("Returning cached dashboard stats")
        return cached_stats

    # If not cached, compute stats
    try:
        from authly.users.repository import UserRepository

        user_repo = UserRepository(conn)

        # Get various counts (these could be optimized with a single query)
        total_users = await user_repo.count_filtered({})
        active_users = await user_repo.count_filtered({"is_active": True})
        admin_users = await user_repo.count_filtered({"is_admin": True})
        unverified_users = await user_repo.count_filtered({"is_verified": False})
        password_change_required = await user_repo.count_filtered({"requires_password_change": True})

        # Get recent activity stats
        from datetime import datetime, timedelta

        now = datetime.now(UTC)
        last_24h = now - timedelta(days=1)
        last_7d = now - timedelta(days=7)

        recent_signups_24h = await user_repo.count_filtered({"created_after": last_24h})
        recent_signups_7d = await user_repo.count_filtered({"created_after": last_7d})

        stats = {
            "users": {
                "total": total_users,
                "active": active_users,
                "inactive": total_users - active_users,
                "admins": admin_users,
                "unverified": unverified_users,
                "requires_password_change": password_change_required,
            },
            "activity": {
                "new_users_24h": recent_signups_24h,
                "new_users_7d": recent_signups_7d,
            },
            "timestamp": now.isoformat(),
        }

        # Cache the stats
        await cache_service.set_dashboard_stats(stats)

        logger.info("Computed and cached dashboard stats")
        return stats

    except Exception as e:
        logger.error(f"Failed to compute dashboard stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve dashboard statistics"
        ) from None


# ============================================================================
# OAUTH CLIENT MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/clients")
async def list_clients(
    limit: int = 100,
    offset: int = 0,
    include_inactive: bool = False,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_client_read),
) -> list[OAuthClientModel]:
    """
    List OAuth clients with pagination.
    Mirrors the CLI 'client list' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        clients = await client_repo.get_active_clients(limit=limit, offset=offset)

        if not include_inactive:
            clients = [client for client in clients if client.is_active]

        return clients
    except Exception as e:
        logger.error(f"Failed to list clients: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to list clients: {e!s}"
        ) from None


@admin_router.post("/clients")
async def create_client(
    client_request: OAuthClientCreateRequest,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> OAuthClientCredentialsResponse:
    """
    Create a new OAuth client.
    Mirrors the CLI 'client create' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, config)

        result = await client_service.create_client(client_request)

        logger.info(f"Created OAuth client: {result.client_id}")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create client: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create client: {e!s}"
        ) from None


@admin_router.get("/clients/{client_id}")
async def get_client(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_read),
) -> dict:
    """
    Get detailed information about a specific client.
    Mirrors the CLI 'client show' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, config)

        client = await client_service.get_client_by_id(client_id)
        if not client:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Client not found: {client_id}")

        # Get client scopes
        scopes = await client_service.get_client_scopes(client_id)

        # Return client with assigned scopes
        client_data = client.model_dump()
        client_data["assigned_scopes"] = scopes

        return client_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get client: {e!s}"
        ) from None


@admin_router.put("/clients/{client_id}")
async def update_client(
    client_id: str,
    update_data: dict,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> OAuthClientModel:
    """
    Update client information.
    Mirrors the CLI 'client update' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, config)

        updated_client = await client_service.update_client(client_id, update_data)

        logger.info(f"Updated OAuth client: {client_id}")
        return updated_client

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update client: {e!s}"
        ) from None


@admin_router.post("/clients/{client_id}/regenerate-secret")
async def regenerate_client_secret(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> dict:
    """
    Regenerate client secret for confidential clients.
    Mirrors the CLI 'client regenerate-secret' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, config)

        new_secret = await client_service.regenerate_client_secret(client_id)

        if new_secret:
            logger.info(f"Regenerated secret for client: {client_id}")
            return {
                "client_id": client_id,
                "new_secret": new_secret,
                "message": "Client secret regenerated successfully",
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot regenerate secret (client not found or is public client)",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to regenerate secret for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to regenerate client secret: {e!s}"
        ) from None


@admin_router.delete("/clients/{client_id}")
async def delete_client(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> dict:
    """
    Delete (deactivate) a client.
    Mirrors the CLI 'client delete' command functionality.
    """
    try:
        client_repo = ClientRepository(conn)
        scope_repo = ScopeRepository(conn)
        client_service = ClientService(client_repo, scope_repo, config)

        success = await client_service.deactivate_client(client_id)

        if success:
            logger.info(f"Deactivated OAuth client: {client_id}")
            return {"client_id": client_id, "message": "Client deactivated successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete client: {e!s}"
        ) from None


# ============================================================================
# OIDC CLIENT MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/clients/{client_id}/oidc")
async def get_client_oidc_settings(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_client_read),
) -> dict:
    """
    Get OpenID Connect specific settings for a client.
    """
    try:
        client_repo = ClientRepository(conn)
        client = await client_repo.get_by_client_id(client_id)

        if not client:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

        # Return OIDC-specific settings
        oidc_settings = {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "is_oidc_client": client.is_oidc_client(),
            "oidc_scopes": client.get_oidc_scopes(),
            "id_token_signed_response_alg": client.id_token_signed_response_alg,
            "subject_type": client.subject_type,
            "sector_identifier_uri": client.sector_identifier_uri,
            "require_auth_time": client.require_auth_time,
            "default_max_age": client.default_max_age,
            "initiate_login_uri": client.initiate_login_uri,
            "request_uris": client.request_uris,
            "application_type": client.application_type,
            "contacts": client.contacts,
        }

        return oidc_settings

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get OIDC settings for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get OIDC settings: {e!s}"
        ) from None


@admin_router.put("/clients/{client_id}/oidc")
async def update_client_oidc_settings(
    client_id: str,
    oidc_settings: dict,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_client_write),
) -> dict:
    """
    Update OpenID Connect specific settings for a client.
    """
    try:
        client_repo = ClientRepository(conn)
        client = await client_repo.get_by_client_id(client_id)

        if not client:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

        # Validate and prepare OIDC update data
        valid_oidc_fields = {
            "id_token_signed_response_alg",
            "subject_type",
            "sector_identifier_uri",
            "require_auth_time",
            "default_max_age",
            "initiate_login_uri",
            "request_uris",
            "application_type",
            "contacts",
        }

        update_data = {}
        for field, value in oidc_settings.items():
            if field in valid_oidc_fields:
                update_data[field] = value

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="No valid OIDC fields provided for update"
            )

        # Update client with OIDC settings
        await client_repo.update_client(client.id, update_data)

        logger.info(f"Updated OIDC settings for client: {client_id}")

        # Return updated OIDC settings
        return {
            "client_id": client_id,
            "message": "OIDC settings updated successfully",
            "updated_fields": list(update_data.keys()),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update OIDC settings for client {client_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update OIDC settings: {e!s}"
        ) from None


@admin_router.get("/clients/oidc/algorithms")
async def get_supported_oidc_algorithms(_admin: UserModel = Depends(require_admin_client_read)) -> dict:
    """
    Get list of supported OpenID Connect ID token signing algorithms.
    """
    return {
        "supported_algorithms": [
            {"algorithm": "RS256", "description": "RSA using SHA-256 (recommended)", "default": True},
            {"algorithm": "HS256", "description": "HMAC using SHA-256", "default": False},
            {"algorithm": "ES256", "description": "ECDSA using P-256 and SHA-256", "default": False},
        ],
        "subject_types": [
            {"type": "public", "description": "Same subject identifier for all clients", "default": True},
            {"type": "pairwise", "description": "Different subject identifier per client", "default": False},
        ],
    }


# ============================================================================
# OAUTH SCOPE MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/scopes")
async def list_scopes(
    limit: int = 100,
    offset: int = 0,
    include_inactive: bool = False,
    default_only: bool = False,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_read),
) -> list[OAuthScopeModel]:
    """
    List OAuth scopes with pagination and filtering.
    Mirrors the CLI 'scope list' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        if default_only:
            scopes = await scope_service.get_default_scopes()
        else:
            scopes = await scope_service.list_scopes(limit=limit, offset=offset, include_inactive=include_inactive)

        return scopes

    except Exception as e:
        logger.error(f"Failed to list scopes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to list scopes: {e!s}"
        ) from None


@admin_router.post("/scopes")
async def create_scope(
    scope_data: dict,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_write),
) -> OAuthScopeModel:
    """
    Create a new OAuth scope.
    Mirrors the CLI 'scope create' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        result = await scope_service.create_scope(
            scope_data["scope_name"],
            scope_data.get("description"),
            scope_data.get("is_default", False),
            scope_data.get("is_active", True),
        )

        logger.info(f"Created OAuth scope: {result.scope_name}")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create scope: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create scope: {e!s}"
        ) from None


@admin_router.get("/scopes/defaults")
async def get_default_scopes(
    conn: AsyncConnection = Depends(get_database_connection), _admin: UserModel = Depends(require_admin_scope_read)
) -> list[OAuthScopeModel]:
    """
    Get all default scopes.
    Mirrors the CLI 'scope defaults' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        default_scopes = await scope_service.get_default_scopes()
        return default_scopes

    except Exception as e:
        logger.error(f"Failed to get default scopes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get default scopes: {e!s}"
        ) from None


@admin_router.get("/scopes/{scope_name}")
async def get_scope(
    scope_name: str,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_read),
) -> OAuthScopeModel:
    """
    Get detailed information about a specific scope.
    Mirrors the CLI 'scope show' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        scope = await scope_service.get_scope_by_name(scope_name)

        if not scope:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scope not found: {scope_name}")

        return scope

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scope {scope_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get scope: {e!s}"
        ) from None


@admin_router.put("/scopes/{scope_name}")
async def update_scope(
    scope_name: str,
    update_data: dict,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_write),
) -> OAuthScopeModel:
    """
    Update scope information.
    Mirrors the CLI 'scope update' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        updated_scope = await scope_service.update_scope(scope_name, update_data, requesting_admin=True)

        logger.info(f"Updated OAuth scope: {scope_name}")
        return updated_scope

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update scope {scope_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update scope: {e!s}"
        ) from None


@admin_router.delete("/scopes/{scope_name}")
async def delete_scope(
    scope_name: str,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_write),
) -> dict:
    """
    Delete (deactivate) a scope.
    Mirrors the CLI 'scope delete' command functionality.
    """
    try:
        scope_repo = ScopeRepository(conn)
        scope_service = ScopeService(scope_repo)

        success = await scope_service.deactivate_scope(scope_name, requesting_admin=True)

        if success:
            logger.info(f"Deactivated OAuth scope: {scope_name}")
            return {"scope_name": scope_name, "message": "Scope deactivated successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found or cannot be deactivated"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scope {scope_name}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete scope: {e!s}"
        ) from None


# ============================================================================
# USER MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/users", response_model=AdminUserListResponse)
async def get_admin_users(
    # Pagination parameters
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(25, ge=1, le=100, description="Number of users to return (max 100)"),
    # Text search filters
    username: str | None = Query(None, description="Filter by username (partial match)"),
    email: str | None = Query(None, description="Filter by email (partial match)"),
    given_name: str | None = Query(None, description="Filter by given name (partial match)"),
    family_name: str | None = Query(None, description="Filter by family name (partial match)"),
    # Boolean status filters
    is_active: bool | None = Query(None, description="Filter by active status"),
    is_verified: bool | None = Query(None, description="Filter by verification status"),
    is_admin: bool | None = Query(None, description="Filter by admin status"),
    requires_password_change: bool | None = Query(None, description="Filter by password change requirement"),
    # Date range filters (ISO format: YYYY-MM-DDTHH:MM:SS)
    created_after: str | None = Query(None, description="Filter users created after this date (ISO format)"),
    created_before: str | None = Query(None, description="Filter users created before this date (ISO format)"),
    last_login_after: str | None = Query(None, description="Filter users with last login after this date (ISO format)"),
    last_login_before: str | None = Query(
        None, description="Filter users with last login before this date (ISO format)"
    ),
    # OIDC profile filters
    locale: str | None = Query(None, description="Filter by locale"),
    zoneinfo: str | None = Query(None, description="Filter by timezone"),
    # Dependencies
    admin_user: UserModel = Depends(require_admin_user_read),
    user_service: UserService = Depends(get_user_service),
    cache_service: AdminCacheService = Depends(get_admin_cache),
):
    """
    Get paginated list of users with advanced filtering capabilities.

    This endpoint provides comprehensive user listing with:
    - Text search across username, email, and name fields
    - Boolean filtering for user status fields
    - Date range filtering for temporal queries
    - OIDC profile filtering
    - Proper pagination with metadata
    - Caching for improved performance (30s TTL)

    Requires admin:users:read scope.
    """
    try:
        # Build filters dictionary from query parameters
        filters = {}

        # Add text search filters
        if username:
            filters["username"] = username
        if email:
            filters["email"] = email
        if given_name:
            filters["given_name"] = given_name
        if family_name:
            filters["family_name"] = family_name

        # Add boolean status filters
        if is_active is not None:
            filters["is_active"] = is_active
        if is_verified is not None:
            filters["is_verified"] = is_verified
        if is_admin is not None:
            filters["is_admin"] = is_admin
        if requires_password_change is not None:
            filters["requires_password_change"] = requires_password_change

        # Add date range filters (convert from ISO strings)
        from datetime import datetime

        if created_after:
            try:
                filters["created_after"] = datetime.fromisoformat(created_after.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(status_code=400, detail="Invalid created_after date format. Use ISO format.") from e

        if created_before:
            try:
                filters["created_before"] = datetime.fromisoformat(created_before.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(
                    status_code=400, detail="Invalid created_before date format. Use ISO format."
                ) from e

        if last_login_after:
            try:
                filters["last_login_after"] = datetime.fromisoformat(last_login_after.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(
                    status_code=400, detail="Invalid last_login_after date format. Use ISO format."
                ) from e

        if last_login_before:
            try:
                filters["last_login_before"] = datetime.fromisoformat(last_login_before.replace("Z", "+00:00"))
            except ValueError as e:
                raise HTTPException(
                    status_code=400, detail="Invalid last_login_before date format. Use ISO format."
                ) from e

        # Add OIDC profile filters
        if locale:
            filters["locale"] = locale
        if zoneinfo:
            filters["zoneinfo"] = zoneinfo

        # Check cache first
        cached_result = await cache_service.get_user_listing(
            filters=filters if filters else None, skip=skip, limit=limit
        )

        if cached_result:
            users, total_count, active_count = cached_result
            logger.debug(f"Cache hit for user listing with {len(filters)} filters")
        else:
            # Get optimized admin user listing with inline session counts
            users, total_count, active_count = await user_service.get_optimized_admin_listing(
                skip=skip, limit=limit, filters=filters if filters else None
            )

            # Cache the result
            await cache_service.set_user_listing(
                users=users,
                total_count=total_count,
                active_count=active_count,
                filters=filters if filters else None,
                skip=skip,
                limit=limit,
            )

        # Users already include active_sessions from optimized query
        admin_users = users

        # Calculate pagination info
        total_pages = math.ceil(total_count / limit) if total_count > 0 else 0
        current_page = (skip // limit) + 1
        has_next = skip + limit < total_count
        has_previous = skip > 0

        page_info = {
            "skip": skip,
            "limit": limit,
            "has_next": has_next,
            "has_previous": has_previous,
            "current_page": current_page,
            "total_pages": total_pages,
        }

        logger.info(
            f"Admin user {admin_user.username} retrieved {len(admin_users)} users "
            f"(page {current_page}/{total_pages}, total: {total_count})"
        )

        return AdminUserListResponse(
            users=admin_users,
            total_count=total_count,
            page_info=page_info,
            filters_applied=filters if filters else None,
            active_count=active_count,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get admin users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve users: {e!s}"
        ) from None


@admin_router.get("/users/{user_id}", response_model=AdminUserResponse)
async def get_admin_user_details(
    user_id: UUID,
    admin_user: UserModel = Depends(require_admin_user_read),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
    cache_service: AdminCacheService = Depends(get_admin_cache),
):
    """
    Get detailed information about a specific user.

    This endpoint provides complete user details including:
    - All user fields (including admin-only fields)
    - Active session count
    - All OIDC claims
    - Caching for improved performance (60s TTL)

    Requires admin:users:read scope.
    """
    try:
        # Check cache first
        cached_user = await cache_service.get_user_details(user_id)
        if cached_user:
            logger.debug(f"Cache hit for user details: {user_id}")
            user_data = cached_user
        else:
            # Get optimized user details with inline session count
            user_with_sessions = await user_service.get_user_with_sessions(user_id, admin_context=True)

            if not user_with_sessions:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            # User already includes active_sessions from optimized query
            user_data = user_with_sessions

            # Cache the user details
            await cache_service.set_user_details(user_id, user_data)

        logger.info(
            f"Admin user {admin_user.username} retrieved details for user "
            f"(ID: {user_id}, active sessions: {user_data.get('active_sessions', 0)})"
        )

        return AdminUserResponse(**user_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user details for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve user details: {e!s}"
        ) from None


@admin_router.post("/users", response_model=AdminUserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_admin_user(
    create_request: AdminUserCreateRequest,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
    cache_service: AdminCacheService = Depends(get_admin_cache),
):
    """
    Create a new user with admin privileges.

    This endpoint allows administrators to create users with elevated privileges:
    - Can set is_admin, is_verified, and is_active flags
    - Can set all OIDC profile fields
    - Can force password change on first login
    - Supports comprehensive user profile creation

    Business rules enforced:
    - Username and email uniqueness validation
    - Password policy enforcement
    - Admin privilege logging for audit purposes

    Requires admin:users:write scope.
    """
    try:
        # Validate the creation request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)

        # Convert request to dict for validation
        user_data = create_request.model_dump(exclude_none=True)

        # Handle password requirements
        generate_temp = user_data.get("generate_temp_password", False)
        if generate_temp and user_data.get("password"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot specify both password and generate_temp_password",
            )

        if not generate_temp and not user_data.get("password"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either password must be provided or generate_temp_password must be true",
            )

        # Validate the creation request with business rules
        await validation.validate_user_creation(user_data, admin_user)

        # Create the user using the service layer
        created_user, temp_password = await user_service.create_admin_user(
            user_data=user_data,
            requesting_user=admin_user,
            generate_temp_password=generate_temp,
        )

        # Get active session count (should be 0 for new user)
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)
        active_sessions = await token_repo.count_active_sessions(created_user.id)

        # Convert to AdminUserCreateResponse with session count and temporary password
        user_response_data = created_user.model_dump()
        user_response_data["active_sessions"] = active_sessions
        if temp_password:
            user_response_data["temporary_password"] = temp_password

        # Invalidate dashboard stats cache (user count changed)
        await cache_service.invalidate_all_users()

        logger.info(
            f"Admin user {admin_user.username} created user {created_user.username} "
            f"(ID: {created_user.id}, is_admin: {created_user.is_admin}, temp_password: {bool(temp_password)})"
        )

        return AdminUserCreateResponse(**user_response_data)

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for user creation: {e.message}")
        # If there are detailed errors, use the first one's message for better user experience
        detail_message = e.details[0].message if e.details and len(e.details) > 0 else e.message
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail_message) from e

    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create user: {e!s}"
        ) from None


@admin_router.put("/users/{user_id}", response_model=AdminUserResponse)
async def update_admin_user(
    user_id: UUID,
    update_request: AdminUserUpdateRequest,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
    cache_service: AdminCacheService = Depends(get_admin_cache),
):
    """
    Update a user with admin privileges.

    This endpoint allows administrators to update any user field including:
    - All user fields (username, email, password)
    - Admin-only fields (is_admin, is_active, is_verified, requires_password_change)
    - All OIDC claims

    Business rules enforced:
    - Cannot remove own admin privileges
    - Cannot deactivate the last admin user
    - Username and email uniqueness validation
    - Password policy enforcement

    Requires admin:users:write scope.
    """
    try:
        # Validate the update request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)

        # Convert update request to dict, excluding None values
        update_data = update_request.model_dump(exclude_none=True)

        if not update_data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided for update")

        # Validate the update with business rules
        await validation.validate_user_update(user_id, update_data, admin_user)

        # Perform the update with admin privileges
        updated_user = await user_service.update_user(
            user_id=user_id,
            update_data=update_data,
            requesting_user=admin_user,
            admin_override=True,
            admin_context=True,
        )

        # Get active session count for the response
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)
        active_sessions = await token_repo.count_active_sessions(user_id)

        # Convert to AdminUserResponse with session count
        user_data = updated_user.model_dump()
        user_data["active_sessions"] = active_sessions

        # Invalidate caches for this user
        await cache_service.invalidate_user(user_id)

        logger.info(
            f"Admin user {admin_user.username} updated user {updated_user.username} "
            f"(ID: {user_id}, fields: {list(update_data.keys())})"
        )

        return AdminUserResponse(**user_data)

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for user update {user_id}: {e.message}")
        # If there are detailed errors, use the first one's message for better user experience
        detail_message = e.details[0].message if e.details and len(e.details) > 0 else e.message
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail_message) from e

    except RecordNotFoundError:
        logger.warning(f"User not found for update: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update user: {e!s}"
        ) from None


@admin_router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_admin_user(
    user_id: UUID,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
    cache_service: AdminCacheService = Depends(get_admin_cache),
):
    """
    Delete a user with complete cascade cleanup.

    This endpoint performs a complete deletion of a user and all related data:
    - Invalidates all user tokens (access and refresh)
    - Revokes all OAuth authorization codes
    - Deletes the user record

    Business rules enforced:
    - Cannot delete the last admin user
    - Requires admin:users:write scope

    Returns 204 No Content on success.
    """
    try:
        # Validate the deletion request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)
        user = await validation.validate_user_deletion(user_id, admin_user)

        # Perform cascade deletion
        deletion_stats = await user_service.cascade_delete_user(user_id=user_id, requesting_user=admin_user)

        # Invalidate caches for this user
        await cache_service.invalidate_user(user_id)

        logger.info(
            f"Admin user {admin_user.username} deleted user {user.username} "
            f"(ID: {user_id}), cleanup stats: {deletion_stats}"
        )

        # Return 204 No Content as per REST standards
        return

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for user deletion {user_id}: {e.message}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from None

    except RecordNotFoundError:
        logger.warning(f"User not found for deletion: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete user: {e!s}"
        ) from None


@admin_router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: UUID,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
):
    """
    Reset a user's password with secure temporary password generation.

    This endpoint provides secure password reset functionality for administrators:
    - Generates a cryptographically secure temporary password
    - Sets requires_password_change flag to force password change on next login
    - Invalidates all existing user sessions for security
    - Applies password complexity requirements
    - Provides audit logging for security tracking

    Business rules enforced:
    - User must exist in the system
    - Temporary password meets complexity requirements
    - All user sessions are invalidated for security

    Requires admin:users:write scope.

    Returns the generated temporary password for secure communication to the user.
    """
    try:
        # Validate the password reset request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)
        await validation.validate_password_reset(user_id, admin_user)

        # Generate secure temporary password
        temp_password = user_service.generate_temporary_password()

        # Update user with new password and force password change
        update_data = {
            "password": temp_password,
            "requires_password_change": True,
        }

        updated_user = await user_service.update_user(
            user_id=user_id,
            update_data=update_data,
            requesting_user=admin_user,
            admin_override=True,
            admin_context=True,
        )

        # Invalidate all existing sessions for security
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)
        invalidated_count = await token_repo.invalidate_user_sessions(user_id)

        logger.info(
            f"Admin user {admin_user.username} reset password for user {updated_user.username} "
            f"(ID: {user_id}, invalidated {invalidated_count} sessions)"
        )

        return {
            "user_id": str(user_id),
            "username": updated_user.username,
            "temporary_password": temp_password,
            "requires_password_change": True,
            "invalidated_sessions": invalidated_count,
            "message": "Password reset successfully. User must change password on next login.",
        }

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for password reset {user_id}: {e.message}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from None

    except RecordNotFoundError:
        logger.warning(f"User not found for password reset: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to reset password for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to reset password: {e!s}"
        ) from None


@admin_router.get("/users/{user_id}/sessions", response_model=AdminSessionListResponse)
async def get_user_sessions(
    user_id: UUID,
    skip: int = Query(0, ge=0, description="Number of sessions to skip"),
    limit: int = Query(25, ge=1, le=100, description="Number of sessions to return (max 100)"),
    include_inactive: bool = Query(True, description="Include inactive/expired sessions"),
    admin_user: UserModel = Depends(require_admin_user_read),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
):
    """
    Get paginated list of user sessions with detailed information.

    This endpoint provides comprehensive session management for administrators:
    - View all user sessions (active and inactive)
    - Paginated results with metadata
    - Session details including token type, expiry, and client info
    - Last activity tracking
    - Security status (expired, invalidated)

    Requires admin:users:read scope.
    """
    try:
        # Validate the session access request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)
        user = await validation.validate_session_access(user_id, admin_user)

        # Get user sessions from token repository
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)
        sessions = await token_repo.get_user_sessions(
            user_id, skip=skip, limit=limit, include_inactive=include_inactive
        )
        total_count = await token_repo.count_user_sessions(user_id, include_inactive=include_inactive)
        active_count = await token_repo.count_active_sessions(user_id)

        # Convert TokenModel instances to AdminSessionResponse
        from datetime import datetime

        session_responses = []
        for session in sessions:
            now = datetime.now(UTC)
            is_expired = session.expires_at <= now
            is_active = not session.invalidated and not is_expired

            session_responses.append(
                AdminSessionResponse(
                    session_id=session.id,
                    token_jti=session.token_jti,
                    token_type=session.token_type.value,
                    created_at=session.created_at,
                    expires_at=session.expires_at,
                    last_activity=session.created_at,  # Use created_at as proxy for last_activity
                    is_active=is_active,
                    client_id=session.client_id,
                    scope=session.scope,
                    is_expired=is_expired,
                    is_invalidated=session.invalidated,
                    invalidated_at=session.invalidated_at,
                ).model_dump()
            )

        # Calculate pagination info
        import math

        total_pages = math.ceil(total_count / limit) if total_count > 0 else 0
        current_page = (skip // limit) + 1
        has_next = skip + limit < total_count
        has_previous = skip > 0

        page_info = {
            "skip": skip,
            "limit": limit,
            "has_next": has_next,
            "has_previous": has_previous,
            "current_page": current_page,
            "total_pages": total_pages,
        }

        logger.info(
            f"Admin user {admin_user.username} retrieved {len(session_responses)} sessions for user {user.username} "
            f"(page {current_page}/{total_pages}, total: {total_count}, active: {active_count})"
        )

        return AdminSessionListResponse(
            sessions=session_responses,
            total_count=total_count,
            active_count=active_count,
            page_info=page_info,
        )

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for session access {user_id}: {e.message}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from None

    except RecordNotFoundError:
        logger.warning(f"User not found for session access: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to get sessions for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve user sessions: {e!s}"
        ) from None


@admin_router.delete("/users/{user_id}/sessions")
async def revoke_all_user_sessions(
    user_id: UUID,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
):
    """
    Revoke all active sessions for a user (force logout).

    This endpoint provides comprehensive session management for administrators:
    - Invalidates all active sessions (access and refresh tokens)
    - Forces user to re-authenticate on next request
    - Provides security audit logging
    - Returns count of revoked sessions

    Business rules enforced:
    - User must exist in the system
    - All active sessions are invalidated immediately
    - Comprehensive audit logging for security

    Requires admin:users:write scope.
    """
    try:
        # Validate the session revocation request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)
        user = await validation.validate_session_revocation(user_id, admin_user)

        # Revoke all user sessions
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)

        # Count active sessions before revocation
        active_sessions_before = await token_repo.count_active_sessions(user_id)

        # Invalidate all user tokens (both access and refresh)
        await token_repo.invalidate_user_tokens(user_id)

        # Count active sessions after revocation (should be 0)
        active_sessions_after = await token_repo.count_active_sessions(user_id)
        revoked_count = active_sessions_before - active_sessions_after

        logger.warning(
            f"Admin user {admin_user.username} revoked all sessions for user {user.username} "
            f"(ID: {user_id}, revoked {revoked_count} sessions)"
        )

        return {
            "user_id": str(user_id),
            "username": user.username,
            "revoked_sessions": revoked_count,
            "active_sessions_remaining": active_sessions_after,
            "message": f"Successfully revoked {revoked_count} active sessions. User must re-authenticate.",
        }

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for session revocation {user_id}: {e.message}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from None

    except RecordNotFoundError:
        logger.warning(f"User not found for session revocation: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to revoke sessions for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to revoke user sessions: {e!s}"
        ) from None


@admin_router.delete("/users/{user_id}/sessions/{session_id}")
async def revoke_specific_user_session(
    user_id: UUID,
    session_id: UUID,
    admin_user: UserModel = Depends(require_admin_user_write),
    user_service: UserService = Depends(get_user_service),
    conn: AsyncConnection = Depends(get_database_connection),
):
    """
    Revoke a specific user session by session ID.

    This endpoint allows administrators to revoke individual user sessions:
    - Invalidates a specific session by token ID
    - Maintains other active sessions
    - Provides security audit logging
    - Validates session ownership

    Business rules enforced:
    - User must exist in the system
    - Session must belong to the specified user
    - Session must exist and be active
    - Comprehensive audit logging for security

    Requires admin:users:write scope.
    """
    try:
        # Validate the session revocation request
        from authly.admin.validation import AdminUserValidation

        validation = AdminUserValidation(conn)
        user = await validation.validate_session_revocation(user_id, admin_user, session_id)

        # Get the specific session and validate ownership
        from authly.tokens.repository import TokenRepository

        token_repo = TokenRepository(conn)
        session = await token_repo.get_by_id(session_id)

        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

        if session.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Session does not belong to the specified user"
            )

        if session.invalidated:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session is already invalidated")

        # Invalidate the specific session
        await token_repo.invalidate_token(session.token_jti)

        logger.info(
            f"Admin user {admin_user.username} revoked session {session_id} for user {user.username} "
            f"(token_type: {session.token_type.value}, jti: {session.token_jti})"
        )

        return {
            "user_id": str(user_id),
            "username": user.username,
            "session_id": str(session_id),
            "token_jti": session.token_jti,
            "token_type": session.token_type.value,
            "message": "Session successfully revoked.",
        }

    except HTTPException:
        raise
    except AdminValidationError as e:
        logger.warning(f"Admin validation failed for session revocation {user_id}/{session_id}: {e.message}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message) from None

    except RecordNotFoundError:
        logger.warning(f"User not found for session revocation: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from None

    except Exception as e:
        logger.error(f"Failed to revoke session {session_id} for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to revoke session: {e!s}"
        ) from None


# ============================================================================
# ADMIN AUTHENTICATION ENDPOINTS
# ============================================================================
#
# Admin authentication is handled through the OAuth 2.1 flow using /api/v1/oauth/token
# with admin credentials. No separate admin authentication endpoint is needed.
