"""
Admin API Router for Authly authentication service.

This router provides authenticated admin endpoints that mirror the CLI operations,
enabling API-first administration of OAuth clients, scopes, and system management.
"""

import logging
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from psycopg import AsyncConnection

from authly.config import AuthlyConfig
from authly.core.dependencies import get_config, get_database_connection
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import (
    ClientType,
    OAuthClientCreateRequest,
    OAuthClientCredentialsResponse,
    OAuthClientModel,
    OAuthScopeModel,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.oauth.scope_service import ScopeService
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)

# Admin API Router
admin_router = APIRouter(prefix="/admin", tags=["admin"])


# Import admin authentication dependencies
from authly.api.admin_dependencies import (
    require_admin_client_read,
    require_admin_client_write,
    require_admin_scope,
    require_admin_scope_read,
    require_admin_scope_write,
    require_admin_system_read,
    require_admin_user,
    require_admin_user_read,
)

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
) -> List[OAuthClientModel]:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to list clients: {str(e)}"
        )


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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create client: {str(e)}"
        )


@admin_router.get("/clients/{client_id}")
async def get_client(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_read),
) -> Dict:
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get client: {str(e)}")


@admin_router.put("/clients/{client_id}")
async def update_client(
    client_id: str,
    update_data: Dict,
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update client: {str(e)}"
        )


@admin_router.post("/clients/{client_id}/regenerate-secret")
async def regenerate_client_secret(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> Dict:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to regenerate client secret: {str(e)}"
        )


@admin_router.delete("/clients/{client_id}")
async def delete_client(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
    _admin: UserModel = Depends(require_admin_client_write),
) -> Dict:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete client: {str(e)}"
        )


# ============================================================================
# OIDC CLIENT MANAGEMENT ENDPOINTS
# ============================================================================


@admin_router.get("/clients/{client_id}/oidc")
async def get_client_oidc_settings(
    client_id: str,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_client_read),
) -> Dict:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get OIDC settings: {str(e)}"
        )


@admin_router.put("/clients/{client_id}/oidc")
async def update_client_oidc_settings(
    client_id: str,
    oidc_settings: Dict,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_client_write),
) -> Dict:
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
        updated_client = await client_repo.update_client(client.id, update_data)

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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update OIDC settings: {str(e)}"
        )


@admin_router.get("/clients/oidc/algorithms")
async def get_supported_oidc_algorithms(_admin: UserModel = Depends(require_admin_client_read)) -> Dict:
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
) -> List[OAuthScopeModel]:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to list scopes: {str(e)}"
        )


@admin_router.post("/scopes")
async def create_scope(
    scope_data: Dict,
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to create scope: {str(e)}"
        )


@admin_router.get("/scopes/defaults")
async def get_default_scopes(
    conn: AsyncConnection = Depends(get_database_connection), _admin: UserModel = Depends(require_admin_scope_read)
) -> List[OAuthScopeModel]:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get default scopes: {str(e)}"
        )


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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get scope: {str(e)}")


@admin_router.put("/scopes/{scope_name}")
async def update_scope(
    scope_name: str,
    update_data: Dict,
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update scope: {str(e)}"
        )


@admin_router.delete("/scopes/{scope_name}")
async def delete_scope(
    scope_name: str,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_scope_write),
) -> Dict:
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete scope: {str(e)}"
        )


# ============================================================================
# USER MANAGEMENT ENDPOINTS (Future expansion)
# ============================================================================


@admin_router.get("/users")
async def list_users(
    limit: int = 100,
    offset: int = 0,
    conn: AsyncConnection = Depends(get_database_connection),
    _admin: UserModel = Depends(require_admin_user_read),
):
    """
    List users with pagination.
    Future expansion for user management via admin API.
    """
    # TODO: Implement comprehensive user management endpoints
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="User management endpoints will be implemented in future phases",
    )


# ============================================================================
# ADMIN AUTHENTICATION ENDPOINTS (Placeholder for task 1.5)
# ============================================================================


@admin_router.post("/auth")
async def admin_authenticate():
    """
    Admin authentication endpoint.
    Will be implemented in task 1.5 with proper admin login flow.
    """
    # TODO: Implement admin authentication in task 1.5
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Admin authentication endpoint will be implemented in task 1.5",
    )
