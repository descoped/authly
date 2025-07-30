"""
Tests for OpenID Connect (OIDC) client management functionality.

This module tests the OIDC-specific client management features including:
- OIDC client creation and validation
- OIDC-specific field handling
- Admin API endpoints for OIDC client management
- OIDC scope assignment and validation
"""

from typing import Dict, List
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestServer
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import (
    ClientType,
    IDTokenSigningAlgorithm,
    OAuthClientCreateRequest,
    SubjectType,
)
from authly.oauth.scope_repository import ScopeRepository


class TestOIDCClientCreation:
    """Test OIDC client creation and validation"""

    @pytest.mark.asyncio
    async def test_create_oidc_client_with_openid_scope(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test creating an OIDC client with openid scope"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create OIDC client with openid scope
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile email",
                id_token_signed_response_alg=IDTokenSigningAlgorithm.RS256,
                subject_type=SubjectType.PUBLIC,
                require_auth_time=True,
                default_max_age=3600,
                application_type="web",
                contacts=["admin@example.com"],
            )

            result = await client_service.create_client(request)

            assert result.client_id is not None
            assert result.client_secret is not None
            assert result.client_type == ClientType.CONFIDENTIAL
            assert result.client_name == "Test OIDC Client"

            # Verify the client was created with OIDC settings
            client = await client_repo.get_by_client_id(result.client_id)
            assert client is not None
            assert client.is_oidc_client() is True
            assert client.get_oidc_scopes() == ["openid", "profile", "email"]
            assert client.id_token_signed_response_alg == IDTokenSigningAlgorithm.RS256
            assert client.subject_type == SubjectType.PUBLIC
            assert client.require_auth_time is True
            assert client.default_max_age == 3600
            assert client.application_type == "web"
            assert client.contacts == ["admin@example.com"]

    @pytest.mark.asyncio
    async def test_create_oauth_client_without_openid_scope(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test creating a regular OAuth client without openid scope"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create OAuth client without openid scope
            request = OAuthClientCreateRequest(
                client_name="Test OAuth Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="read write",
                id_token_signed_response_alg=IDTokenSigningAlgorithm.HS256,
                subject_type=SubjectType.PAIRWISE,
                sector_identifier_uri="https://example.com/sector",
            )

            result = await client_service.create_client(request)

            # Verify the client was created
            client = await client_repo.get_by_client_id(result.client_id)
            assert client is not None
            assert client.is_oidc_client() is False  # No openid scope
            assert client.get_oidc_scopes() == []
            assert client.id_token_signed_response_alg == IDTokenSigningAlgorithm.HS256
            assert client.subject_type == SubjectType.PAIRWISE
            assert client.sector_identifier_uri == "https://example.com/sector"

    @pytest.mark.asyncio
    async def test_oidc_client_validation(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test OIDC client validation"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Test validation: pairwise subject type requires sector_identifier_uri
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile",
                subject_type=SubjectType.PAIRWISE,
                # Missing sector_identifier_uri
            )

            with pytest.raises(Exception) as exc_info:
                await client_service.create_client(request)

            assert "sector_identifier_uri is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_oidc_client_default_values(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test OIDC client default values"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create client with minimal OIDC settings
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid",
            )

            result = await client_service.create_client(request)

            # Verify defaults are applied
            client = await client_repo.get_by_client_id(result.client_id)
            assert client.id_token_signed_response_alg == IDTokenSigningAlgorithm.RS256
            assert client.subject_type == SubjectType.PUBLIC
            assert client.application_type == "web"
            assert client.require_auth_time is False
            assert client.default_max_age is None
            assert client.contacts == []
            assert client.request_uris == []


class TestOIDCClientAPI:
    """Test OIDC client management through Admin API"""

    @pytest.mark.asyncio
    async def test_oidc_endpoints_require_authentication(self, test_server: AsyncTestServer):
        """Test that OIDC endpoints require authentication"""
        # Test without auth header
        response = await test_server.client.get("/admin/clients/test-client/oidc")
        await response.expect_status(401)

        response = await test_server.client.put(
            "/admin/clients/test-client/oidc", json={"id_token_signed_response_alg": "HS256"}
        )
        await response.expect_status(401)

        response = await test_server.client.get("/admin/clients/oidc/algorithms")
        await response.expect_status(401)


class TestOIDCClientValidation:
    """Test OIDC client validation functionality"""

    @pytest.mark.asyncio
    async def test_validate_request_uris_https_only(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test that request_uris must use HTTPS"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Test with non-HTTPS request_uri
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile",
                request_uris=["http://example.com/request"],  # HTTP not allowed
            )

            with pytest.raises(Exception) as exc_info:
                await client_service.create_client(request)

            assert "request_uris must use HTTPS" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_contacts_email_format(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test that contacts must be valid email addresses"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Test with invalid email format
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile",
                contacts=["invalid-email"],  # Invalid email format
            )

            with pytest.raises(Exception) as exc_info:
                await client_service.create_client(request)

            assert "Invalid contact email format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_default_max_age_non_negative(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test that default_max_age must be non-negative"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Test with negative default_max_age
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile",
                default_max_age=-1,  # Negative value not allowed
            )

            with pytest.raises(Exception) as exc_info:
                await client_service.create_client(request)

            assert "default_max_age must be non-negative" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_application_type(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test that application_type must be valid"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Test with invalid application_type
            request = OAuthClientCreateRequest(
                client_name="Test OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile",
                application_type="invalid",  # Must be 'web' or 'native'
            )

            with pytest.raises(Exception) as exc_info:
                await client_service.create_client(request)

            assert "application_type must be 'web' or 'native'" in str(exc_info.value)


class TestOIDCClientModel:
    """Test OIDC client model functionality"""

    @pytest.mark.asyncio
    async def test_is_oidc_client_detection(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test OIDC client detection"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create OIDC client
            oidc_request = OAuthClientCreateRequest(
                client_name="OIDC Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile email",
            )

            oidc_result = await client_service.create_client(oidc_request)
            oidc_client = await client_repo.get_by_client_id(oidc_result.client_id)

            assert oidc_client.is_oidc_client() is True
            assert oidc_client.get_oidc_scopes() == ["openid", "profile", "email"]

            # Create regular OAuth client
            oauth_request = OAuthClientCreateRequest(
                client_name="OAuth Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="read write",
            )

            oauth_result = await client_service.create_client(oauth_request)
            oauth_client = await client_repo.get_by_client_id(oauth_result.client_id)

            assert oauth_client.is_oidc_client() is False
            assert oauth_client.get_oidc_scopes() == []

    @pytest.mark.asyncio
    async def test_get_oidc_scopes_filtering(
        self, transaction_manager: TransactionManager, initialize_authly: AuthlyResourceManager
    ):
        """Test OIDC scope filtering"""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create client with mixed scopes
            request = OAuthClientCreateRequest(
                client_name="Mixed Scopes Client",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://example.com/callback"],
                scope="openid profile email read write admin",
            )

            result = await client_service.create_client(request)
            client = await client_repo.get_by_client_id(result.client_id)

            # Should only return OIDC scopes
            oidc_scopes = client.get_oidc_scopes()
            assert set(oidc_scopes) == {"openid", "profile", "email"}
            assert "read" not in oidc_scopes
            assert "write" not in oidc_scopes
            assert "admin" not in oidc_scopes
