"""Integration tests for OAuth 2.1 service layers with real database connections."""

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from psycopg_toolkit import TransactionManager

from authly import Authly
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import (
    ClientType,
    GrantType,
    OAuthClientCreateRequest,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.oauth.scope_service import ScopeService

logger = logging.getLogger(__name__)


# Note: Service fixtures are removed - services will be created within test transaction context


@pytest.fixture
async def test_client_request():
    """Test client creation request for OAuth client creation."""
    return OAuthClientCreateRequest(
        client_name="Test OAuth Client",
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=["https://example.com/callback"],
        grant_types=[GrantType.AUTHORIZATION_CODE],
        token_endpoint_auth_method=TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
    )


@pytest.fixture
async def test_public_client_request():
    """Test public client creation request for OAuth client creation."""
    return OAuthClientCreateRequest(
        client_name="Test Public OAuth Client",
        client_type=ClientType.PUBLIC,
        redirect_uris=["https://example.com/callback"],
        grant_types=[GrantType.AUTHORIZATION_CODE],
        token_endpoint_auth_method=TokenEndpointAuthMethod.NONE,
    )


@pytest.fixture
async def test_scope_data():
    """Test scope data for OAuth scope creation."""
    return {
        "scope_name": "test_scope_" + uuid4().hex[:8],
        "description": "Test scope for integration testing",
        "is_default": False,
        "is_active": True,
    }


@pytest.fixture
async def test_client_data():
    """Test client data for OAuth client creation (dict format)."""
    return {
        "client_id": "test_client_" + uuid4().hex[:8],
        "client_name": "Test OAuth Client",
        "client_type": ClientType.CONFIDENTIAL,
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE],
        "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        "client_secret": "test_secret_" + uuid4().hex[:16],
    }


@pytest.fixture
async def test_public_client_data():
    """Test public client data for OAuth client creation (dict format)."""
    return {
        "client_id": "test_public_client_" + uuid4().hex[:8],
        "client_name": "Test Public OAuth Client",
        "client_type": ClientType.PUBLIC,
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE],
        "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
    }


class TestClientService:
    """Test cases for ClientService with real database integration."""

    @pytest.mark.asyncio
    async def test_create_confidential_client(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test creating a confidential OAuth client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            credentials_response = await client_service.create_client(test_client_request)
            
            # Check credentials response
            assert credentials_response.client_name == test_client_request.client_name
            assert credentials_response.client_type == test_client_request.client_type
            # Service generates client_id automatically
            assert credentials_response.client_id is not None
            assert credentials_response.client_id.startswith("client_")
            # Confidential clients should have a client secret
            assert credentials_response.client_secret is not None
            
            # Verify client was created in database
            created_client = await client_repo.get_by_client_id(credentials_response.client_id)
            assert created_client is not None
            assert created_client.redirect_uris == test_client_request.redirect_uris
            assert created_client.grant_types == test_client_request.grant_types

    @pytest.mark.asyncio
    async def test_create_public_client(self, initialize_authly: Authly, test_public_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test creating a public OAuth client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            created_client = await client_service.create_client(test_public_client_request)
            
            assert created_client.client_name == test_public_client_request.client_name
            assert created_client.client_type == ClientType.PUBLIC
            # Public clients should not have a client secret
            assert created_client.client_secret is None

    @pytest.mark.asyncio
    async def test_create_client_with_invalid_redirect_uri(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test creating client with invalid redirect URI."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Test with invalid redirect URI
            invalid_request = OAuthClientCreateRequest(
                client_name=test_client_request.client_name,
                client_type=test_client_request.client_type,
                redirect_uris=["invalid-uri"],
                grant_types=test_client_request.grant_types,
                token_endpoint_auth_method=test_client_request.token_endpoint_auth_method,
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await client_service.create_client(invalid_request)
            
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_create_client_with_localhost_redirect_uri(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test creating client with localhost redirect URI (should be allowed for testing)."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Test with localhost redirect URI
            localhost_request = OAuthClientCreateRequest(
                client_name=test_client_request.client_name,
                client_type=test_client_request.client_type,
                redirect_uris=["http://localhost:3000/callback"],
                grant_types=test_client_request.grant_types,
                token_endpoint_auth_method=test_client_request.token_endpoint_auth_method,
            )
            
            created_client = await client_service.create_client(localhost_request)
            assert created_client.client_name == localhost_request.client_name

    @pytest.mark.asyncio
    async def test_create_client_duplicate_client_id(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test creating client with duplicate client_id."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create first client
            first_response = await client_service.create_client(test_client_request)
            
            # Create another client with same request - should succeed since service auto-generates unique client_id
            second_response = await client_service.create_client(test_client_request)
            
            # Verify they have different client_ids
            assert first_response.client_id != second_response.client_id

    @pytest.mark.asyncio
    async def test_authenticate_client_with_valid_credentials(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test client authentication with valid credentials."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Authenticate with correct credentials
            authenticated_client = await client_service.authenticate_client(
                credentials_response.client_id, credentials_response.client_secret
            )
            
            assert authenticated_client is not None
            assert authenticated_client.client_id == credentials_response.client_id

    @pytest.mark.asyncio
    async def test_authenticate_client_with_invalid_credentials(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test client authentication with invalid credentials."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Authenticate with wrong secret
            authenticated_client = await client_service.authenticate_client(
                credentials_response.client_id, "wrong_secret"
            )
            
            assert authenticated_client is None

    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_client(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test authentication of non-existent client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Try to authenticate non-existent client
            authenticated_client = await client_service.authenticate_client(
                "nonexistent_client", "any_secret"
            )
            
            assert authenticated_client is None

    @pytest.mark.asyncio
    async def test_authenticate_public_client(self, initialize_authly: Authly, test_public_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test public client authentication (no secret required)."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create public client
            credentials_response = await client_service.create_client(test_public_client_request)
            
            # Authenticate public client (no secret needed)
            from authly.oauth.models import TokenEndpointAuthMethod
            authenticated_client = await client_service.authenticate_client(
                credentials_response.client_id, None, TokenEndpointAuthMethod.NONE
            )
            
            assert authenticated_client is not None
            assert authenticated_client.client_id == credentials_response.client_id

    @pytest.mark.asyncio
    async def test_validate_redirect_uri_exact_match(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test redirect URI validation with exact match."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Get the client model from repository
            client_model = await client_repo.get_by_client_id(credentials_response.client_id)
            
            # Test with exact match
            is_valid = client_model.is_redirect_uri_allowed("https://example.com/callback")
            assert is_valid is True
            
            # Test with non-registered URI
            is_valid = client_model.is_redirect_uri_allowed("https://evil.com/callback")
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_update_client_info(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test updating client information."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Update client
            update_data = {
                "client_name": "Updated Client Name",
                "redirect_uris": ["https://updated.example.com/callback"],
            }
            
            updated_client = await client_service.update_client(
                credentials_response.client_id, update_data
            )
            
            assert updated_client.client_name == update_data["client_name"]
            assert updated_client.redirect_uris == update_data["redirect_uris"]

    @pytest.mark.asyncio
    async def test_update_client_with_invalid_redirect_uri(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test updating client with invalid redirect URI."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Try to update with invalid redirect URI
            update_data = {
                "redirect_uris": ["invalid-uri"],
            }
            
            with pytest.raises(HTTPException) as exc_info:
                await client_service.update_client(credentials_response.client_id, update_data)
            
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_deactivate_client(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test client deactivation."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            client_service = ClientService(client_repo, scope_repo)
            
            # Create client
            credentials_response = await client_service.create_client(test_client_request)
            
            # Deactivate client
            success = await client_service.deactivate_client(credentials_response.client_id)
            assert success is True
            
            # Verify client is deactivated
            deactivated_client = await client_service.get_client_by_id(credentials_response.client_id)
            assert deactivated_client is None


class TestScopeService:
    """Test cases for ScopeService with real database integration."""

    @pytest.mark.asyncio
    async def test_create_scope(self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager):
        """Test creating an OAuth scope."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            created_scope = await scope_service.create_scope(
                test_scope_data["scope_name"],
                test_scope_data["description"],
                test_scope_data["is_default"],
                test_scope_data["is_active"]
            )
            
            assert created_scope.scope_name == test_scope_data["scope_name"]
            assert created_scope.description == test_scope_data["description"]
            assert created_scope.is_default == test_scope_data["is_default"]
            assert created_scope.is_active == test_scope_data["is_active"]

    @pytest.mark.asyncio
    async def test_create_scope_with_invalid_name(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test creating scope with invalid name."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Test with scope name containing spaces
            with pytest.raises(HTTPException) as exc_info:
                await scope_service.create_scope("invalid scope name")
            
            assert exc_info.value.status_code == 400
            assert "cannot contain spaces" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_create_duplicate_scope(self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager):
        """Test creating duplicate scope."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create first scope
            await scope_service.create_scope(test_scope_data["scope_name"])
            
            # Try to create duplicate
            with pytest.raises(HTTPException) as exc_info:
                await scope_service.create_scope(test_scope_data["scope_name"])
            
            assert exc_info.value.status_code == 400
            assert "already exists" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_update_scope(self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager):
        """Test updating scope information."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scope
            created_scope = await scope_service.create_scope(test_scope_data["scope_name"])
            
            # Update scope
            update_data = {
                "description": "Updated description",
                "is_default": True,
            }
            
            updated_scope = await scope_service.update_scope(
                created_scope.scope_name, update_data, requesting_admin=True
            )
            
            assert updated_scope.description == update_data["description"]
            assert updated_scope.is_default == update_data["is_default"]

    @pytest.mark.asyncio
    async def test_update_scope_non_admin(self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager):
        """Test updating scope as non-admin (should fail)."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scope
            created_scope = await scope_service.create_scope(test_scope_data["scope_name"])
            
            # Try to update as non-admin
            update_data = {"description": "Updated description"}
            
            with pytest.raises(HTTPException) as exc_info:
                await scope_service.update_scope(
                    created_scope.scope_name, update_data, requesting_admin=False
                )
            
            assert exc_info.value.status_code == 403
            assert "administrators" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_validate_requested_scopes(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test validating requested scopes for a client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create client
            client_service = ClientService(client_repo, scope_repo)
            credentials_response = await client_service.create_client(test_client_request)
            
            # Get the created client model
            created_client = await client_repo.get_by_client_id(credentials_response.client_id)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope = await scope_service.create_scope(f"read_{unique_suffix}", "Read access")
            write_scope = await scope_service.create_scope(f"write_{unique_suffix}", "Write access")
            admin_scope = await scope_service.create_scope(f"admin_{unique_suffix}", "Admin access")
            
            # Associate client with read and write scopes
            await client_repo.associate_client_scopes(
                created_client.id, [read_scope.id, write_scope.id]
            )
            
            # Test validating authorized scopes
            valid_scopes = await scope_service.validate_requested_scopes(
                f"{read_scope.scope_name} {write_scope.scope_name}", created_client.id
            )
            assert read_scope.scope_name in valid_scopes
            assert write_scope.scope_name in valid_scopes
            assert admin_scope.scope_name not in valid_scopes

    @pytest.mark.asyncio
    async def test_validate_requested_scopes_unauthorized(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test validating unauthorized scopes for a client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create client
            client_service = ClientService(client_repo, scope_repo)
            credentials_response = await client_service.create_client(test_client_request)
            
            # Get the created client model
            created_client = await client_repo.get_by_client_id(credentials_response.client_id)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope = await scope_service.create_scope(f"read_{unique_suffix}", "Read access")
            admin_scope = await scope_service.create_scope(f"admin_{unique_suffix}", "Admin access")
            
            # Associate client with only read scope
            await client_repo.associate_client_scopes(created_client.id, [read_scope.id])
            
            # Test validating unauthorized scope
            with pytest.raises(HTTPException) as exc_info:
                await scope_service.validate_requested_scopes(
                    f"{read_scope.scope_name} {admin_scope.scope_name}", created_client.id
                )
            
            assert exc_info.value.status_code == 400
            assert "not authorized" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_validate_requested_scopes_invalid(self, initialize_authly: Authly, test_client_request: OAuthClientCreateRequest, transaction_manager: TransactionManager):
        """Test validating invalid/nonexistent scopes."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create client
            client_service = ClientService(client_repo, scope_repo)
            credentials_response = await client_service.create_client(test_client_request)
            
            # Get the created client model
            created_client = await client_repo.get_by_client_id(credentials_response.client_id)
            
            # Test validating nonexistent scope
            with pytest.raises(HTTPException) as exc_info:
                await scope_service.validate_requested_scopes(
                    "nonexistent_scope", created_client.id
                )
            
            assert exc_info.value.status_code == 400
            assert "invalid" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_associate_token_with_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test associating a token with scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope = await scope_service.create_scope(f"read_{unique_suffix}", "Read access")
            write_scope = await scope_service.create_scope(f"write_{unique_suffix}", "Write access")
            
            # Create a real user first (required for foreign key constraint)
            from authly.tokens import TokenModel, TokenRepository, TokenType
            from authly.users import UserModel, UserRepository
            
            user_repo = UserRepository(conn)
            user_model = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            created_user = await user_repo.create(user_model)
            
            # Create a token that exists in the database
            token_repo = TokenRepository(conn)
            token_model = TokenModel(
                id=uuid4(),
                token_jti=str(uuid4()),
                user_id=created_user.id,  # Use the real user ID
                token_type=TokenType.ACCESS,
                token_value="dummy.jwt.token",  # Mock JWT value
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                created_at=datetime.now(timezone.utc)
            )
            created_token = await token_repo.store_token(token_model)
            
            # Associate token with scopes
            count = await scope_service.associate_token_with_scopes(
                created_token.id, [read_scope.scope_name, write_scope.scope_name]
            )
            assert count == 2
            
            # Verify associations
            token_scopes = await scope_service.get_token_scopes(created_token.id)
            assert read_scope.scope_name in token_scopes
            assert write_scope.scope_name in token_scopes

    @pytest.mark.asyncio
    async def test_check_token_has_scope(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test checking if a token has a specific scope."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope_name = f"read_{unique_suffix}"
            write_scope_name = f"write_{unique_suffix}"
            
            read_scope = await scope_service.create_scope(read_scope_name, "Read access")
            
            # Create a real user and token in the database
            from authly.tokens import TokenModel, TokenRepository, TokenType
            from authly.users import UserModel, UserRepository
            
            user_repo = UserRepository(conn)
            user_model = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            created_user = await user_repo.create(user_model)
            
            # Create a token that exists in the database
            token_repo = TokenRepository(conn)
            token_model = TokenModel(
                id=uuid4(),
                token_jti=str(uuid4()),
                user_id=created_user.id,
                token_type=TokenType.ACCESS,
                token_value="dummy.jwt.token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                created_at=datetime.now(timezone.utc)
            )
            created_token = await token_repo.store_token(token_model)
            
            # Associate token with scope
            await scope_service.associate_token_with_scopes(created_token.id, [read_scope_name])
            
            # Check if token has scope
            has_read = await scope_service.check_token_has_scope(created_token.id, read_scope_name)
            assert has_read is True
            
            has_write = await scope_service.check_token_has_scope(created_token.id, write_scope_name)
            assert has_write is False

    @pytest.mark.asyncio
    async def test_check_token_has_any_scope(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test checking if a token has any of the required scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope_name = f"read_{unique_suffix}"
            write_scope_name = f"write_{unique_suffix}"
            admin_scope_name = f"admin_{unique_suffix}"
            
            read_scope = await scope_service.create_scope(read_scope_name, "Read access")
            write_scope = await scope_service.create_scope(write_scope_name, "Write access")
            
            # Create a real user and token in the database
            from authly.tokens import TokenModel, TokenRepository, TokenType
            from authly.users import UserModel, UserRepository
            
            user_repo = UserRepository(conn)
            user_model = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            created_user = await user_repo.create(user_model)
            
            # Create a token that exists in the database
            token_repo = TokenRepository(conn)
            token_model = TokenModel(
                id=uuid4(),
                token_jti=str(uuid4()),
                user_id=created_user.id,
                token_type=TokenType.ACCESS,
                token_value="dummy.jwt.token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                created_at=datetime.now(timezone.utc)
            )
            created_token = await token_repo.store_token(token_model)
            
            # Associate token with read scope only
            await scope_service.associate_token_with_scopes(created_token.id, [read_scope_name])
            
            # Check if token has any of the required scopes
            has_any = await scope_service.check_token_has_any_scope(
                created_token.id, [read_scope_name, write_scope_name]
            )
            assert has_any is True
            
            has_any = await scope_service.check_token_has_any_scope(
                created_token.id, [write_scope_name, admin_scope_name]
            )
            assert has_any is False

    @pytest.mark.asyncio
    async def test_check_token_has_all_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test checking if a token has all required scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scopes with unique names
            unique_suffix = uuid4().hex[:8]
            read_scope_name = f"read_{unique_suffix}"
            write_scope_name = f"write_{unique_suffix}"
            admin_scope_name = f"admin_{unique_suffix}"
            
            read_scope = await scope_service.create_scope(read_scope_name, "Read access")
            write_scope = await scope_service.create_scope(write_scope_name, "Write access")
            admin_scope = await scope_service.create_scope(admin_scope_name, "Admin access")
            
            # Create a real user and token in the database
            from authly.tokens import TokenModel, TokenRepository, TokenType
            from authly.users import UserModel, UserRepository
            
            user_repo = UserRepository(conn)
            user_model = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            created_user = await user_repo.create(user_model)
            
            # Create a token that exists in the database
            token_repo = TokenRepository(conn)
            token_model = TokenModel(
                id=uuid4(),
                token_jti=str(uuid4()),
                user_id=created_user.id,
                token_type=TokenType.ACCESS,
                token_value="dummy.jwt.token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                created_at=datetime.now(timezone.utc)
            )
            created_token = await token_repo.store_token(token_model)
            
            # Associate token with read and write scopes
            await scope_service.associate_token_with_scopes(created_token.id, [read_scope_name, write_scope_name])
            
            # Check if token has all required scopes
            has_all = await scope_service.check_token_has_all_scopes(
                created_token.id, [read_scope_name, write_scope_name]
            )
            assert has_all is True
            
            has_all = await scope_service.check_token_has_all_scopes(
                created_token.id, [read_scope_name, write_scope_name, admin_scope_name]
            )
            assert has_all is False

    @pytest.mark.asyncio
    async def test_reduce_scopes_to_granted(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test reducing requested scopes to granted scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create actual scopes for testing
            unique_suffix = uuid4().hex[:8]
            read_scope_name = f"read_{unique_suffix}"
            write_scope_name = f"write_{unique_suffix}"
            admin_scope_name = f"admin_{unique_suffix}"
            
            await scope_service.create_scope(read_scope_name, "Read access")
            await scope_service.create_scope(write_scope_name, "Write access")
            await scope_service.create_scope(admin_scope_name, "Admin access")
            
            # Test normal scope reduction
            requested_scopes = [read_scope_name, write_scope_name, admin_scope_name]
            granted_scopes = [read_scope_name, write_scope_name]
            
            final_scopes = await scope_service.reduce_scopes_to_granted(
                requested_scopes, granted_scopes
            )
            
            assert set(final_scopes) == {read_scope_name, write_scope_name}
            
            # Test with invalid grants (should be filtered out)
            invalid_granted = [read_scope_name, write_scope_name, "invalid_scope"]
            final_scopes = await scope_service.reduce_scopes_to_granted(
                requested_scopes, invalid_granted
            )
            
            assert set(final_scopes) == {read_scope_name, write_scope_name}
            assert "invalid_scope" not in final_scopes

    @pytest.mark.asyncio
    async def test_list_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test listing OAuth scopes with pagination."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create multiple scopes
            scope_names = []
            for i in range(5):
                scope_name = f"test_scope_{i}_{uuid4().hex[:8]}"
                scope_names.append(scope_name)
                await scope_service.create_scope(scope_name, f"Test scope {i}")
            
            # List scopes with a large limit to ensure we get all our test scopes
            scopes = await scope_service.list_scopes(limit=1000, offset=0)
            
            # Should include our created scopes
            returned_names = [scope.scope_name for scope in scopes]
            for scope_name in scope_names:
                assert scope_name in returned_names
            
            # Test pagination by getting a smaller list and ensuring it works
            small_list = await scope_service.list_scopes(limit=3, offset=0)
            assert len(small_list) <= 3

    @pytest.mark.asyncio
    async def test_get_default_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test getting default scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            scope_service = ScopeService(scope_repo)
            
            # Create scopes with one default
            default_scope = await scope_service.create_scope(
                "default_scope_" + uuid4().hex[:8], "Default scope", is_default=True
            )
            await scope_service.create_scope(
                "non_default_scope_" + uuid4().hex[:8], "Non-default scope", is_default=False
            )
            
            # Get default scopes
            default_scopes = await scope_service.get_default_scopes()
            
            # Should include our default scope
            default_names = [scope.scope_name for scope in default_scopes]
            assert default_scope.scope_name in default_names