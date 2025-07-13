"""Integration tests for OAuth 2.1 repository layers using real database connections."""

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly import Authly
from authly.auth import get_password_hash
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    GrantType,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthScopeModel,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository

logger = logging.getLogger(__name__)


@pytest.fixture
async def test_user_data(initialize_authly: Authly):
    unique = uuid4().hex[:8]
    password_hash = get_password_hash("SecurePass123!")
    return {"username": f"testuser_{unique}", "email": f"test_{unique}@example.com", "password_hash": password_hash}


@pytest.fixture
async def test_user(
    initialize_authly: Authly, test_user_data: dict, transaction_manager: TransactionManager
) -> UserModel:
    """Create a test user in the database"""
    async with transaction_manager.transaction() as conn:
        user_repo = UserRepository(conn)
        user = UserModel(
            id=uuid4(),
            username=test_user_data["username"],
            email=test_user_data["email"],
            password_hash=test_user_data["password_hash"],  # Use password_hash directly
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=False,
            is_admin=False,
        )
        return await user_repo.create(user)


@pytest.fixture
async def test_client_data():
    """Test client data for OAuth client creation."""
    return {
        "client_id": "test_client_" + uuid4().hex[:8],
        "client_name": "Test OAuth Client",
        "client_type": ClientType.CONFIDENTIAL,
        "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        "redirect_uris": ["https://example.com/callback", "https://app.example.com/oauth/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        "client_secret": "test_secret_123",
        "is_active": True,
    }


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
async def test_authorization_code_data():
    """Test authorization code data."""
    return {
        "code": "test_code_" + uuid4().hex[:16],
        "redirect_uri": "https://example.com/callback",
        "scope": "read write",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
    }


class TestClientRepository:
    """Test cases for ClientRepository with real database integration."""

    @pytest.mark.asyncio
    async def test_create_client(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test creating an OAuth client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            created_client = await client_repo.create_client(test_client_data)

            assert created_client.client_id == test_client_data["client_id"]
            assert created_client.client_name == test_client_data["client_name"]
            assert created_client.client_type == test_client_data["client_type"]
            assert created_client.token_endpoint_auth_method == test_client_data["token_endpoint_auth_method"]
            assert created_client.redirect_uris == test_client_data["redirect_uris"]
            assert created_client.grant_types == test_client_data["grant_types"]
            assert created_client.is_active == test_client_data["is_active"]
            # Client secret should be hashed
            assert created_client.client_secret_hash != test_client_data["client_secret"]
            assert created_client.id is not None
            assert created_client.created_at is not None

    @pytest.mark.asyncio
    async def test_get_client_by_id(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test retrieving client by ID."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client first
            created_client = await client_repo.create_client(test_client_data)

            # Retrieve by ID
            retrieved_client = await client_repo.get_by_id(created_client.id)

            assert retrieved_client is not None
            assert retrieved_client.id == created_client.id
            assert retrieved_client.client_id == created_client.client_id
            assert retrieved_client.client_name == created_client.client_name

    @pytest.mark.asyncio
    async def test_get_client_by_client_id(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test retrieving client by client_id."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client first
            created_client = await client_repo.create_client(test_client_data)

            # Retrieve by client_id
            retrieved_client = await client_repo.get_by_client_id(created_client.client_id)

            assert retrieved_client is not None
            assert retrieved_client.client_id == created_client.client_id
            assert retrieved_client.client_name == created_client.client_name

    @pytest.mark.asyncio
    async def test_update_client(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test updating client information."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client first
            created_client = await client_repo.create_client(test_client_data)

            # Add a small delay to ensure different timestamps
            import asyncio

            await asyncio.sleep(0.001)  # 1ms delay

            # Update client
            update_data = {
                "client_name": "Updated Client Name",
                "redirect_uris": ["https://updated.example.com/callback"],
                "is_active": False,
            }

            updated_client = await client_repo.update_client(created_client.id, update_data)

            assert updated_client.client_name == update_data["client_name"]
            assert updated_client.redirect_uris == update_data["redirect_uris"]
            assert updated_client.is_active == update_data["is_active"]
            # Verify that updated_at is at least as recent as created_at (can be equal due to transaction timing)
            assert updated_client.updated_at >= created_client.updated_at

    @pytest.mark.asyncio
    async def test_delete_client(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test client deletion."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create client first
            created_client = await client_repo.create_client(test_client_data)

            # Delete client
            success = await client_repo.delete_client(created_client.id)
            assert success is True

            # Verify client is deleted (soft delete - marked as inactive)
            deleted_client = await client_repo.get_by_id(created_client.id)
            assert deleted_client is not None  # Still exists in database
            assert deleted_client.is_active is False  # But marked as inactive

    @pytest.mark.asyncio
    async def test_client_scope_association(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_scope_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test associating scopes with clients."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)

            # Create client and scope
            created_client = await client_repo.create_client(test_client_data)
            created_scope = await scope_repo.create_scope(test_scope_data)

            # Associate scope with client
            count = await client_repo.associate_client_scopes(created_client.id, [created_scope.id])
            assert count == 1

            # Verify association
            client_scopes = await client_repo.get_client_scopes(created_client.id)
            assert len(client_scopes) == 1
            assert client_scopes[0] == created_scope.scope_name

    @pytest.mark.asyncio
    async def test_duplicate_client_id(
        self, initialize_authly: Authly, test_client_data: dict, transaction_manager: TransactionManager
    ):
        """Test creating client with duplicate client_id raises error."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create first client
            await client_repo.create_client(test_client_data)

            # Try to create client with same client_id
            with pytest.raises(Exception):  # Should raise database constraint error
                await client_repo.create_client(test_client_data)


class TestScopeRepository:
    """Test cases for ScopeRepository with real database integration."""

    @pytest.mark.asyncio
    async def test_create_scope(
        self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager
    ):
        """Test creating an OAuth scope."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            created_scope = await scope_repo.create_scope(test_scope_data)

            assert created_scope.scope_name == test_scope_data["scope_name"]
            assert created_scope.description == test_scope_data["description"]
            assert created_scope.is_default == test_scope_data["is_default"]
            assert created_scope.is_active == test_scope_data["is_active"]
            assert created_scope.id is not None
            assert created_scope.created_at is not None

    @pytest.mark.asyncio
    async def test_get_scope_by_name(
        self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager
    ):
        """Test retrieving scope by name."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            # Create scope first
            created_scope = await scope_repo.create_scope(test_scope_data)

            # Retrieve by name
            retrieved_scope = await scope_repo.get_by_scope_name(created_scope.scope_name)

            assert retrieved_scope is not None
            assert retrieved_scope.id == created_scope.id
            assert retrieved_scope.scope_name == created_scope.scope_name

    @pytest.mark.asyncio
    async def test_get_active_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test retrieving active scopes with pagination."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            # Get initial count of active scopes
            initial_active_scopes = await scope_repo.get_active_scopes(limit=1000, offset=0)
            initial_count = len(initial_active_scopes)

            # Create multiple scopes with unique names
            created_scopes = []
            for i in range(5):
                scope_data = {
                    "scope_name": f"test_scope_{i}_{uuid4().hex[:8]}",
                    "description": f"Test scope {i}",
                    "is_default": i < 2,  # First 2 are default
                    "is_active": i != 4,  # Last one is inactive
                }
                created_scope = await scope_repo.create_scope(scope_data)
                created_scopes.append(created_scope)

            # Get active scopes after creation
            active_scopes = await scope_repo.get_active_scopes(limit=1000, offset=0)

            # Should have 4 more active scopes than before (excluding the inactive one)
            expected_active_count = initial_count + 4
            assert len(active_scopes) == expected_active_count, (
                f"Expected {expected_active_count} active scopes, got {len(active_scopes)}"
            )

            # Check that our created active scopes are in the results
            active_scope_names = [scope.scope_name for scope in active_scopes]
            expected_active_scopes = [scope for scope in created_scopes if scope.is_active]

            for expected_scope in expected_active_scopes:
                assert expected_scope.scope_name in active_scope_names, (
                    f"Expected scope '{expected_scope.scope_name}' not found in active scopes"
                )

    @pytest.mark.asyncio
    async def test_get_default_scopes(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test retrieving default scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            # Create scopes with some defaults
            default_scope_data = {
                "scope_name": "default_scope_" + uuid4().hex[:8],
                "description": "Default test scope",
                "is_default": True,
                "is_active": True,
            }
            non_default_scope_data = {
                "scope_name": "non_default_scope_" + uuid4().hex[:8],
                "description": "Non-default test scope",
                "is_default": False,
                "is_active": True,
            }

            created_default = await scope_repo.create_scope(default_scope_data)
            await scope_repo.create_scope(non_default_scope_data)

            # Get default scopes
            default_scopes = await scope_repo.get_default_scopes()

            # Should include our default scope
            default_scope_names = [scope.scope_name for scope in default_scopes]
            assert created_default.scope_name in default_scope_names

    @pytest.mark.asyncio
    async def test_validate_scope_names(self, initialize_authly: Authly, transaction_manager: TransactionManager):
        """Test validating scope names."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            # Create test scopes
            valid_scope_data = {
                "scope_name": "valid_scope_" + uuid4().hex[:8],
                "description": "Valid test scope",
                "is_default": False,
                "is_active": True,
            }
            invalid_scope_data = {
                "scope_name": "invalid_scope_" + uuid4().hex[:8],
                "description": "Invalid test scope",
                "is_default": False,
                "is_active": False,  # Inactive
            }

            created_valid = await scope_repo.create_scope(valid_scope_data)
            created_invalid = await scope_repo.create_scope(invalid_scope_data)

            # Validate scope names
            test_names = [created_valid.scope_name, created_invalid.scope_name, "nonexistent_scope"]
            valid_names = await scope_repo.validate_scope_names(test_names)

            # Should only return the active scope
            assert created_valid.scope_name in valid_names
            assert created_invalid.scope_name not in valid_names
            assert "nonexistent_scope" not in valid_names

    @pytest.mark.asyncio
    async def test_token_scope_association(
        self, initialize_authly: Authly, test_scope_data: dict, transaction_manager: TransactionManager
    ):
        """Test associating tokens with scopes."""
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)

            # Create scope
            created_scope = await scope_repo.create_scope(test_scope_data)

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
                updated_at=datetime.now(timezone.utc),
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
                created_at=datetime.now(timezone.utc),
            )
            created_token = await token_repo.store_token(token_model)

            # Associate token with scope
            count = await scope_repo.associate_token_scopes(created_token.id, [created_scope.id])
            assert count == 1

            # Verify association
            token_scopes = await scope_repo.get_scopes_for_token(created_token.id)
            assert len(token_scopes) == 1
            assert token_scopes[0].id == created_scope.id


class TestAuthorizationCodeRepository:
    """Test cases for AuthorizationCodeRepository with real database integration."""

    @pytest.mark.asyncio
    async def test_create_authorization_code(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_authorization_code_data: dict,
        test_user: UserModel,
        transaction_manager: TransactionManager,
    ):
        """Test creating an authorization code."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            authz_repo = AuthorizationCodeRepository(conn)

            # Create client first
            created_client = await client_repo.create_client(test_client_data)

            # Create authorization code
            code_data = {
                **test_authorization_code_data,
                "client_id": created_client.id,
                "user_id": test_user.id,
            }

            created_code = await authz_repo.create_authorization_code(code_data)

            assert created_code.code == code_data["code"]
            assert created_code.client_id == code_data["client_id"]
            assert created_code.user_id == code_data["user_id"]
            assert created_code.redirect_uri == code_data["redirect_uri"]
            assert created_code.scope == code_data["scope"]
            assert created_code.code_challenge == code_data["code_challenge"]
            assert created_code.code_challenge_method == code_data["code_challenge_method"]
            assert created_code.is_used is False
            assert created_code.id is not None

    @pytest.mark.asyncio
    async def test_get_authorization_code(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_authorization_code_data: dict,
        test_user: UserModel,
        transaction_manager: TransactionManager,
    ):
        """Test retrieving authorization code."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            authz_repo = AuthorizationCodeRepository(conn)

            # Create client and authorization code
            created_client = await client_repo.create_client(test_client_data)
            code_data = {
                **test_authorization_code_data,
                "client_id": created_client.id,
                "user_id": test_user.id,
            }
            created_code = await authz_repo.create_authorization_code(code_data)

            # Retrieve authorization code
            retrieved_code = await authz_repo.get_by_code(created_code.code)

            assert retrieved_code is not None
            assert retrieved_code.id == created_code.id
            assert retrieved_code.code == created_code.code
            assert retrieved_code.client_id == created_code.client_id

    @pytest.mark.asyncio
    async def test_consume_authorization_code(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_authorization_code_data: dict,
        test_user: UserModel,
        transaction_manager: TransactionManager,
    ):
        """Test consuming (marking as used) authorization code."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            authz_repo = AuthorizationCodeRepository(conn)

            # Create client and authorization code
            created_client = await client_repo.create_client(test_client_data)
            code_data = {
                **test_authorization_code_data,
                "client_id": created_client.id,
                "user_id": test_user.id,
            }
            created_code = await authz_repo.create_authorization_code(code_data)

            # Consume the code
            consumed_code = await authz_repo.consume_authorization_code(created_code.code)

            assert consumed_code is not None
            assert consumed_code.is_used is True
            assert consumed_code.used_at is not None

            # Try to consume again - should return None
            second_consume = await authz_repo.consume_authorization_code(created_code.code)
            assert second_consume is None

    @pytest.mark.asyncio
    async def test_verify_pkce_challenge(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_authorization_code_data: dict,
        test_user: UserModel,
        transaction_manager: TransactionManager,
    ):
        """Test PKCE challenge verification."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            authz_repo = AuthorizationCodeRepository(conn)

            # Create client and authorization code
            created_client = await client_repo.create_client(test_client_data)
            code_data = {
                **test_authorization_code_data,
                "client_id": created_client.id,
                "user_id": test_user.id,
            }
            created_code = await authz_repo.create_authorization_code(code_data)

            # Test PKCE verification with correct verifier
            correct_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # Matches the challenge
            is_valid = await authz_repo.verify_pkce_challenge(created_code.code, correct_verifier)
            assert is_valid is True

            # Test PKCE verification with incorrect verifier
            incorrect_verifier = "wrong_verifier"
            is_valid = await authz_repo.verify_pkce_challenge(created_code.code, incorrect_verifier)
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_cleanup_expired_codes(
        self,
        initialize_authly: Authly,
        test_client_data: dict,
        test_user: UserModel,
        transaction_manager: TransactionManager,
    ):
        """Test cleanup of expired authorization codes."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            authz_repo = AuthorizationCodeRepository(conn)

            # Create client
            created_client = await client_repo.create_client(test_client_data)

            # Create expired code
            expired_code_data = {
                "code": "expired_code_" + uuid4().hex[:16],
                "client_id": created_client.id,
                "user_id": test_user.id,
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "expires_at": datetime.now(timezone.utc) - timedelta(minutes=10),  # Already expired
            }

            # Create valid code
            valid_code_data = {
                "code": "valid_code_" + uuid4().hex[:16],
                "client_id": created_client.id,
                "user_id": test_user.id,
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),  # Still valid
            }

            expired_code = await authz_repo.create_authorization_code(expired_code_data)
            valid_code = await authz_repo.create_authorization_code(valid_code_data)

            # Cleanup expired codes
            cleanup_count = await authz_repo.cleanup_expired_codes()
            assert cleanup_count >= 1  # Should have cleaned up at least our expired code

            # Verify expired code is gone
            retrieved_expired = await authz_repo.get_by_code(expired_code.code)
            assert retrieved_expired is None

            # Verify valid code is still there
            retrieved_valid = await authz_repo.get_by_code(valid_code.code)
            assert retrieved_valid is not None
