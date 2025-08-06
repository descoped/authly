"""Tests for OAuth 2.1 Authorization Flow.

Tests authorization endpoints, service layer, and complete OAuth 2.1 authorization code flow.
"""

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.authorization_service import AuthorizationService
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    AuthorizationError,
    ClientType,
    CodeChallengeMethod,
    OAuthAuthorizationRequest,
    ResponseType,
    TokenEndpointAuthMethod,
    UserConsentRequest,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    # Generate code verifier (base64url-encoded random string)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")

    # Generate code challenge (SHA256 hash of verifier, base64url-encoded)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    return code_verifier, code_challenge


class TestAuthorizationService:
    """Test OAuth 2.1 Authorization Service business logic."""

    @pytest.mark.asyncio
    async def test_validate_authorization_request_success(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test successful authorization request validation."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Create test scope
            scope_data = {
                "scope_name": f"read_{uuid4().hex[:8]}",
                "description": "Read access",
                "is_default": True,
                "is_active": True,
            }
            await scope_repo.create_scope(scope_data)

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Create authorization request
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope=scope_data["scope_name"],
                state="test_state_123",
            )

            # Validate request
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            assert is_valid is True
            assert error_code is None
            assert client is not None
            assert client.client_id == created_client.client_id

    @pytest.mark.asyncio
    async def test_validate_authorization_request_invalid_client(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authorization request validation with invalid client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Create authorization request with non-existent client
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id="nonexistent_client",
                redirect_uri="https://client.example.com/callback",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="read",
                state="test_state_123",
            )

            # Validate request
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            assert is_valid is False
            assert error_code == AuthorizationError.UNAUTHORIZED_CLIENT
            assert client is None

    @pytest.mark.asyncio
    async def test_validate_authorization_request_invalid_redirect_uri(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authorization request validation with invalid redirect URI."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Create authorization request with invalid redirect URI
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="https://malicious.example.com/callback",  # Invalid redirect URI
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                scope="read",
                state="test_state_123",
            )

            # Validate request
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            assert is_valid is False
            assert error_code == AuthorizationError.INVALID_REQUEST
            assert client is None

    @pytest.mark.asyncio
    async def test_generate_authorization_code_success(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test successful authorization code generation."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            user_repo = UserRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user
            user_data = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            created_user = await user_repo.create(user_data)

            # Create test client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Create consent request
            consent_request = UserConsentRequest(
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                scope="read write",
                state="test_state_123",
                code_challenge=code_challenge,
                code_challenge_method=CodeChallengeMethod.S256,
                user_id=created_user.id,
                approved=True,
                approved_scopes=["read", "write"],
            )

            # Generate authorization code
            auth_code = await auth_service.generate_authorization_code(consent_request)

            assert auth_code is not None
            assert len(auth_code) > 0

            # Verify code was stored in database
            stored_code = await auth_code_repo.get_by_code(auth_code)
            assert stored_code is not None
            assert stored_code.client_id == created_client.id
            assert stored_code.user_id == created_user.id
            assert stored_code.code_challenge == code_challenge
            assert stored_code.is_valid()

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_success(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test successful authorization code exchange."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            user_repo = UserRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user
            user_data = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            created_user = await user_repo.create(user_data)

            # Create test client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Generate PKCE pair
            code_verifier, code_challenge = generate_pkce_pair()

            # Create authorization code directly
            auth_code_data = {
                "code": f"auth_code_{uuid4().hex}",
                "client_id": created_client.id,
                "user_id": created_user.id,
                "redirect_uri": "https://client.example.com/callback",
                "scope": "read write",
                "expires_at": datetime.now(UTC) + timedelta(minutes=10),
                "code_challenge": code_challenge,
                "code_challenge_method": CodeChallengeMethod.S256,
                "is_used": False,
            }
            created_auth_code = await auth_code_repo.create_authorization_code(auth_code_data)

            # Exchange authorization code
            success, code_data, error_msg = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=code_verifier,
            )

            assert success is True
            assert code_data is not None
            assert error_msg is None
            assert code_data["user_id"] == created_user.id
            assert code_data["client_id"] == created_client.client_id  # String client_id, not UUID
            assert code_data["scope"] == "read write"

            # Verify code was marked as used
            used_code = await auth_code_repo.get_by_code(created_auth_code.code)
            assert used_code.is_used is True

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_invalid_pkce(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authorization code exchange with invalid PKCE verifier."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            user_repo = UserRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test user
            user_data = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            created_user = await user_repo.create(user_data)

            # Create test client
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Generate PKCE pairs (different ones)
            code_verifier, code_challenge = generate_pkce_pair()
            wrong_verifier, _ = generate_pkce_pair()

            # Create authorization code
            auth_code_data = {
                "code": f"auth_code_{uuid4().hex}",
                "client_id": created_client.id,
                "user_id": created_user.id,
                "redirect_uri": "https://client.example.com/callback",
                "scope": "read write",
                "expires_at": datetime.now(UTC) + timedelta(minutes=10),
                "code_challenge": code_challenge,
                "code_challenge_method": CodeChallengeMethod.S256,
                "is_used": False,
            }
            created_auth_code = await auth_code_repo.create_authorization_code(auth_code_data)

            # Exchange with wrong verifier
            success, code_data, error_msg = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=wrong_verifier,
            )

            assert success is False
            assert code_data is None
            assert error_msg == "Invalid PKCE code verifier"


class TestPKCEUtilities:
    """Test PKCE helper utilities."""

    def test_generate_pkce_pair(self):
        """Test PKCE code verifier and challenge generation."""
        code_verifier, code_challenge = generate_pkce_pair()

        # Verify code verifier format (base64url, 43-128 chars)
        assert 43 <= len(code_verifier) <= 128
        # Base64url only uses [A-Za-z0-9_-] characters
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
        assert all(c in allowed_chars for c in code_verifier)

        # Verify code challenge format (base64url, 43-44 chars for SHA256)
        assert 43 <= len(code_challenge) <= 44
        assert all(c in allowed_chars for c in code_challenge)

        # Verify they are different
        assert code_verifier != code_challenge

    def test_pkce_challenge_verification(self):
        """Test PKCE challenge verification logic."""
        from authly.oauth.authorization_service import AuthorizationService

        # Create a mock service instance (we only need the verification method)
        service = AuthorizationService(None, None, None)

        code_verifier, code_challenge = generate_pkce_pair()

        # Valid verification should succeed
        assert service._verify_pkce_challenge(code_verifier, code_challenge) is True

        # Invalid verification should fail
        wrong_verifier, _ = generate_pkce_pair()
        assert service._verify_pkce_challenge(wrong_verifier, code_challenge) is False


class TestAuthorizationModels:
    """Test OAuth 2.1 Authorization models and validation."""

    def test_authorization_request_validation(self):
        """Test authorization request model validation."""
        code_verifier, code_challenge = generate_pkce_pair()

        # Valid request
        request = OAuthAuthorizationRequest(
            response_type=ResponseType.CODE,
            client_id="test_client",
            redirect_uri="https://client.example.com/callback",
            code_challenge=code_challenge,
            code_challenge_method=CodeChallengeMethod.S256,
            scope="read write",
            state="test_state",
        )

        assert request.response_type == ResponseType.CODE
        assert request.validate_pkce_params() is True
        assert request.get_scope_list() == ["read", "write"]

    def test_authorization_request_invalid_pkce(self):
        """Test authorization request with invalid PKCE parameters."""
        # Create request with minimum valid length but test validation logic
        code_verifier, code_challenge = generate_pkce_pair()

        request = OAuthAuthorizationRequest(
            response_type=ResponseType.CODE,
            client_id="test_client",
            redirect_uri="https://client.example.com/callback",
            code_challenge=code_challenge,
            code_challenge_method=CodeChallengeMethod.S256,
        )

        # Valid request should pass
        assert request.validate_pkce_params() is True

        # Test with too short challenge manually
        request.code_challenge = "short_challenge_12345678901234567890123"  # Still too short
        assert request.validate_pkce_params() is False

    def test_user_consent_request(self):
        """Test user consent request model."""
        code_verifier, code_challenge = generate_pkce_pair()

        consent = UserConsentRequest(
            client_id="test_client",
            redirect_uri="https://client.example.com/callback",
            scope="read write",
            state="test_state",
            code_challenge=code_challenge,
            code_challenge_method=CodeChallengeMethod.S256,
            user_id=uuid4(),
            approved=True,
            approved_scopes=["read", "write"],
        )

        assert consent.approved is True
        assert consent.approved_scopes == ["read", "write"]
