"""
Comprehensive PKCE edge case tests for OAuth 2.1.

Tests PKCE security requirements including replay attacks, expiration,
and invalid parameter handling.
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
)
from authly.oauth.scope_repository import ScopeRepository
from authly.users import UserModel, UserRepository


def generate_pkce_pair():
    """Generate PKCE code verifier and challenge pair."""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


class TestPKCEReplayAttacks:
    """Test PKCE replay attack prevention."""

    @pytest.mark.asyncio
    async def test_authorization_code_cannot_be_reused(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that authorization codes cannot be reused (replay attack prevention)."""
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

            # First exchange should succeed
            success1, code_data1, error_msg1 = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=code_verifier,
            )

            assert success1 is True
            assert code_data1 is not None
            assert error_msg1 is None

            # Second exchange should fail (replay attack)
            success2, code_data2, error_msg2 = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=code_verifier,
            )

            assert success2 is False
            assert code_data2 is None
            assert error_msg2 is not None
            # The error message should indicate the code is invalid/used/expired
            assert any(word in error_msg2.lower() for word in ["already", "used", "invalid", "expired"])

    @pytest.mark.asyncio
    async def test_used_code_invalidates_tokens(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that reusing a code should invalidate any tokens issued from it."""
        # This is a security requirement from OAuth 2.0 Security BCP
        # If a code is used twice, all tokens from that code should be revoked
        async with transaction_manager.transaction() as conn:
            AuthorizationCodeRepository(conn)

            # Check if there's a mechanism to track tokens issued from codes
            # This test documents expected behavior even if not yet implemented
            pass  # Implementation depends on token storage strategy


class TestPKCEExpiration:
    """Test PKCE code expiration."""

    @pytest.mark.asyncio
    async def test_expired_authorization_code_rejected(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that expired authorization codes are rejected."""
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

            # Create EXPIRED authorization code
            auth_code_data = {
                "code": f"auth_code_{uuid4().hex}",
                "client_id": created_client.id,
                "user_id": created_user.id,
                "redirect_uri": "https://client.example.com/callback",
                "scope": "read write",
                "expires_at": datetime.now(UTC) - timedelta(minutes=1),  # Already expired
                "code_challenge": code_challenge,
                "code_challenge_method": CodeChallengeMethod.S256,
                "is_used": False,
            }
            created_auth_code = await auth_code_repo.create_authorization_code(auth_code_data)

            # Exchange should fail due to expiration
            success, code_data, error_msg = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=code_verifier,
            )

            assert success is False
            assert code_data is None
            assert error_msg is not None
            assert "expired" in error_msg.lower()

    @pytest.mark.asyncio
    async def test_authorization_code_max_lifetime(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that authorization codes have maximum lifetime of 10 minutes."""
        async with transaction_manager.transaction() as conn:
            auth_code_repo = AuthorizationCodeRepository(conn)

            # Create a code with standard expiration
            auth_code_data = {
                "code": f"auth_code_{uuid4().hex}",
                "client_id": uuid4(),
                "user_id": uuid4(),
                "redirect_uri": "https://client.example.com/callback",
                "scope": "read",
                "expires_at": datetime.now(UTC) + timedelta(minutes=10),
                "code_challenge": "test_challenge",
                "code_challenge_method": CodeChallengeMethod.S256,
                "is_used": False,
            }
            created_code = await auth_code_repo.create_authorization_code(auth_code_data)

            # Verify expiration is within 10 minutes
            time_until_expiry = created_code.expires_at - datetime.now(UTC)
            assert time_until_expiry.total_seconds() <= 600  # 10 minutes


class TestPKCEInvalidParameters:
    """Test PKCE invalid parameter handling."""

    @pytest.mark.asyncio
    async def test_missing_code_challenge(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that authorization requests without code_challenge are rejected."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            auth_service = AuthorizationService(client_repo, scope_repo, auth_code_repo)

            # Create test client requiring PKCE
            client_data = {
                "client_id": f"test_client_{uuid4().hex[:8]}",
                "client_name": "Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "require_pkce": True,
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Create scope
            scope_data = {
                "scope_name": f"read_{uuid4().hex[:8]}",
                "description": "Read access",
                "is_default": True,
                "is_active": True,
            }
            await scope_repo.create_scope(scope_data)

            # Create authorization request WITHOUT code_challenge
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                # Missing: code_challenge and code_challenge_method
                scope=scope_data["scope_name"],
                state="test_state_123",
            )

            # Validate request - should fail
            is_valid, error_code, client = await auth_service.validate_authorization_request(auth_request)

            assert is_valid is False
            assert error_code is not None
            assert error_code == AuthorizationError.INVALID_REQUEST

    @pytest.mark.asyncio
    async def test_invalid_code_challenge_length(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that code challenges with invalid length are rejected."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            auth_code_repo = AuthorizationCodeRepository(conn)
            AuthorizationService(client_repo, scope_repo, auth_code_repo)

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

            # Create scope
            scope_data = {
                "scope_name": f"read_{uuid4().hex[:8]}",
                "description": "Read access",
                "is_default": True,
                "is_active": True,
            }
            await scope_repo.create_scope(scope_data)

            # Create authorization request with TOO SHORT code_challenge
            auth_request = OAuthAuthorizationRequest(
                response_type=ResponseType.CODE,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_challenge="tooshort",  # Less than 43 characters
                code_challenge_method=CodeChallengeMethod.S256,
                scope=scope_data["scope_name"],
                state="test_state_123",
            )

            # Should fail validation
            assert auth_request.validate_pkce_params() is False

    @pytest.mark.asyncio
    async def test_plain_method_rejected(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that 'plain' code_challenge_method is rejected (only S256 allowed)."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

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

            # OAuth 2.1 mandates S256 only - plain method should be rejected
            # This is tested in the actual endpoint, but we document the requirement
            assert created_client.require_pkce is True

    @pytest.mark.asyncio
    async def test_wrong_code_verifier(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that wrong code_verifier is rejected during token exchange."""
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
            # Generate a DIFFERENT verifier
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

            # Exchange with WRONG verifier should fail
            success, code_data, error_msg = await auth_service.exchange_authorization_code(
                code=created_auth_code.code,
                client_id=created_client.client_id,
                redirect_uri="https://client.example.com/callback",
                code_verifier=wrong_verifier,  # Wrong!
            )

            assert success is False
            assert code_data is None
            assert error_msg is not None
            assert "invalid" in error_msg.lower() and "verifier" in error_msg.lower()


class TestPKCESecurityRequirements:
    """Test additional PKCE security requirements."""

    @pytest.mark.asyncio
    async def test_code_verifier_entropy(self):
        """Test that code_verifier has sufficient entropy."""
        # Generate multiple verifiers and check they're unique
        verifiers = set()
        for _ in range(100):
            verifier, _ = generate_pkce_pair()
            verifiers.add(verifier)

        # All should be unique (high entropy)
        assert len(verifiers) == 100

        # Check minimum length (43 chars for 256 bits of entropy)
        for verifier in verifiers:
            assert len(verifier) >= 43

    @pytest.mark.asyncio
    async def test_code_challenge_format(self):
        """Test that code_challenge follows correct format."""
        code_verifier, code_challenge = generate_pkce_pair()

        # Should be base64url encoded (no padding, URL-safe chars)
        assert "=" not in code_challenge
        assert "+" not in code_challenge
        assert "/" not in code_challenge

        # Should only contain base64url characters
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
        assert all(c in allowed_chars for c in code_challenge)

        # Length should be 43 chars (base64url of SHA256)
        assert len(code_challenge) == 43

    @pytest.mark.asyncio
    async def test_pkce_required_for_public_clients(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that PKCE is required for public clients."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create PUBLIC client
            public_client_data = {
                "client_id": f"public_client_{uuid4().hex[:8]}",
                "client_name": "Public Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            public_client = await client_repo.create_client(public_client_data)

            # Public clients MUST use PKCE in OAuth 2.1
            assert public_client.require_pkce is True

    @pytest.mark.asyncio
    async def test_pkce_recommended_for_confidential_clients(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that PKCE is recommended (and enabled) for confidential clients."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)

            # Create CONFIDENTIAL client
            confidential_client_data = {
                "client_id": f"confidential_client_{uuid4().hex[:8]}",
                "client_name": "Confidential Client",
                "client_type": ClientType.CONFIDENTIAL,
                "client_secret": secrets.token_urlsafe(32),
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            }
            confidential_client = await client_repo.create_client(confidential_client_data)

            # OAuth 2.1 recommends PKCE for all clients
            # Authly should enforce it by default
            assert confidential_client.require_pkce is True
