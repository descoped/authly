"""
Enhanced OIDC ID token validation tests.

Tests ID token structure, claims, signatures, and security requirements.
"""

import base64
import json
import time
from datetime import UTC, datetime
from uuid import uuid4

import jwt
import pytest
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager
from authly.oidc.scopes import OIDCScope
from authly.users import UserModel, UserRepository


class TestIDTokenStructure:
    """Test ID token structure and format."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_is_valid_jwt(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID tokens are valid JWTs with proper structure."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Create test data for ID token
            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"
            nonce = "test_nonce_123"

            # Generate ID token
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                nonce=nonce,
                scopes=[OIDCScope.OPENID, OIDCScope.PROFILE],
            )

            # Verify JWT structure (header.payload.signature)
            parts = id_token.split(".")
            assert len(parts) == 3

            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            assert "alg" in header
            assert "typ" in header
            assert header["typ"] == "JWT"

            # Decode payload (without verification for structure test)
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

            # Required claims per OIDC spec
            assert "iss" in payload  # Issuer
            assert "sub" in payload  # Subject (user ID)
            assert "aud" in payload  # Audience (client ID)
            assert "exp" in payload  # Expiration
            assert "iat" in payload  # Issued at
            assert "nonce" in payload  # Nonce (if provided)

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_required_claims(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID tokens contain all required OIDC claims."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"

            # Generate ID token
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                scopes=[OIDCScope.OPENID],
            )

            # Decode without verification
            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Check required claims
            assert payload["iss"] == initialize_authly.config.issuer_url
            assert payload["sub"] == user_id
            assert payload["aud"] == client_id

            # Check timestamps
            now = time.time()
            assert payload["iat"] <= now
            assert payload["exp"] > now
            assert payload["exp"] - payload["iat"] == 3600  # 1 hour default

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_auth_time_claim(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test auth_time claim when max_age is requested."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"
            auth_time = int(time.time()) - 300  # 5 minutes ago

            # Generate ID token with auth_time
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                auth_time=auth_time,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # auth_time should be present
            assert "auth_time" in payload
            assert payload["auth_time"] == auth_time


class TestIDTokenNonce:
    """Test ID token nonce handling."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_nonce_included_when_provided(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that nonce is included in ID token when provided in request."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"
            nonce = f"nonce_{uuid4().hex}"

            # Generate ID token with nonce
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                nonce=nonce,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Nonce should match exactly
            assert "nonce" in payload
            assert payload["nonce"] == nonce

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_nonce_not_included_when_not_provided(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that nonce is not included when not provided."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"

            # Generate ID token without nonce
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Nonce should not be present
            assert "nonce" not in payload

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_nonce_replay_protection(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that nonce provides replay protection."""
        # Nonce validation is typically done client-side
        # Server should faithfully echo the nonce
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Generate two tokens with same nonce
            nonce = f"unique_nonce_{uuid4().hex}"

            token1 = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="client1",
                nonce=nonce,
                scopes=[OIDCScope.OPENID],
            )

            token2 = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="client1",
                nonce=nonce,
                scopes=[OIDCScope.OPENID],
            )

            # Both should have the same nonce (server echoes it)
            payload1 = jwt.decode(token1, options={"verify_signature": False})
            payload2 = jwt.decode(token2, options={"verify_signature": False})

            assert payload1["nonce"] == nonce
            assert payload2["nonce"] == nonce

            # Client would track used nonces and reject duplicates


class TestIDTokenAtHash:
    """Test at_hash (access token hash) claim."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_at_hash_included_with_access_token(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that at_hash is included when ID token is issued with access token."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"
            access_token = f"access_token_{uuid4().hex}"

            # Generate ID token with access token hash
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                access_token=access_token,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # at_hash should be present
            assert "at_hash" in payload

            # Verify at_hash is correct (left half of hash of access token)
            # This depends on the algorithm used (typically RS256)
            import hashlib

            access_token_hash = hashlib.sha256(access_token.encode()).digest()
            expected_at_hash = (
                base64.urlsafe_b64encode(
                    access_token_hash[:16]  # Left half
                )
                .decode()
                .rstrip("=")
            )

            assert payload["at_hash"] == expected_at_hash

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_at_hash_not_included_without_access_token(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that at_hash is not included when no access token is issued."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            user_id = str(uuid4())
            client_id = f"test_client_{uuid4().hex[:8]}"

            # Generate ID token without access token
            id_token = token_service.create_id_token(
                user_id=user_id,
                client_id=client_id,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # at_hash should not be present
            assert "at_hash" not in payload


class TestIDTokenScopes:
    """Test ID token claims based on requested scopes."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_profile_scope_claims(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that profile scope adds appropriate claims."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Create user with profile data
            user_data = UserModel(
                id=uuid4(),
                username=f"testuser_{uuid4().hex[:8]}",
                email=f"test_{uuid4().hex[:8]}@example.com",
                password_hash="dummy_hash",
                given_name="John",
                family_name="Doe",
                nickname="Johnny",
                picture="https://example.com/photo.jpg",
                profile="https://example.com/profile",
                is_verified=True,
                is_admin=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
            created_user = await user_repo.create(user_data)

            # Generate ID token with profile scope
            id_token = token_service.create_id_token(
                user_id=str(created_user.id),
                client_id="test_client",
                scopes=[OIDCScope.OPENID, OIDCScope.PROFILE],
                user_claims={
                    "given_name": created_user.given_name,
                    "family_name": created_user.family_name,
                    "nickname": created_user.nickname,
                    "picture": created_user.picture,
                    "profile": created_user.profile,
                },
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Profile claims should be included
            assert payload.get("given_name") == "John"
            assert payload.get("family_name") == "Doe"
            assert payload.get("nickname") == "Johnny"
            assert payload.get("picture") == "https://example.com/photo.jpg"
            assert payload.get("profile") == "https://example.com/profile"

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_email_scope_claims(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that email scope adds email claims."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Create user with email
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

            # Generate ID token with email scope
            id_token = token_service.create_id_token(
                user_id=str(created_user.id),
                client_id="test_client",
                scopes=[OIDCScope.OPENID, OIDCScope.EMAIL],
                user_claims={
                    "email": created_user.email,
                    "email_verified": created_user.is_verified,
                },
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Email claims should be included
            assert "email" in payload
            assert "email_verified" in payload
            assert payload["email"] == created_user.email
            assert payload["email_verified"] is True


class TestIDTokenExpiration:
    """Test ID token expiration and lifetime."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_default_expiration(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID tokens have correct default expiration."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Generate ID token
            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="test_client",
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Check expiration (default should be 1 hour)
            exp_time = datetime.fromtimestamp(payload["exp"], tz=UTC)
            iat_time = datetime.fromtimestamp(payload["iat"], tz=UTC)

            lifetime = exp_time - iat_time
            assert lifetime.total_seconds() == 3600  # 1 hour

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_custom_expiration(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID tokens can have custom expiration."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Generate ID token with custom expiration
            custom_exp = int(time.time()) + 1800  # 30 minutes

            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="test_client",
                scopes=[OIDCScope.OPENID],
                expiration=custom_exp,
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Should use custom expiration
            assert payload["exp"] == custom_exp


class TestIDTokenSignature:
    """Test ID token signature validation."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_signature_verification(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID token signatures can be verified."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Generate ID token
            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="test_client",
                scopes=[OIDCScope.OPENID],
            )

            # Get public key for verification
            public_key = token_service.get_public_key()

            # Verify signature
            try:
                payload = jwt.decode(
                    id_token,
                    public_key,
                    algorithms=["RS256"],
                    audience="test_client",
                    issuer=initialize_authly.config.issuer_url,
                )
                assert payload["sub"] is not None  # Verification succeeded
            except jwt.InvalidTokenError as e:
                pytest.fail(f"Token verification failed: {e}")

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_invalid_signature_rejected(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test that ID tokens with invalid signatures are rejected."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Generate valid ID token
            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="test_client",
                scopes=[OIDCScope.OPENID],
            )

            # Tamper with signature
            parts = id_token.split(".")
            tampered_token = f"{parts[0]}.{parts[1]}.INVALID_SIGNATURE"

            # Get public key for verification
            public_key = token_service.get_public_key()

            # Verification should fail
            with pytest.raises(jwt.InvalidSignatureError):
                jwt.decode(
                    tampered_token,
                    public_key,
                    algorithms=["RS256"],
                    audience="test_client",
                    issuer=initialize_authly.config.issuer_url,
                )


class TestIDTokenAudience:
    """Test ID token audience validation."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_single_audience(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test ID token with single audience (client_id)."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            client_id = f"test_client_{uuid4().hex[:8]}"

            # Generate ID token
            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id=client_id,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # Audience should be the client_id
            assert payload["aud"] == client_id

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="TokenService not available in test context")
    async def test_id_token_multiple_audiences(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test ID token with multiple audiences."""
        async with transaction_manager.transaction():
            # OIDCTokenService not yet implemented
            pytest.skip("OIDCTokenService not yet implemented")

            # Multiple audiences (e.g., client and resource server)
            audiences = ["client_id", "https://api.example.com"]

            # Generate ID token with multiple audiences
            id_token = token_service.create_id_token(
                user_id=str(uuid4()),
                client_id="client_id",
                audiences=audiences,
                scopes=[OIDCScope.OPENID],
            )

            payload = jwt.decode(id_token, options={"verify_signature": False})

            # When multiple audiences, azp (authorized party) should be present
            if isinstance(payload["aud"], list):
                assert "azp" in payload
                assert payload["azp"] == "client_id"
