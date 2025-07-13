"""
Tests for OIDC ID Token functionality.

This module tests the OpenID Connect ID token generation and validation.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from jose import JWTError, jwt

from authly.config import AuthlyConfig
from authly.oauth.models import OAuthClientModel
from authly.oidc.id_token import (
    IDTokenClaims,
    IDTokenGenerator,
    IDTokenService,
    create_id_token_service,
    validate_id_token_scopes,
)
from authly.users.models import UserModel


class TestIDTokenGenerator:
    """Test ID token generator functionality."""
    
    @pytest.fixture
    def config(self, test_config):
        """Use existing test configuration."""
        return test_config
    
    @pytest.fixture
    def generator(self, config):
        """Create ID token generator."""
        return IDTokenGenerator(config)
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user_id = uuid4()
        return UserModel(
            id=user_id,
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False
        )
    
    @pytest.fixture
    def test_client(self):
        """Create test OAuth client."""
        from authly.oauth.models import ClientType
        client_id = str(uuid4())
        return OAuthClientModel(
            id=uuid4(),
            client_id=client_id,
            client_secret_hash="test_secret_hash",
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    def test_generate_id_token_basic(self, generator, test_user, test_client):
        """Test basic ID token generation."""
        scopes = ["openid", "profile"]
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode token to verify structure
        claims = jwt.get_unverified_claims(token)
        
        # Check required claims
        assert claims[IDTokenClaims.ISS] == generator.issuer
        assert claims[IDTokenClaims.SUB] == str(test_user.id)
        assert claims[IDTokenClaims.AUD] == str(test_client.client_id)
        assert IDTokenClaims.EXP in claims
        assert IDTokenClaims.IAT in claims
        assert IDTokenClaims.AUTH_TIME in claims
    
    def test_generate_id_token_with_nonce(self, generator, test_user, test_client):
        """Test ID token generation with nonce."""
        scopes = ["openid"]
        nonce = "test_nonce_value"
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes,
            nonce=nonce
        )
        
        claims = jwt.get_unverified_claims(token)
        assert claims[IDTokenClaims.NONCE] == nonce
    
    def test_generate_id_token_with_auth_time(self, generator, test_user, test_client):
        """Test ID token generation with specific auth time."""
        scopes = ["openid"]
        auth_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes,
            auth_time=auth_time
        )
        
        claims = jwt.get_unverified_claims(token)
        assert claims[IDTokenClaims.AUTH_TIME] == int(auth_time.timestamp())
    
    def test_generate_id_token_with_profile_claims(self, generator, test_user, test_client):
        """Test ID token generation with profile claims."""
        scopes = ["openid", "profile"]
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        claims = jwt.get_unverified_claims(token)
        
        # Should include profile claims
        assert claims.get("preferred_username") == test_user.username
        assert claims.get("name") == test_user.username  # Fallback to username
    
    def test_generate_id_token_with_email_claims(self, generator, test_user, test_client):
        """Test ID token generation with email claims."""
        scopes = ["openid", "email"]
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        claims = jwt.get_unverified_claims(token)
        
        # Should include email claims
        assert claims.get("email") == test_user.email
        assert claims.get("email_verified") == test_user.is_verified
    
    def test_generate_id_token_with_additional_claims(self, generator, test_user, test_client):
        """Test ID token generation with additional claims."""
        scopes = ["openid"]
        additional_claims = {
            "custom_claim": "custom_value",
            "another_claim": 42
        }
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes,
            additional_claims=additional_claims
        )
        
        claims = jwt.get_unverified_claims(token)
        
        # Should include additional claims
        assert claims.get("custom_claim") == "custom_value"
        assert claims.get("another_claim") == 42
    
    def test_generate_id_token_without_openid_scope(self, generator, test_user, test_client):
        """Test ID token generation fails without openid scope."""
        scopes = ["profile", "email"]  # No openid scope
        
        with pytest.raises(HTTPException) as exc_info:
            generator.generate_id_token(
                user=test_user,
                client=test_client,
                scopes=scopes
            )
        
        assert exc_info.value.status_code == 400
        assert "openid" in str(exc_info.value.detail)
    
    def test_validate_id_token_valid(self, generator, test_user, test_client):
        """Test validation of valid ID token."""
        scopes = ["openid", "profile"]
        
        # Generate token
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        # Validate token
        claims = generator.validate_id_token(token, str(test_client.client_id))
        
        assert claims[IDTokenClaims.SUB] == str(test_user.id)
        assert claims[IDTokenClaims.AUD] == str(test_client.client_id)
        assert claims[IDTokenClaims.ISS] == generator.issuer
    
    def test_validate_id_token_invalid_signature(self, generator, test_client):
        """Test validation of token with invalid signature."""
        # Create token with wrong RSA key - we'll simulate this by creating a token with a different key
        # and then validating it with the correct generator
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate a different RSA key pair
        wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_private_key_pem = wrong_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        claims = {
            IDTokenClaims.ISS: generator.issuer,
            IDTokenClaims.SUB: str(uuid4()),
            IDTokenClaims.AUD: str(test_client.client_id),
            IDTokenClaims.EXP: int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
            IDTokenClaims.IAT: int(datetime.now(timezone.utc).timestamp()),
        }
        
        # Create token with wrong key but valid key ID format
        invalid_token = jwt.encode(
            claims, 
            wrong_private_key_pem, 
            algorithm="RS256",
            headers={"kid": "wrong_key_id"}
        )
        
        with pytest.raises(HTTPException) as exc_info:
            generator.validate_id_token(invalid_token, str(test_client.client_id))
        
        assert exc_info.value.status_code == 401
    
    def test_validate_id_token_expired(self, generator, test_client):
        """Test validation of expired token."""
        # Create expired token using the current signing key
        from cryptography.hazmat.primitives import serialization

        from authly.oidc.jwks import get_current_signing_key
        
        signing_key = get_current_signing_key()
        if not signing_key:
            pytest.skip("No signing key available for test")
        
        private_key_pem = signing_key.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create expired token
        expired_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        claims = {
            IDTokenClaims.ISS: generator.issuer,
            IDTokenClaims.SUB: str(uuid4()),
            IDTokenClaims.AUD: str(test_client.client_id),
            IDTokenClaims.EXP: int(expired_time.timestamp()),
            IDTokenClaims.IAT: int((expired_time - timedelta(minutes=15)).timestamp()),
        }
        
        expired_token = jwt.encode(
            claims, 
            private_key_pem, 
            algorithm=generator.algorithm,
            headers={"kid": signing_key.key_id}
        )
        
        with pytest.raises(HTTPException) as exc_info:
            generator.validate_id_token(expired_token, str(test_client.client_id))
        
        assert exc_info.value.status_code == 401
    
    def test_validate_id_token_wrong_audience(self, generator, test_user, test_client):
        """Test validation of token with wrong audience."""
        scopes = ["openid"]
        
        # Generate token for one client
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        # Try to validate with different client ID
        wrong_client_id = str(uuid4())
        
        with pytest.raises(HTTPException) as exc_info:
            generator.validate_id_token(token, wrong_client_id)
        
        assert exc_info.value.status_code == 401
        assert "audience" in str(exc_info.value.detail)
    
    def test_extract_user_id(self, generator, test_user, test_client):
        """Test extracting user ID from token."""
        scopes = ["openid"]
        
        token = generator.generate_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        extracted_user_id = generator.extract_user_id(token)
        assert extracted_user_id == test_user.id
    
    def test_extract_user_id_invalid_token(self, generator):
        """Test extracting user ID from invalid token."""
        invalid_token = "invalid.jwt.token"
        
        with pytest.raises(HTTPException) as exc_info:
            generator.extract_user_id(invalid_token)
        
        assert exc_info.value.status_code == 401


class TestIDTokenService:
    """Test ID token service functionality."""
    
    @pytest.fixture
    def config(self, test_config):
        """Use existing test configuration."""
        return test_config
    
    @pytest.fixture
    def service(self, config):
        """Create ID token service."""
        return IDTokenService(config)
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user_id = uuid4()
        return UserModel(
            id=user_id,
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False
        )
    
    @pytest.fixture
    def test_client(self):
        """Create test OAuth client."""
        from authly.oauth.models import ClientType
        client_id = str(uuid4())
        return OAuthClientModel(
            id=uuid4(),
            client_id=client_id,
            client_secret_hash="test_secret_hash",
            client_name="Test Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    @pytest.mark.asyncio
    async def test_create_id_token(self, service, test_user, test_client):
        """Test creating ID token through service."""
        scopes = ["openid", "profile", "email"]
        
        token = await service.create_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token structure
        claims = jwt.get_unverified_claims(token)
        assert claims[IDTokenClaims.SUB] == str(test_user.id)
        assert claims[IDTokenClaims.AUD] == str(test_client.client_id)
    
    @pytest.mark.asyncio
    async def test_validate_id_token_service(self, service, test_user, test_client):
        """Test validating ID token through service."""
        scopes = ["openid"]
        
        # Create token
        token = await service.create_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        # Validate token
        claims = await service.validate_id_token(token, str(test_client.client_id))
        
        assert claims[IDTokenClaims.SUB] == str(test_user.id)
        assert claims[IDTokenClaims.AUD] == str(test_client.client_id)
    
    @pytest.mark.asyncio
    async def test_get_user_id_from_token(self, service, test_user, test_client):
        """Test getting user ID from token through service."""
        scopes = ["openid"]
        
        # Create token
        token = await service.create_id_token(
            user=test_user,
            client=test_client,
            scopes=scopes
        )
        
        # Extract user ID
        user_id = await service.get_user_id_from_token(token)
        assert user_id == test_user.id


class TestIDTokenUtilities:
    """Test ID token utility functions."""
    
    def test_create_id_token_service(self, test_config):
        """Test creating ID token service."""
        config = test_config
        
        service = create_id_token_service(config)
        assert isinstance(service, IDTokenService)
    
    def test_validate_id_token_scopes_valid(self):
        """Test validating OIDC scopes for ID token."""
        # Valid OIDC scopes
        scopes = ["openid", "profile", "email"]
        assert validate_id_token_scopes(scopes) is True
    
    def test_validate_id_token_scopes_invalid(self):
        """Test validating non-OIDC scopes for ID token."""
        # No openid scope
        scopes = ["profile", "email"]
        assert validate_id_token_scopes(scopes) is False
        
        # Empty scopes
        scopes = []
        assert validate_id_token_scopes(scopes) is False


class TestIDTokenClaims:
    """Test ID token claims handling."""
    
    def test_user_claims_extraction(self, test_config):
        """Test extraction of user claims from user model."""
        config = test_config
        
        generator = IDTokenGenerator(config)
        
        user = UserModel(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False
        )
        
        # Test profile claims
        profile_scopes = ["openid", "profile"]
        profile_claims = generator._extract_user_claims(user, profile_scopes)
        
        assert "preferred_username" in profile_claims
        assert "name" in profile_claims
        assert profile_claims["preferred_username"] == user.username
        assert profile_claims["name"] == user.username
        
        # Test email claims
        email_scopes = ["openid", "email"]
        email_claims = generator._extract_user_claims(user, email_scopes)
        
        assert "email" in email_claims
        assert "email_verified" in email_claims
        assert email_claims["email"] == user.email
        assert email_claims["email_verified"] == user.is_verified
        
        # Test no extra claims for basic openid
        basic_scopes = ["openid"]
        basic_claims = generator._extract_user_claims(user, basic_scopes)
        
        # Should not include profile or email claims
        assert "preferred_username" not in basic_claims
        assert "email" not in basic_claims

    def test_get_user_name_method(self, test_config):
        """Test _get_user_name method."""
        config = test_config
        generator = IDTokenGenerator(config)
        
        user = UserModel(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True,
            is_verified=True,
            is_admin=False
        )
        
        # Test that it returns username as fallback
        name = generator._get_user_name(user)
        assert name == user.username

    def test_validate_id_token_claims_method(self, test_config):
        """Test _validate_id_token_claims method."""
        config = test_config
        generator = IDTokenGenerator(config)
        
        client_id = "test_client_id"
        now = datetime.now(timezone.utc)
        
        # Valid claims
        valid_claims = {
            IDTokenClaims.ISS: generator.issuer,
            IDTokenClaims.SUB: str(uuid4()),
            IDTokenClaims.AUD: client_id,
            IDTokenClaims.EXP: int((now + timedelta(minutes=15)).timestamp()),
            IDTokenClaims.IAT: int(now.timestamp()),
        }
        
        # Should not raise exception
        generator._validate_id_token_claims(valid_claims, client_id)
        
        # Test missing required claim
        invalid_claims = valid_claims.copy()
        del invalid_claims[IDTokenClaims.ISS]
        
        with pytest.raises(HTTPException) as exc_info:
            generator._validate_id_token_claims(invalid_claims, client_id)
        assert exc_info.value.status_code == 401
        assert "Missing required claim: iss" in str(exc_info.value.detail)
        
        # Test invalid issuer
        invalid_claims = valid_claims.copy()
        invalid_claims[IDTokenClaims.ISS] = "wrong_issuer"
        
        with pytest.raises(HTTPException) as exc_info:
            generator._validate_id_token_claims(invalid_claims, client_id)
        assert exc_info.value.status_code == 401
        assert "Invalid issuer" in str(exc_info.value.detail)
        
        # Test invalid audience
        invalid_claims = valid_claims.copy()
        invalid_claims[IDTokenClaims.AUD] = "wrong_audience"
        
        with pytest.raises(HTTPException) as exc_info:
            generator._validate_id_token_claims(invalid_claims, client_id)
        assert exc_info.value.status_code == 401
        assert "Invalid audience" in str(exc_info.value.detail)
        
        # Test expired token
        invalid_claims = valid_claims.copy()
        invalid_claims[IDTokenClaims.EXP] = int((now - timedelta(minutes=30)).timestamp())
        
        with pytest.raises(HTTPException) as exc_info:
            generator._validate_id_token_claims(invalid_claims, client_id)
        assert exc_info.value.status_code == 401
        assert "Token has expired" in str(exc_info.value.detail)