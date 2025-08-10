"""
Tests for OpenID Connect JWKS (JSON Web Key Set) functionality.
"""

import base64
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from authly.oidc.jwks import (
    JWKModel,
    JWKSManager,
    JWKSModel,
    JWKSService,
    get_current_signing_key,
    get_jwks_manager,
    get_jwks_response,
    get_key_for_verification,
)


class TestJWKSService:
    """Test JWKS service functionality."""

    @pytest.fixture
    def jwks_service(self):
        """Create JWKS service instance."""
        return JWKSService()

    async def test_generate_rsa_key_pair(self, jwks_service):
        """Test RSA key pair generation."""
        key_pair = await jwks_service.generate_rsa_key_pair()

        assert key_pair is not None
        assert key_pair.private_key is not None
        assert key_pair.public_key is not None
        assert key_pair.key_id is not None
        assert key_pair.key_id.startswith("key_")
        assert key_pair.algorithm == "RS256"
        assert isinstance(key_pair.created_at, datetime)

    async def test_generate_rsa_key_pair_custom_params(self, jwks_service):
        """Test RSA key pair generation with custom parameters."""
        key_pair = await jwks_service.generate_rsa_key_pair(key_size=3072, algorithm="RS384")

        assert key_pair.algorithm == "RS384"
        assert key_pair.private_key.key_size == 3072

    async def test_get_current_key_pair(self, jwks_service):
        """Test getting current key pair."""
        # Initially no current key
        assert jwks_service.get_current_key_pair() is None

        # Generate key pair
        key_pair = await jwks_service.generate_rsa_key_pair()

        # Should now have current key
        current_key = jwks_service.get_current_key_pair()
        assert current_key is not None
        assert current_key.key_id == key_pair.key_id

    async def test_get_key_pair_by_id(self, jwks_service):
        """Test getting key pair by ID."""
        key_pair = await jwks_service.generate_rsa_key_pair()

        # Get by ID
        retrieved_key = jwks_service.get_key_pair(key_pair.key_id)
        assert retrieved_key is not None
        assert retrieved_key.key_id == key_pair.key_id

        # Non-existent ID
        assert jwks_service.get_key_pair("nonexistent") is None

    async def test_get_all_key_pairs(self, jwks_service):
        """Test getting all key pairs."""
        assert len(jwks_service.get_all_key_pairs()) == 0

        # Generate multiple key pairs
        key1 = await jwks_service.generate_rsa_key_pair()
        key2 = await jwks_service.generate_rsa_key_pair()

        all_keys = jwks_service.get_all_key_pairs()
        assert len(all_keys) == 2
        assert any(k.key_id == key1.key_id for k in all_keys)
        assert any(k.key_id == key2.key_id for k in all_keys)

    async def test_convert_to_jwk(self, jwks_service):
        """Test converting key pair to JWK format."""
        key_pair = await jwks_service.generate_rsa_key_pair()
        jwk = jwks_service.convert_to_jwk(key_pair)

        assert isinstance(jwk, JWKModel)
        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.alg == "RS256"
        assert jwk.kid == key_pair.key_id
        assert jwk.n is not None
        assert jwk.e is not None
        assert isinstance(jwk.n, str)
        assert isinstance(jwk.e, str)

    async def test_convert_to_jwk_rsa_values(self, jwks_service):
        """Test that JWK contains correct RSA values."""
        key_pair = await jwks_service.generate_rsa_key_pair()
        jwk = jwks_service.convert_to_jwk(key_pair)

        # Get public key numbers
        public_numbers = key_pair.public_key.public_numbers()

        # Decode JWK values
        n_bytes = base64.urlsafe_b64decode(jwk.n + "==")
        e_bytes = base64.urlsafe_b64decode(jwk.e + "==")

        # Convert bytes back to integers
        n_int = int.from_bytes(n_bytes, byteorder="big")
        e_int = int.from_bytes(e_bytes, byteorder="big")

        # Should match original key
        assert n_int == public_numbers.n
        assert e_int == public_numbers.e

    async def test_get_jwks(self, jwks_service):
        """Test getting JWKS response."""
        # No keys initially
        jwks = jwks_service.get_jwks()
        assert isinstance(jwks, JWKSModel)
        assert len(jwks.keys) == 0

        # Generate keys
        key1 = await jwks_service.generate_rsa_key_pair(algorithm="RS256")
        key2 = await jwks_service.generate_rsa_key_pair(algorithm="RS384")

        # Get JWKS
        jwks = jwks_service.get_jwks()
        assert len(jwks.keys) == 2

        # Check keys are correctly converted
        key_ids = [jwk.kid for jwk in jwks.keys]
        assert key1.key_id in key_ids
        assert key2.key_id in key_ids

        # Check algorithms
        algorithms = [jwk.alg for jwk in jwks.keys]
        assert "RS256" in algorithms
        assert "RS384" in algorithms

    async def test_rotate_keys(self, jwks_service):
        """Test key rotation."""
        # Generate initial key
        old_key = await jwks_service.generate_rsa_key_pair()
        old_key_id = old_key.key_id

        # Rotate keys
        new_key = await jwks_service.rotate_keys(algorithm="RS384")

        # Should have new current key
        current_key = jwks_service.get_current_key_pair()
        assert current_key.key_id == new_key.key_id
        assert current_key.algorithm == "RS384"

        # Should still have old key
        old_key_retrieved = jwks_service.get_key_pair(old_key_id)
        assert old_key_retrieved is not None

        # Should have both keys in JWKS
        jwks = jwks_service.get_jwks()
        assert len(jwks.keys) == 2

    async def test_remove_key(self, jwks_service):
        """Test key removal."""
        key1 = await jwks_service.generate_rsa_key_pair()
        key2 = await jwks_service.generate_rsa_key_pair()

        # Remove key
        assert jwks_service.remove_key(key1.key_id) is True
        assert jwks_service.get_key_pair(key1.key_id) is None
        assert jwks_service.get_key_pair(key2.key_id) is not None

        # Remove non-existent key
        assert jwks_service.remove_key("nonexistent") is False

    async def test_remove_current_key(self, jwks_service):
        """Test removing current key."""
        key1 = await jwks_service.generate_rsa_key_pair()
        current_key = jwks_service.get_current_key_pair()
        assert current_key.key_id == key1.key_id

        # Remove current key
        jwks_service.remove_key(key1.key_id)

        # Should no longer have current key
        assert jwks_service.get_current_key_pair() is None

    def test_int_to_base64url(self, jwks_service):
        """Test integer to base64url conversion."""
        # Test with known values
        test_value = 65537  # Common RSA exponent
        encoded = jwks_service._int_to_base64url(test_value)

        # Should be base64url without padding
        assert "=" not in encoded
        assert isinstance(encoded, str)

        # Should be reversible
        decoded_bytes = base64.urlsafe_b64decode(encoded + "==")
        decoded_int = int.from_bytes(decoded_bytes, byteorder="big")
        assert decoded_int == test_value

    def test_generate_key_id_uniqueness(self, jwks_service):
        """Test that generated key IDs are unique."""
        key_ids = set()
        for _ in range(10):
            key_id = jwks_service._generate_key_id()
            assert key_id not in key_ids
            key_ids.add(key_id)
            assert key_id.startswith("key_")


class TestJWKSManager:
    """Test JWKS manager functionality."""

    def test_init_with_auto_generate(self):
        """Test manager initialization with auto-generate."""
        manager = JWKSManager(auto_generate=True)
        assert manager.get_signing_key() is not None

    def test_init_without_auto_generate(self):
        """Test manager initialization without auto-generate."""
        manager = JWKSManager(auto_generate=False)
        assert manager.get_signing_key() is None

    def test_get_jwks_response(self):
        """Test getting JWKS response."""
        manager = JWKSManager()
        response = manager.get_jwks_response()

        assert isinstance(response, dict)
        assert "keys" in response
        assert isinstance(response["keys"], list)
        assert len(response["keys"]) > 0

        # Check first key structure
        first_key = response["keys"][0]
        assert "kty" in first_key
        assert "use" in first_key
        assert "alg" in first_key
        assert "kid" in first_key
        assert "n" in first_key
        assert "e" in first_key

    def test_get_jwks_response_error_handling(self):
        """Test JWKS response error handling."""
        manager = JWKSManager(auto_generate=False)

        # Mock service to raise exception
        with patch.object(manager.service, "get_jwks") as mock_get_jwks:
            mock_get_jwks.side_effect = Exception("Test error")

            with pytest.raises(HTTPException) as exc_info:
                manager.get_jwks_response()

            assert exc_info.value.status_code == 500
            assert "Unable to generate JWKS response" in exc_info.value.detail

    def test_get_signing_key(self):
        """Test getting signing key."""
        manager = JWKSManager()
        signing_key = manager.get_signing_key()

        assert signing_key is not None
        assert hasattr(signing_key, "private_key")
        assert hasattr(signing_key, "public_key")

    def test_get_key_for_verification(self):
        """Test getting key for verification."""
        manager = JWKSManager()
        signing_key = manager.get_signing_key()

        # Get key for verification
        verification_key = manager.get_key_for_verification(signing_key.key_id)
        assert verification_key is not None
        assert verification_key.key_id == signing_key.key_id

        # Non-existent key
        assert manager.get_key_for_verification("nonexistent") is None


class TestJWKSGlobalFunctions:
    """Test global JWKS functions."""

    def test_get_jwks_manager(self):
        """Test getting global JWKS manager."""
        # Clear global manager
        import authly.oidc.jwks

        authly.oidc.jwks._jwks_manager = None

        manager1 = get_jwks_manager()
        manager2 = get_jwks_manager()

        # Should be same instance
        assert manager1 is manager2

    def test_get_jwks_response(self):
        """Test getting JWKS response."""
        response = get_jwks_response()

        assert isinstance(response, dict)
        assert "keys" in response
        assert len(response["keys"]) > 0

    def test_get_current_signing_key(self):
        """Test getting current signing key."""
        key = get_current_signing_key()

        assert key is not None
        assert hasattr(key, "private_key")
        assert hasattr(key, "public_key")
        assert hasattr(key, "key_id")

    def test_get_key_for_verification_global(self):
        """Test global get_key_for_verification function."""
        # Get current signing key
        signing_key = get_current_signing_key()

        # Test getting key for verification
        verification_key = get_key_for_verification(signing_key.key_id)
        assert verification_key is not None
        assert verification_key.key_id == signing_key.key_id

        # Test with non-existent key
        assert get_key_for_verification("nonexistent") is None


class TestJWKSEndpoint:
    """Test JWKS endpoint functionality."""

    @pytest.mark.asyncio
    async def test_jwks_endpoint_response_structure(self):
        """Test JWKS endpoint response structure."""
        from authly.api.oidc_router import jwks_endpoint

        # Mock the get_jwks_response function
        with patch("authly.oidc.jwks.get_jwks_response") as mock_get_jwks:
            mock_get_jwks.return_value = {
                "keys": [
                    {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key-id", "n": "test-n-value", "e": "AQAB"}
                ]
            }

            # Import Response for testing
            from fastapi.responses import JSONResponse

            # Call endpoint
            response = await jwks_endpoint()

            # Check response
            assert isinstance(response, JSONResponse)
            # JSONResponse headers are set directly on the response object
            assert "Cache-Control" in response.headers
            assert response.headers["Cache-Control"] == "public, max-age=3600"

            # For JSONResponse, we can check that the mock was called correctly
            mock_get_jwks.assert_called_once()

    @pytest.mark.asyncio
    async def test_jwks_endpoint_error_handling(self):
        """Test JWKS endpoint error handling."""
        from authly.api.oidc_router import jwks_endpoint

        # Mock the get_jwks_response function to raise exception
        with patch("authly.oidc.jwks.get_jwks_response") as mock_get_jwks:
            mock_get_jwks.side_effect = Exception("Test error")

            with pytest.raises(HTTPException) as exc_info:
                await jwks_endpoint()

            assert exc_info.value.status_code == 500
            assert "Unable to generate JWKS response" in exc_info.value.detail
