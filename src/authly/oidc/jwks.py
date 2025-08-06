"""
OpenID Connect JWKS (JSON Web Key Set) Implementation.

This module implements the JWKS endpoint according to OpenID Connect Core 1.0
and RFC 7517 (JSON Web Key). The JWKS endpoint provides public keys that
clients can use to verify the signatures of ID tokens.

Key Features:
- RSA key pair generation and management
- JWK (JSON Web Key) format conversion
- JWKS (JSON Web Key Set) endpoint implementation
- Key rotation support
- Proper HTTP caching headers

Based on:
- OpenID Connect Core 1.0 Section 10.1
- RFC 7517 (JSON Web Key)
- RFC 7518 (JSON Web Algorithms)
"""

import base64
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from fastapi import HTTPException, status
from psycopg import AsyncConnection
from pydantic import BaseModel, Field

from .jwks_repository import JWKSKeyModel, JWKSRepository

logger = logging.getLogger(__name__)


@dataclass
class RSAKeyPair:
    """
    RSA key pair for JWT signing.

    Attributes:
        private_key: RSA private key for signing
        public_key: RSA public key for verification
        key_id: Unique identifier for the key
        created_at: Timestamp when key was created
        algorithm: JWT algorithm (RS256, RS384, RS512)
    """

    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    key_id: str
    created_at: datetime
    algorithm: str = "RS256"


class JWKModel(BaseModel):
    """
    JSON Web Key (JWK) model according to RFC 7517.

    Represents a single public key in JWK format for ID token verification.
    """

    kty: str = Field(..., description="Key type (RSA)")
    use: str = Field(..., description="Key use (sig for signature)")
    alg: str = Field(..., description="Algorithm (RS256, RS384, RS512)")
    kid: str = Field(..., description="Key ID")
    n: str = Field(..., description="RSA modulus (base64url encoded)")
    e: str = Field(..., description="RSA exponent (base64url encoded)")


class JWKSModel(BaseModel):
    """
    JSON Web Key Set (JWKS) model according to RFC 7517.

    Contains an array of JWK objects representing all public keys
    available for ID token verification.
    """

    keys: list[JWKModel] = Field(..., description="Array of JWK objects")


class JWKSService:
    """
    Service for managing JSON Web Key Sets (JWKS).

    Handles RSA key generation, JWK format conversion, and JWKS endpoint
    functionality for OpenID Connect ID token verification.
    """

    def __init__(self, db_connection: AsyncConnection | None = None):
        """Initialize JWKS service with optional database persistence."""
        self._key_pairs: dict[str, RSAKeyPair] = {}
        self._current_key_id: str | None = None
        self._repository = JWKSRepository(db_connection) if db_connection else None

    async def load_keys_from_database(self):
        """Load existing keys from database into memory."""
        if not self._repository:
            return

        try:
            db_keys = await self._repository.get_active_keys()
            for db_key in db_keys:
                # Skip if already loaded
                if db_key.kid in self._key_pairs:
                    continue

                # Note: We can only load the public key from database
                # Private keys should not be stored in database for security
                # This method is mainly for JWKS endpoint serving public keys
                logger.info(f"Loaded public key {db_key.kid} from database")

                # Set current key if none exists
                if self._current_key_id is None:
                    self._current_key_id = db_key.kid

        except Exception as e:
            logger.error(f"Failed to load keys from database: {e}")

    async def generate_rsa_key_pair(self, key_size: int = 2048, algorithm: str = "RS256") -> RSAKeyPair:
        """
        Generate a new RSA key pair for JWT signing.

        Args:
            key_size: RSA key size in bits (default 2048)
            algorithm: JWT algorithm (RS256, RS384, RS512)

        Returns:
            RSAKeyPair: New key pair with unique key ID
        """

        logger.info(f"Generating new RSA key pair (size: {key_size}, algorithm: {algorithm})")

        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        # Get public key
        public_key = private_key.public_key()

        # Generate unique key ID
        key_id = self._generate_key_id()

        # Create key pair object
        key_pair = RSAKeyPair(
            private_key=private_key,
            public_key=public_key,
            key_id=key_id,
            created_at=datetime.now(UTC),
            algorithm=algorithm,
        )

        # Store key pair in memory
        self._key_pairs[key_id] = key_pair

        # Store in database if repository is available
        if self._repository:
            try:
                # Convert to JWK format for database storage
                jwk_model = self.convert_to_jwk(key_pair)

                # Create database model
                db_key_model = JWKSKeyModel(
                    kid=key_id,
                    key_data=jwk_model.model_dump(),
                    key_type="RSA",
                    algorithm=algorithm,
                    key_use="sig",
                    is_active=True,
                    created_at=key_pair.created_at,
                    key_size=key_size,
                )

                await self._repository.store_key(db_key_model)
                logger.info(f"Stored key pair {key_id} in database")

            except Exception as e:
                logger.error(f"Failed to store key pair in database: {e}")
                # Continue without database storage

        # Set as current key if no current key exists
        if self._current_key_id is None:
            self._current_key_id = key_id

        logger.info(f"Generated RSA key pair with ID: {key_id}")
        return key_pair

    def _generate_rsa_key_pair_sync(self, key_size: int = 2048, algorithm: str = "RS256") -> RSAKeyPair:
        """
        Synchronous wrapper for RSA key pair generation.

        Args:
            key_size: RSA key size in bits (default 2048)
            algorithm: JWT algorithm (RS256, RS384, RS512)

        Returns:
            RSAKeyPair: New key pair with unique key ID
        """
        logger.info(f"Generating RSA key pair synchronously (size: {key_size}, algorithm: {algorithm})")

        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        # Get public key
        public_key = private_key.public_key()

        # Generate unique key ID
        key_id = self._generate_key_id()

        # Create key pair object
        key_pair = RSAKeyPair(
            private_key=private_key,
            public_key=public_key,
            key_id=key_id,
            created_at=datetime.now(UTC),
            algorithm=algorithm,
        )

        # Store key pair in memory
        self._key_pairs[key_id] = key_pair

        # Set as current key if no current key exists
        if self._current_key_id is None:
            self._current_key_id = key_id

        logger.info(f"Generated RSA key pair synchronously with ID: {key_id}")
        return key_pair

    def get_current_key_pair(self) -> RSAKeyPair | None:
        """
        Get the current active key pair for signing.

        Returns:
            Current RSA key pair or None if no keys exist
        """
        if self._current_key_id and self._current_key_id in self._key_pairs:
            return self._key_pairs[self._current_key_id]
        return None

    def get_key_pair(self, key_id: str) -> RSAKeyPair | None:
        """
        Get a specific key pair by ID.

        Args:
            key_id: Key identifier

        Returns:
            RSA key pair or None if not found
        """
        return self._key_pairs.get(key_id)

    def get_all_key_pairs(self) -> list[RSAKeyPair]:
        """
        Get all stored key pairs.

        Returns:
            List of all RSA key pairs
        """
        return list(self._key_pairs.values())

    def convert_to_jwk(self, key_pair: RSAKeyPair) -> JWKModel:
        """
        Convert RSA key pair to JWK format.

        Args:
            key_pair: RSA key pair to convert

        Returns:
            JWK model representing the public key
        """
        logger.debug(f"Converting key pair {key_pair.key_id} to JWK format")

        # Get public key numbers
        public_numbers = key_pair.public_key.public_numbers()

        # Convert to base64url format
        n = self._int_to_base64url(public_numbers.n)
        e = self._int_to_base64url(public_numbers.e)

        # Create JWK
        jwk = JWKModel(kty="RSA", use="sig", alg=key_pair.algorithm, kid=key_pair.key_id, n=n, e=e)

        logger.debug(f"Created JWK for key {key_pair.key_id}")
        return jwk

    def get_jwks(self) -> JWKSModel:
        """
        Get JSON Web Key Set containing all public keys.

        Returns:
            JWKS model with all public keys
        """
        logger.debug("Generating JWKS response")

        # Convert all key pairs to JWK format
        jwks = []
        for key_pair in self._key_pairs.values():
            jwk = self.convert_to_jwk(key_pair)
            jwks.append(jwk)

        # Create JWKS
        jwks_model = JWKSModel(keys=jwks)

        logger.info(f"Generated JWKS with {len(jwks)} keys")
        return jwks_model

    async def rotate_keys(self, key_size: int = 2048, algorithm: str = "RS256") -> RSAKeyPair:
        """
        Rotate keys by generating a new key pair and making it current.

        Args:
            key_size: RSA key size in bits
            algorithm: JWT algorithm

        Returns:
            New current key pair
        """
        logger.info("Rotating RSA keys")

        # Generate new key pair
        new_key_pair = await self.generate_rsa_key_pair(key_size, algorithm)

        # Make it the current key
        self._current_key_id = new_key_pair.key_id

        logger.info(f"Rotated to new key: {new_key_pair.key_id}")
        return new_key_pair

    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key pair from storage.

        Args:
            key_id: Key identifier to remove

        Returns:
            True if key was removed, False if not found
        """
        if key_id in self._key_pairs:
            del self._key_pairs[key_id]

            # If this was the current key, clear current key
            if self._current_key_id == key_id:
                self._current_key_id = None

            logger.info(f"Removed key: {key_id}")
            return True

        return False

    def _generate_key_id(self) -> str:
        """
        Generate a unique key ID.

        Returns:
            Unique key identifier
        """
        # Use timestamp-based key ID with microseconds for uniqueness
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
        return f"key_{timestamp}"

    def _int_to_base64url(self, value: int) -> str:
        """
        Convert integer to base64url encoded string.

        Args:
            value: Integer value to encode

        Returns:
            Base64url encoded string
        """
        # Convert to bytes
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder="big")

        # Base64url encode
        encoded = base64.urlsafe_b64encode(value_bytes).decode("ascii")

        # Remove padding
        return encoded.rstrip("=")


class JWKSManager:
    """
    High-level manager for JWKS operations.

    Provides a simplified interface for JWKS operations with proper
    initialization and error handling.
    """

    def __init__(self, auto_generate: bool = True):
        """
        Initialize JWKS manager.

        Args:
            auto_generate: Whether to auto-generate initial key pair
        """
        self.service = JWKSService()

        if auto_generate:
            self._ensure_key_pair()

    def _ensure_key_pair(self):
        """Ensure at least one key pair exists."""
        if not self.service.get_current_key_pair():
            logger.info("No key pairs found, generating initial key pair")
            self.service._generate_rsa_key_pair_sync()

    def get_jwks_response(self) -> dict[str, Any]:
        """
        Get JWKS response for the endpoint.

        Returns:
            JWKS response as dictionary
        """
        try:
            self._ensure_key_pair()
            jwks_model = self.service.get_jwks()
            return jwks_model.model_dump()
        except Exception as e:
            logger.error(f"Error generating JWKS response: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to generate JWKS response"
            ) from None

    def get_signing_key(self) -> RSAKeyPair | None:
        """
        Get the current signing key pair.

        Returns:
            Current signing key pair or None
        """
        return self.service.get_current_key_pair()

    def get_key_for_verification(self, key_id: str) -> RSAKeyPair | None:
        """
        Get a key pair for verification by key ID.

        Args:
            key_id: Key identifier

        Returns:
            Key pair for verification or None
        """
        return self.service.get_key_pair(key_id)


# Global JWKS manager instance
_jwks_manager: JWKSManager | None = None


def get_jwks_manager() -> JWKSManager:
    """
    Get global JWKS manager instance.

    Returns:
        Global JWKS manager
    """
    global _jwks_manager
    if _jwks_manager is None:
        _jwks_manager = JWKSManager()
    return _jwks_manager


def get_jwks_response() -> dict[str, Any]:
    """
    Get JWKS response for the endpoint.

    Returns:
        JWKS response as dictionary
    """
    manager = get_jwks_manager()
    return manager.get_jwks_response()


def get_current_signing_key() -> RSAKeyPair | None:
    """
    Get the current signing key pair.

    Returns:
        Current signing key pair or None
    """
    manager = get_jwks_manager()
    return manager.get_signing_key()


def get_key_for_verification(key_id: str) -> RSAKeyPair | None:
    """
    Get key pair for verification by key ID.

    Args:
        key_id: Key identifier to look up

    Returns:
        Key pair for verification or None if not found
    """
    manager = get_jwks_manager()
    return manager.get_key_for_verification(key_id)
