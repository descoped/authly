import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from authly.config.secret_providers import SecretProvider
from authly.config.secure import SecureSecrets


@dataclass
class AuthlyConfig:
    """Configuration management for Authly with secure secret handling.

    Attributes:
        _algorithm: JWT signing algorithm
        _access_token_expire_minutes: Access token expiration in minutes
        _refresh_token_expire_days: Refresh token expiration in days

    Example usage:
        test_provider = StaticSecretProvider(
            secret_key="test-secret-key",
            refresh_secret_key="test-refresh-key"
        )
        AuthlyConfig.load(test_provider)
    """

    _fastapi_api_version_prefix: str
    _algorithm: str
    _access_token_expire_minutes: int
    _refresh_token_expire_days: int
    _secrets: Optional[SecureSecrets] = None

    def __del__(self):
        """Ensure secure cleanup of secrets."""
        if self._secrets:
            self._secrets.clear_memory()

    @classmethod
    def load(
            cls,
            secret_provider: SecretProvider,
            secrets_path: Optional[Path] = None
    ) -> 'AuthlyConfig':
        """Load configuration from environment and secure storage.

        Args:
            secret_provider: Provide secret provider
            secrets_path: Optional custom path for secrets storage

        Returns:
            Initialized AuthlyConfig instance
        """
        config = cls(
            _fastapi_api_version_prefix=os.getenv("AUTHLY_API_VERSION_PREFIX", "/api/v1"),
            _algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            _access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")),
            _refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        )

        config._secrets = SecureSecrets(secrets_path)
        secrets = secret_provider.get_secrets()
        config._secrets.set_secret("secret_key", secrets.secret_key)
        config._secrets.set_secret("refresh_secret_key", secrets.refresh_secret_key)

        return config

    @property
    def fastapi_api_version_prefix(self):
        return self._fastapi_api_version_prefix

    @property
    def secret_key(self) -> str:
        """Get JWT secret key."""
        return self._secrets.get_secret("secret_key")

    @property
    def refresh_secret_key(self) -> str:
        """Get JWT refresh secret key."""
        return self._secrets.get_secret("refresh_secret_key")

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def access_token_expire_minutes(self) -> int:
        return self._access_token_expire_minutes

    @property
    def refresh_token_expire_days(self) -> int:
        return self._refresh_token_expire_days
