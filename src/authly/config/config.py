import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from authly.config.secret_providers import SecretProvider
from authly.config.database_providers import DatabaseProvider, EnvDatabaseProvider
from authly.config.secure import SecureSecrets


@dataclass
class AuthlyConfig:
    """Configuration management for Authly with secure secret and database handling.

    Attributes:
        _algorithm: JWT signing algorithm
        _access_token_expire_minutes: Access token expiration in minutes
        _refresh_token_expire_days: Refresh token expiration in days
        _database_url: Database connection URL

    Example usage:
        secret_provider = StaticSecretProvider(
            secret_key="test-secret-key",
            refresh_secret_key="test-refresh-key"
        )
        database_provider = StaticDatabaseProvider(
            database_url="postgresql://user:pass@localhost/db"
        )
        AuthlyConfig.load(secret_provider, database_provider)
    """

    _fastapi_api_version_prefix: str
    _algorithm: str
    _access_token_expire_minutes: int
    _refresh_token_expire_days: int
    _database_url: str
    _secrets: Optional[SecureSecrets] = None

    def __del__(self):
        """Ensure secure cleanup of secrets."""
        if self._secrets:
            self._secrets.clear_memory()

    @classmethod
    def load(
        cls, 
        secret_provider: SecretProvider, 
        database_provider: Optional[DatabaseProvider] = None,
        secrets_path: Optional[Path] = None
    ) -> "AuthlyConfig":
        """Load configuration from environment and secure storage.

        Args:
            secret_provider: Provider for JWT secrets
            database_provider: Provider for database configuration (defaults to EnvDatabaseProvider)
            secrets_path: Optional custom path for secrets storage

        Returns:
            Initialized AuthlyConfig instance
        """
        # Use default database provider if none provided
        if database_provider is None:
            database_provider = EnvDatabaseProvider()

        # Get database configuration
        db_config = database_provider.get_database_config()

        config = cls(
            _fastapi_api_version_prefix=os.getenv("AUTHLY_API_VERSION_PREFIX", "/api/v1"),
            _algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            _access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")),
            _refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")),
            _database_url=db_config.database_url,
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

    @property
    def database_url(self) -> str:
        """Get database connection URL."""
        return self._database_url

    def get_masked_database_url(self) -> str:
        """Get database URL with password masked for safe logging."""
        from authly.config.database_providers import DatabaseConfig
        db_config = DatabaseConfig(database_url=self._database_url)
        return db_config.get_masked_url()

    def validate(self) -> None:
        """Validate all configuration values."""
        from authly.config.database_providers import DatabaseConfig
        
        # Validate database URL
        db_config = DatabaseConfig(database_url=self._database_url)
        db_config.validate()
        
        # Validate token expiration values
        if self._access_token_expire_minutes <= 0:
            raise ValueError("Access token expiration must be positive")
        
        if self._refresh_token_expire_days <= 0:
            raise ValueError("Refresh token expiration must be positive")
        
        # Validate JWT algorithm
        supported_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]
        if self._algorithm not in supported_algorithms:
            raise ValueError(f"Unsupported JWT algorithm: {self._algorithm}")
        
        # Validate secrets are available
        if not self._secrets:
            raise ValueError("Secrets not initialized")
        
        try:
            self.secret_key
            self.refresh_secret_key
        except Exception as e:
            raise ValueError(f"Secret validation failed: {e}")
