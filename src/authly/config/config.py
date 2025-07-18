import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from authly.config.database_providers import DatabaseProvider, EnvDatabaseProvider
from authly.config.secret_providers import SecretProvider
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
    _rate_limit_max_requests: int
    _rate_limit_window_seconds: int
    _rsa_key_size: int
    _token_hex_length: int
    _authorization_code_length: int
    _client_secret_length: int
    _default_api_url: str
    _default_issuer_url: str
    _default_page_size: int
    _max_page_size: int
    _nonce_max_length: int
    _redirect_uri_max_length: int
    _jwks_cache_max_age_seconds: int
    _hsts_max_age_seconds: int
    _db_cleanup_timeout_seconds: float
    _username_min_length: int
    _username_max_length: int
    _password_min_length: int
    _postgres_port: int
    _bootstrap_dev_mode: bool
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
        secrets_path: Optional[Path] = None,
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
            _rate_limit_max_requests=int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "5")),
            _rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
            _rsa_key_size=int(os.getenv("RSA_KEY_SIZE", "2048")),
            _token_hex_length=int(os.getenv("TOKEN_HEX_LENGTH", "32")),
            _authorization_code_length=int(os.getenv("AUTHORIZATION_CODE_LENGTH", "32")),
            _client_secret_length=int(os.getenv("CLIENT_SECRET_LENGTH", "32")),
            _default_api_url=os.getenv("DEFAULT_API_URL", "http://localhost:8000"),
            _default_issuer_url=os.getenv("DEFAULT_ISSUER_URL", "https://authly.localhost"),
            _default_page_size=int(os.getenv("DEFAULT_PAGE_SIZE", "100")),
            _max_page_size=int(os.getenv("MAX_PAGE_SIZE", "100")),
            _nonce_max_length=int(os.getenv("NONCE_MAX_LENGTH", "255")),
            _redirect_uri_max_length=int(os.getenv("REDIRECT_URI_MAX_LENGTH", "2000")),
            _jwks_cache_max_age_seconds=int(os.getenv("JWKS_CACHE_MAX_AGE_SECONDS", "3600")),
            _hsts_max_age_seconds=int(os.getenv("HSTS_MAX_AGE_SECONDS", "31536000")),
            _db_cleanup_timeout_seconds=float(os.getenv("DB_CLEANUP_TIMEOUT_SECONDS", "10.0")),
            _username_min_length=int(os.getenv("USERNAME_MIN_LENGTH", "1")),
            _username_max_length=int(os.getenv("USERNAME_MAX_LENGTH", "50")),
            _password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "8")),
            _postgres_port=int(os.getenv("POSTGRES_PORT", "5432")),
            _bootstrap_dev_mode=os.getenv("AUTHLY_BOOTSTRAP_DEV_MODE", "false").lower() == "true",
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
    def rate_limit_max_requests(self) -> int:
        return self._rate_limit_max_requests

    @property
    def rate_limit_window_seconds(self) -> int:
        return self._rate_limit_window_seconds

    @property
    def rsa_key_size(self) -> int:
        return self._rsa_key_size

    @property
    def token_hex_length(self) -> int:
        return self._token_hex_length

    @property
    def authorization_code_length(self) -> int:
        return self._authorization_code_length

    @property
    def client_secret_length(self) -> int:
        return self._client_secret_length

    @property
    def default_api_url(self) -> str:
        return self._default_api_url

    @property
    def default_issuer_url(self) -> str:
        return self._default_issuer_url

    @property
    def default_page_size(self) -> int:
        return self._default_page_size

    @property
    def max_page_size(self) -> int:
        return self._max_page_size

    @property
    def nonce_max_length(self) -> int:
        return self._nonce_max_length

    @property
    def redirect_uri_max_length(self) -> int:
        return self._redirect_uri_max_length

    @property
    def jwks_cache_max_age_seconds(self) -> int:
        return self._jwks_cache_max_age_seconds

    @property
    def hsts_max_age_seconds(self) -> int:
        return self._hsts_max_age_seconds

    @property
    def db_cleanup_timeout_seconds(self) -> float:
        return self._db_cleanup_timeout_seconds

    @property
    def username_min_length(self) -> int:
        return self._username_min_length

    @property
    def username_max_length(self) -> int:
        return self._username_max_length

    @property
    def password_min_length(self) -> int:
        return self._password_min_length

    @property
    def postgres_port(self) -> int:
        return self._postgres_port

    @property
    def bootstrap_dev_mode(self) -> bool:
        return self._bootstrap_dev_mode

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

        # Validate rate limiting values
        if self._rate_limit_max_requests <= 0:
            raise ValueError("Rate limit max requests must be positive")

        if self._rate_limit_window_seconds <= 0:
            raise ValueError("Rate limit window seconds must be positive")

        # Validate security constants
        if self._rsa_key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")

        if self._token_hex_length < 16:
            raise ValueError("Token hex length must be at least 16")

        if self._authorization_code_length < 16:
            raise ValueError("Authorization code length must be at least 16")

        if self._client_secret_length < 16:
            raise ValueError("Client secret length must be at least 16")

        # Validate operational values
        if self._default_page_size <= 0:
            raise ValueError("Default page size must be positive")

        if self._max_page_size <= 0:
            raise ValueError("Max page size must be positive")

        if self._default_page_size > self._max_page_size:
            raise ValueError("Default page size cannot exceed max page size")

        if self._nonce_max_length <= 0:
            raise ValueError("Nonce max length must be positive")

        if self._redirect_uri_max_length <= 0:
            raise ValueError("Redirect URI max length must be positive")

        if self._jwks_cache_max_age_seconds < 0:
            raise ValueError("JWKS cache max age must be non-negative")

        if self._hsts_max_age_seconds < 0:
            raise ValueError("HSTS max age must be non-negative")

        if self._db_cleanup_timeout_seconds <= 0:
            raise ValueError("DB cleanup timeout must be positive")

        # Validate field validation constraints
        if self._username_min_length <= 0:
            raise ValueError("Username min length must be positive")

        if self._username_max_length <= 0:
            raise ValueError("Username max length must be positive")

        if self._username_min_length > self._username_max_length:
            raise ValueError("Username min length cannot exceed max length")

        if self._password_min_length <= 0:
            raise ValueError("Password min length must be positive")

        # Validate database configuration
        if self._postgres_port <= 0 or self._postgres_port > 65535:
            raise ValueError("Postgres port must be between 1 and 65535")

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
