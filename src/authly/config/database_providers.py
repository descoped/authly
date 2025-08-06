import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class DatabaseConfig:
    """Container for database configuration."""

    database_url: str

    def get_masked_url(self) -> str:
        """Get database URL with password masked for safe logging."""
        try:
            parsed = urlparse(self.database_url)
            if parsed.password:
                # Replace password with asterisks
                masked_netloc = parsed.netloc.replace(f":{parsed.password}@", ":***@")
                masked_url = self.database_url.replace(parsed.netloc, masked_netloc)
                return masked_url
            return self.database_url
        except Exception:
            # If URL parsing fails, just mask anything that looks like a password
            return re.sub(r":([^:@]+)@", ":***@", self.database_url)

    def validate(self) -> None:
        """Validate database URL format."""
        if not self.database_url:
            raise ValueError("Database URL cannot be empty")

        if not self.database_url.startswith(("postgresql://", "postgres://")):
            raise ValueError("Database URL must be a PostgreSQL connection string (postgresql:// or postgres://)")

        try:
            parsed = urlparse(self.database_url)
            if not parsed.hostname:
                raise ValueError("Database URL must include hostname")
            if not parsed.path or parsed.path == "/":
                raise ValueError("Database URL must include database name") from None
        except Exception as e:
            raise ValueError(f"Invalid database URL format: {e}") from e


class DatabaseProvider(ABC):
    """Abstract interface for database configuration providers.

    TODO: Implement additional providers:
    - AWSRDSProvider
    - AzureSQLProvider
    - GCPCloudSQLProvider
    - KubernetesSecretProvider
    - HashiCorpVaultProvider
    - DatabaseConfigProvider (for multi-tenant setups)
    """

    @abstractmethod
    def get_database_config(self) -> DatabaseConfig:
        """Retrieve database configuration from the provider.

        Returns:
            DatabaseConfig instance containing database connection details

        Raises:
            ValueError: If database configuration cannot be retrieved or is invalid
        """
        pass


class StaticDatabaseProvider(DatabaseProvider):
    """Static database provider for testing."""

    def __init__(self, database_url: str):
        self._database_url = database_url

    def get_database_config(self) -> DatabaseConfig:
        config = DatabaseConfig(database_url=self._database_url)
        config.validate()
        return config


class FileDatabaseProvider(DatabaseProvider):
    """File-based database configuration provider."""

    def __init__(self, config_path: Path):
        self._config_path = config_path

    def get_database_config(self) -> DatabaseConfig:
        if not self._config_path.exists():
            raise ValueError(f"Database config file not found: {self._config_path}")

        with open(self._config_path) as f:
            config_data = json.load(f)

        database_url = config_data.get("DATABASE_URL")
        if not database_url:
            raise ValueError("DATABASE_URL not found in config file")

        config = DatabaseConfig(database_url=database_url)
        config.validate()
        return config


class EnvDatabaseProvider(DatabaseProvider):
    """Environment variable database configuration provider with library-appropriate defaults."""

    def __init__(self, default_url: str | None = None):
        """Initialize with optional default database URL.

        Args:
            default_url: Default database URL to use if DATABASE_URL env var is not set.
                        If None, will use a sensible development default that works out of the box.
        """
        self._default_url = default_url or "postgresql://authly:authly@localhost:5432/authly"

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration from environment with fallback to defaults.

        This provider follows library-first principles:
        - Always provides a working default for development
        - Respects host application's environment variable setup
        - Does not impose configuration loading choices on the host application

        Returns:
            DatabaseConfig: Configuration with validated database URL
        """
        # Check environment first, fallback to sensible default
        database_url = os.getenv("DATABASE_URL", self._default_url)

        config = DatabaseConfig(database_url=database_url)
        config.validate()
        return config
