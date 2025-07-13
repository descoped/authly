import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Secrets:
    """Container for required JWT secrets."""

    secret_key: str
    refresh_secret_key: str


class SecretProvider(ABC):
    """Abstract interface for secret providers.

    TODO: Implement additional providers:
    - AWSSecretsProvider
    - AzureKeyVaultProvider
    - GCPSecretManagerProvider
    - HashiCorpVaultProvider
    - DatabaseSecretProvider
    - APISecretProvider
    """

    @abstractmethod
    def get_secrets(self) -> Secrets:
        """Retrieve secrets from the provider.

        Returns:
            Secrets instance containing required JWT secrets

        Raises:
            ValueError: If required secrets cannot be retrieved
        """
        pass


class StaticSecretProvider(SecretProvider):
    """Static secret provider for testing."""

    def __init__(self, secret_key: str, refresh_secret_key: str):
        self._secret_key = secret_key
        self._refresh_secret_key = refresh_secret_key

    def get_secrets(self) -> Secrets:
        return Secrets(secret_key=self._secret_key, refresh_secret_key=self._refresh_secret_key)


class FileSecretProvider(SecretProvider):
    """File-based secret provider."""

    def __init__(self, config_path: Path):
        self._config_path = config_path

    def get_secrets(self) -> Secrets:
        if not self._config_path.exists():
            raise ValueError(f"Config file not found: {self._config_path}")

        with open(self._config_path) as f:
            config = json.load(f)

        return Secrets(secret_key=config.get("JWT_SECRET_KEY"), refresh_secret_key=config.get("JWT_REFRESH_SECRET_KEY"))


class EnvSecretProvider(SecretProvider):
    """Environment variable secret provider with library-appropriate error messaging."""

    def get_secrets(self) -> Secrets:
        """Get JWT secrets from environment variables.

        This provider follows library-first principles:
        - Does not impose configuration loading choices on the host application
        - Provides clear guidance for different deployment scenarios
        - Respects host application's environment management approach

        Returns:
            Secrets: JWT secret keys from environment

        Raises:
            ValueError: If required JWT secrets are not found in environment
        """
        secret_key = os.getenv("JWT_SECRET_KEY")
        refresh_secret_key = os.getenv("JWT_REFRESH_SECRET_KEY")

        if not secret_key or not refresh_secret_key:
            raise ValueError(
                "Required JWT secrets not found in environment. "
                "Please set JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY environment variables.\n\n"
                "For development, you can:\n"
                "1. Export manually: export JWT_SECRET_KEY='your-secret-key'\n"
                "2. Use your application's .env loading mechanism\n"
                "3. Use StaticSecretProvider for testing\n\n"
                "For production, ensure these variables are set in your deployment environment."
            )

        return Secrets(secret_key=secret_key, refresh_secret_key=refresh_secret_key)
