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
        return Secrets(
            secret_key=self._secret_key,
            refresh_secret_key=self._refresh_secret_key
        )


class FileSecretProvider(SecretProvider):
    """File-based secret provider."""

    def __init__(self, config_path: Path):
        self._config_path = config_path

    def get_secrets(self) -> Secrets:
        if not self._config_path.exists():
            raise ValueError(f"Config file not found: {self._config_path}")

        with open(self._config_path) as f:
            config = json.load(f)

        return Secrets(
            secret_key=config.get("JWT_SECRET_KEY"),
            refresh_secret_key=config.get("JWT_REFRESH_SECRET_KEY")
        )


class EnvSecretProvider(SecretProvider):
    """Environment variable secret provider."""

    def get_secrets(self) -> Secrets:
        secret_key = os.getenv("JWT_SECRET_KEY")
        refresh_secret_key = os.getenv("JWT_REFRESH_SECRET_KEY")

        if not secret_key or not refresh_secret_key:
            raise ValueError("Required JWT secrets not found in environment")

        return Secrets(
            secret_key=secret_key,
            refresh_secret_key=refresh_secret_key
        )
