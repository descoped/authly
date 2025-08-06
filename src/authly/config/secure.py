"""Secure secrets management implementation with encryption, backup, and memory safety features."""

import ctypes
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from json import JSONEncoder
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class DateTimeEncoder(JSONEncoder):
    """JSON encoder with support for datetime and SecretValueType objects."""

    def default(self, obj):
        """Convert datetime and SecretValueType objects to JSON serializable format.

        Args:
            obj: Object to serialize

        Returns:
            JSON serializable representation of the object
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, SecretValueType):
            return obj.value
        return super().default(obj)


class SecretValueType(Enum):
    """Supported secret value types."""

    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DICT = "dict"
    LIST = "list"


@dataclass
class SecretMetadata:
    """Metadata for stored secrets.

    Attributes:
        created_at: Secret creation timestamp
        last_accessed: Last access timestamp
        value_type: Type of the secret value
        version: Secret format version
    """

    created_at: datetime
    last_accessed: datetime
    value_type: SecretValueType
    version: int


class SecureSecrets:
    """Secure storage for sensitive data with encryption and backup capabilities.

    This class provides a secure way to store and manage secrets with features like:
    - Fernet encryption
    - Automatic key rotation
    - Secure memory wiping
    - Atomic file operations
    - Backup and restore functionality

    Attributes:
        VERSION: Current secrets format version
        ROTATION_INTERVAL: Time interval for key rotation
        MAX_SECRET_SIZE: Maximum allowed secret size in bytes
    """

    VERSION = 1
    ROTATION_INTERVAL = timedelta(days=30)
    MAX_SECRET_SIZE = 1024 * 1024  # 1MB limit

    def __init__(self, secrets_location: Path | None = None):
        """Initialize secure secrets' storage.

        Args:
            secrets_location: Custom location for secrets storage. If None, uses default location.
        """
        if secrets_location is None:
            self._base_dir = self._get_base_directory() / ".authly"
        else:
            self._base_dir = secrets_location / ".authly"

        self._base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        self._secrets_file = self._base_dir / ".jwt.store"
        self._key_file = self._base_dir / ".jwt.key"
        self._backup_dir = self._base_dir / "backups"
        self._backup_dir.mkdir(exist_ok=True, mode=0o700)

        self._key = self._get_or_create_key()
        self._fernet = Fernet(self._key)
        self._secrets: dict[str, Any] | None = None
        self._metadata: dict[str, SecretMetadata] = {}

        self._load_secrets()
        self._check_rotation_schedule()

    def __enter__(self) -> "SecureSecrets":
        """Context manager entry.

        Returns:
            Self instance
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with secure memory cleanup."""
        self.clear_memory()

    @staticmethod
    def _get_base_directory() -> Path:
        """Determine the base directory for secrets storage.

        Returns:
            Path to base directory

        Raises:
            FileNotFoundError: If project root cannot be found
        """
        if __name__ != "__main__":
            try:
                return find_root_folder()
            except FileNotFoundError:
                pass

        base_dir = Path.home() / ".authly"
        base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return base_dir

    def _get_or_create_key(self) -> bytes:
        """Get existing encryption key or create new one.

        Returns:
            Encryption key bytes
        """
        if not self._key_file.exists():
            key = Fernet.generate_key()
            self._atomic_write(self._key_file, key)
        return self._key_file.read_bytes()

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        """Write data to file atomically with secure permissions.

        Args:
            path: Target file path
            data: Data to write

        Raises:
            OSError: If file operations fail
        """
        temp_path = path.with_suffix(".tmp")
        os.umask(0o077)
        try:
            with open(temp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except (PermissionError, OSError) as e:
                logger.warning(f"Failed to remove temporary file {temp_path}: {e}")

    def _check_rotation_schedule(self) -> None:
        """Check and perform key rotation if needed."""
        metadata_key_rotation = self._metadata.get("key_rotation", {})
        if isinstance(metadata_key_rotation, dict):
            last_rotation = metadata_key_rotation.get("last_rotated")
            if last_rotation and datetime.now() - datetime.fromisoformat(last_rotation) > self.ROTATION_INTERVAL:
                self.rotate_key()

    def _validate_value(self, value: Any) -> SecretValueType:
        """Validate secret value type and size.

        Args:
            value: Value to validate

        Returns:
            Determined SecretValueType

        Raises:
            ValueError: If value exceeds size limit
            TypeError: If value type is not supported
        """
        if isinstance(value, str):
            if len(value.encode()) > self.MAX_SECRET_SIZE:
                raise ValueError(f"Secret exceeds size limit of {self.MAX_SECRET_SIZE} bytes")
            return SecretValueType.STRING
        elif isinstance(value, int | float):
            return SecretValueType.NUMBER
        elif isinstance(value, bool):
            return SecretValueType.BOOLEAN
        elif isinstance(value, dict):
            if not all(isinstance(k, str) for k in value):
                raise ValueError("Dict keys must be strings")
            return SecretValueType.DICT
        elif isinstance(value, list):
            return SecretValueType.LIST
        else:
            raise TypeError("Value must be a string, number, boolean, dict, or list")

    @staticmethod
    def _secure_wipe(data: bytes) -> None:
        """Attempt to securely wipe data from memory.

        Args:
            data: Data to wipe
        """
        try:
            ctypes.memset(id(data), 0, len(data))
        except Exception as e:
            logger.warning(f"Secure memory wiping failed: {e}")

    def _create_backup(self) -> None:
        """Create backup of current secrets state."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self._backup_dir / f"secrets_backup_{timestamp}.enc"
        if self._secrets_file.exists():
            encrypted_data = self._secrets_file.read_bytes()
            self._atomic_write(backup_path, encrypted_data)

    def _verify_store_integrity(self) -> bool:
        """Verify integrity of secrets store.

        Returns:
            True if store is valid, False otherwise
        """
        try:
            secrets_dict = self._load_secrets()
            for key, value in secrets_dict.items():
                if not isinstance(key, str):
                    return False
                try:
                    self._validate_value(value)
                except (TypeError, ValueError):
                    return False
            return True
        except (OSError, InvalidToken, json.JSONDecodeError, KeyError, AttributeError) as e:
            logger.error(f"Store integrity check failed: {e}")
            return False

    def get_secret(self, key: str) -> Any | None:
        """Retrieve secret by key.

        Args:
            key: Secret key

        Returns:
            Secret value or None if not found

        Raises:
            TypeError: If key is not a string
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")

        if key in self._metadata:
            self._metadata[key].last_accessed = datetime.now()

        return self._secrets.get(key)

    def set_secret(self, key: str, value: Any) -> None:
        """Store secret with key.

        Args:
            key: Secret key
            value: Secret value

        Raises:
            TypeError: If key is not a string or value type is not supported
            ValueError: If value exceeds size limit
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")

        value_type = self._validate_value(value)
        self._create_backup()

        self._metadata[key] = SecretMetadata(
            created_at=datetime.now(), last_accessed=datetime.now(), value_type=value_type, version=self.VERSION
        )

        secrets_dict = self._secrets or {}
        secrets_dict[key] = value

        # noinspection DuplicatedCode
        store_data = {
            "secrets": secrets_dict,
            "metadata": {k: vars(v) for k, v in self._metadata.items()},
            "version": self.VERSION,
        }

        encrypted = self._fernet.encrypt(json.dumps(store_data, cls=DateTimeEncoder).encode())
        self._atomic_write(self._secrets_file, encrypted)
        self._secrets = secrets_dict

        logger.info(f"Secret updated: {key}")

    def secure_delete(self, key: str) -> None:
        """Securely delete secret by key.

        Args:
            key: Secret key

        Raises:
            TypeError: If key is not a string
            KeyError: If secret not found
        """
        if not isinstance(key, str):
            raise TypeError("Key must be a string")

        if key not in self._secrets:
            raise KeyError(f"Secret '{key}' not found")

        self._create_backup()

        secrets_dict = self._secrets.copy()
        del secrets_dict[key]
        if key in self._metadata:
            del self._metadata[key]

        # noinspection DuplicatedCode
        store_data = {
            "secrets": secrets_dict,
            "metadata": {k: vars(v) for k, v in self._metadata.items()},
            "version": self.VERSION,
        }

        encrypted = self._fernet.encrypt(json.dumps(store_data, cls=DateTimeEncoder).encode())
        self._atomic_write(self._secrets_file, encrypted)
        self._secrets = secrets_dict

        logger.info(f"Secret deleted: {key}")

    def rotate_key(self) -> None:
        """Rotate encryption key and re-encrypt secrets."""
        self._create_backup()

        new_key = Fernet.generate_key()
        new_fernet = Fernet(new_key)

        if self._secrets is not None:
            store_data = {
                "secrets": self._secrets,
                "metadata": {k: vars(v) for k, v in self._metadata.items()},
                "version": self.VERSION,
            }
            encrypted = new_fernet.encrypt(json.dumps(store_data, cls=DateTimeEncoder).encode())

            self._atomic_write(self._key_file, new_key)
            self._atomic_write(self._secrets_file, encrypted)

    def clear_memory(self) -> None:
        """Securely clear secrets from memory."""
        if self._secrets is not None:
            for key in self._secrets:
                if isinstance(self._secrets[key], str | bytes):
                    self._secure_wipe(self._secrets[key])
                self._secrets[key] = None
            self._secrets = None

        if hasattr(self, "_key"):
            self._secure_wipe(self._key)
            self._key = None

    def _load_secrets(self) -> dict[str, Any]:
        """Load and decrypt secrets from storage.

        Returns:
            Dictionary of secrets

        Raises:
            ValueError: If secrets cannot be decrypted or format is invalid
        """
        if not self._secrets_file.exists():
            self._secrets = {}
            return self._secrets

        try:
            encrypted = self._secrets_file.read_bytes()
            decrypted = self._fernet.decrypt(encrypted)
            store_data = json.loads(decrypted)

            if not isinstance(store_data, dict):
                raise ValueError("Invalid store format")

            self._secrets = store_data.get("secrets", {})

            metadata_dict = store_data.get("metadata", {})
            self._metadata = {}
            for k, v in metadata_dict.items():
                if isinstance(v, dict):
                    try:
                        v["value_type"] = SecretValueType(v["value_type"])
                        self._metadata[k] = SecretMetadata(**v)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Failed to load metadata for key {k}: {e}")

            return self._secrets

        except (InvalidToken, json.JSONDecodeError) as e:
            logger.error(f"Failed to load secrets: {e}")
            raise ValueError("Failed to decrypt secrets") from e
        except Exception as e:
            logger.error(f"Unexpected error loading secrets: {e}")
            raise RuntimeError("Failed to load secrets: See logs for details") from None

    def restore_backup(self, backup_timestamp: str) -> None:
        """Restore secrets from backup.

        Args:
            backup_timestamp: Timestamp of backup to restore

        Raises:
            FileNotFoundError: If backup not found
        """
        backup_path = self._backup_dir / f"secrets_backup_{backup_timestamp}.enc"
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup {backup_timestamp} not found")

        self._create_backup()

        encrypted_data = backup_path.read_bytes()
        self._atomic_write(self._secrets_file, encrypted_data)
        self._load_secrets()

    def list_backups(self) -> list[str]:
        """List available backup timestamps.

        Returns:
            List of backup timestamp strings
        """
        return [f.stem.replace("secrets_backup_", "") for f in self._backup_dir.glob("secrets_backup_*.enc")]


def find_root_folder() -> Path:
    """Find project root folder by looking for 'pyproject.toml'.

    Returns:
        Path to project root

    Raises:
        FileNotFoundError: If root folder not found
    """
    current_path = Path(__file__).resolve()
    while not (current_path / "pyproject.toml").exists():
        if current_path == current_path.parent:
            raise FileNotFoundError("No 'pyproject.toml' found in any parent directory.")
        current_path = current_path.parent
    return current_path
