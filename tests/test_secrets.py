import logging
from pathlib import Path

import pytest

from authly.config.secure import SecureSecrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secret_store(tmp_path):
    # secrets = SecureSecrets(secrets_location=tmp_path)
    # secrets = SecureSecrets(Path.home())
    secrets = SecureSecrets()
    logger.info(f"\nCreated _secrets_file: {secrets._secrets_file}")
    logger.info(f"\nCreated _key_file: {secrets._key_file}")
    logger.info(f"\nCreated _backup_dir: {secrets._backup_dir}")
    return secrets


def test_jwt_secrets(secret_store):
    # Set secrets
    secret_store.set_secret("JWT_SECRET_KEY", "your-secret-key-here")
    secret_store.set_secret("JWT_REFRESH_SECRET_KEY", "your-refresh-secret-key-here")

    # Verify retrieval
    assert secret_store.get_secret("JWT_SECRET_KEY") == "your-secret-key-here"
    assert secret_store.get_secret("JWT_REFRESH_SECRET_KEY") == "your-refresh-secret-key-here"


def test_rotate_keys(secret_store):
    secret_store.set_secret("JWT_SECRET_KEY", "original-key")
    secret_store.rotate_key()
    assert secret_store.get_secret("JWT_SECRET_KEY") == "original-key"


def test_secure_delete(secret_store):
    secret_store.set_secret("JWT_SECRET_KEY", "delete-me")
    secret_store.secure_delete("JWT_SECRET_KEY")
    assert secret_store.get_secret("JWT_SECRET_KEY") is None
