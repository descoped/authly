import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from authly.config import AuthlyConfig

logger = logging.getLogger(__name__)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8") if isinstance(hashed_password, str) else hashed_password,
    )


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(
    data: dict, secret_key: str, config: AuthlyConfig, algorithm: str = "HS256", expires_delta: Optional[int] = None
) -> str:
    """Create access token with required configuration.

    Args:
        data: Token payload data
        secret_key: Secret key for signing
        algorithm: JWT algorithm
        expires_delta: Optional expiration override in minutes
        config: Required configuration object

    Returns:
        JWT access token string
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.access_token_expire_minutes)

    to_encode = data.copy()
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def create_refresh_token(user_id: str, secret_key: str, config: AuthlyConfig, jti: Optional[str] = None) -> str:
    """
    Create a refresh token with a unique JTI (JWT ID) claim.

    Args:
        user_id: The user identifier to include in the token
        secret_key: The secret key used for signing the token
        config: Required configuration object
        jti: Optionally provide a JTI. If not provided, a new one is generated

    Returns:
        JWT refresh token string
    """
    # Generate a new JTI if one is not provided
    if jti is None:
        token_jti = secrets.token_hex(config.token_hex_length)
    else:
        token_jti = jti

    expire = datetime.now(timezone.utc) + timedelta(days=config.refresh_token_expire_days)
    payload = {"sub": user_id, "type": "refresh", "jti": token_jti, "exp": int(expire.timestamp())}

    return jwt.encode(payload, secret_key, algorithm=config.algorithm)


def decode_token(token: str, secret_key: str, algorithm: str = "HS256") -> dict:
    """
    Decode and verify JWT token.

    Args:
        token: The JWT token to decode
        secret_key: Secret key used to decode the token
        algorithm: Algorithm used for token encoding (default: HS256)

    Returns:
        dict: The decoded token payload

    Raises:
        ValueError: If token validation fails
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except JWTError as e:
        logger.error(f"JWT decode error: {str(e)}")
        raise ValueError("Could not validate credentials")
