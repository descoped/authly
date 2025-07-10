import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from authly import get_config

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
    data: dict, secret_key: str, algorithm: str = "HS256", expires_delta: Optional[int] = None
) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode = data.copy()
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def create_refresh_token(user_id: str, secret_key: str, jti: Optional[str] = None) -> str:
    """
    Create a refresh token with a unique JTI (JWT ID) claim.

    Args:
        user_id (str): The user identifier to include in the token.
        secret_key (str): The secret key used for signing the token.
        jti (Optional[str]): Optionally provide a JTI. If not provided, a new one is generated.

    Returns:
        str: A JWT refresh token.
    """
    # Generate a new JTI if one is not provided
    token_jti = jti or secrets.token_hex(32)
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    payload = {"sub": user_id, "type": "refresh", "jti": token_jti, "exp": int(expire.timestamp())}
    config = get_config()

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
