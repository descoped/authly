import logging
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from authly.config import AuthlyConfig

logger = logging.getLogger(__name__)

# Import authentication metrics tracking
try:
    from authly.monitoring.metrics import metrics

    METRICS_ENABLED = True
except ImportError:
    logger.debug("Metrics collection not available in auth core")
    METRICS_ENABLED = False
    metrics = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    import time

    start_time = time.time()

    try:
        result = bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8") if isinstance(hashed_password, str) else hashed_password,
        )

        # Track password verification metrics
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            status = "success" if result else "failed"
            metrics.track_login_attempt(status, "password")

        return result
    except Exception:
        # Track password verification errors
        if METRICS_ENABLED and metrics:
            time.time() - start_time
            metrics.track_login_attempt("error", "password")
        raise


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(
    data: dict, secret_key: str, config: AuthlyConfig, algorithm: str = "HS256", expires_delta: int | None = None
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
    import time

    start_time = time.time()

    try:
        if expires_delta:
            expire = datetime.now(UTC) + timedelta(minutes=expires_delta)
        else:
            expire = datetime.now(UTC) + timedelta(minutes=config.access_token_expire_minutes)

        to_encode = data.copy()
        to_encode.update({"exp": int(expire.timestamp())})
        token = jwt.encode(to_encode, secret_key, algorithm=algorithm)

        # Track token generation metrics
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.oauth_token_generation_duration_seconds.labels(token_type="access_token").observe(duration)

        return token
    except Exception:
        # Track token generation errors
        if METRICS_ENABLED and metrics:
            metrics.track_security_event("token_generation_error", "error")
        raise


def create_refresh_token(user_id: str, secret_key: str, config: AuthlyConfig, jti: str | None = None) -> str:
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
    import time

    start_time = time.time()

    try:
        # Generate a new JTI if one is not provided
        token_jti = secrets.token_hex(config.token_hex_length) if jti is None else jti

        expire = datetime.now(UTC) + timedelta(days=config.refresh_token_expire_days)
        payload = {"sub": user_id, "type": "refresh", "jti": token_jti, "exp": int(expire.timestamp())}

        token = jwt.encode(payload, secret_key, algorithm=config.algorithm)

        # Track token generation metrics
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.oauth_token_generation_duration_seconds.labels(token_type="refresh_token").observe(duration)

        return token
    except Exception:
        # Track token generation errors
        if METRICS_ENABLED and metrics:
            metrics.track_security_event("token_generation_error", "error")
        raise


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
    import time

    start_time = time.time()

    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])

        # Track successful token validation
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            token_type = payload.get("type", "access_token")
            metrics.oauth_token_generation_duration_seconds.labels(token_type=f"{token_type}_validation").observe(
                duration
            )

        return payload
    except JWTError as e:
        # Track token validation failures
        if METRICS_ENABLED and metrics:
            duration = time.time() - start_time
            metrics.track_security_event("token_validation_failed", "warning")

        logger.error(f"JWT decode error: {e!s}")
        raise ValueError("Could not validate credentials") from e
