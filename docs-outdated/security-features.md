# Security Features Guide

This comprehensive guide covers all security features implemented in Authly's OAuth 2.1 authorization server, including authentication mechanisms, authorization controls, cryptographic implementations, and security best practices.

## 🛡️ Security Overview

Authly implements enterprise-grade security measures with defense-in-depth architecture:

- **OAuth 2.1 Compliance** - Latest security standards with mandatory PKCE
- **Cryptographic Security** - Industry-standard encryption and hashing
- **Access Control** - Multi-layered authorization and rate limiting
- **Secure Communications** - TLS encryption and secure headers
- **Audit and Monitoring** - Comprehensive logging and threat detection
- **Data Protection** - Secure storage and memory-safe operations

## 🔐 Authentication Security

### Password Security

#### Secure Password Hashing
```python
# bcrypt with configurable rounds for future-proofing
import bcrypt

class SecurePasswordManager:
    """Enterprise-grade password management with bcrypt."""
    
    def __init__(self, rounds: int = 12):
        """Initialize with configurable bcrypt rounds.
        
        Args:
            rounds: bcrypt cost factor (12 = ~250ms, 14 = ~1s)
        """
        self.rounds = rounds
    
    def hash_password(self, password: str) -> str:
        """Hash password with salt and configurable rounds."""
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against stored hash with constant-time comparison."""
        try:
            password_bytes = password.encode('utf-8')
            hashed_bytes = hashed.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except (ValueError, TypeError):
            # Invalid hash format - return False but still consume time
            bcrypt.checkpw(b"dummy", bcrypt.gensalt())
            return False
```

#### Password Policy Enforcement
```python
# Strong password requirements
import re
from typing import List, Optional

class PasswordPolicy:
    """Enforces strong password requirements."""
    
    MIN_LENGTH = 12
    MAX_LENGTH = 128
    
    REQUIRED_PATTERNS = [
        (r'[a-z]', "at least one lowercase letter"),
        (r'[A-Z]', "at least one uppercase letter"),
        (r'[0-9]', "at least one digit"),
        (r'[!@#$%^&*(),.?":{}|<>]', "at least one special character")
    ]
    
    # Common password patterns to reject
    FORBIDDEN_PATTERNS = [
        r'(.)\1{3,}',  # 4+ repeated characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
    ]
    
    @classmethod
    def validate_password(cls, password: str) -> tuple[bool, List[str]]:
        """Validate password against security policy.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Length check
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters long")
        
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"Password must not exceed {cls.MAX_LENGTH} characters")
        
        # Required patterns
        for pattern, description in cls.REQUIRED_PATTERNS:
            if not re.search(pattern, password):
                errors.append(f"Password must contain {description}")
        
        # Forbidden patterns
        for pattern in cls.FORBIDDEN_PATTERNS:
            if re.search(pattern, password.lower()):
                errors.append("Password contains weak patterns (repeated or sequential characters)")
                break
        
        # Common password check (basic implementation)
        if password.lower() in cls._get_common_passwords():
            errors.append("Password is too common")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def _get_common_passwords() -> set:
        """Get set of common passwords to reject."""
        return {
            'password', '12345678', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890'
        }
```

### JWT Token Security

#### Secure Token Generation
```python
# JWT implementation with security best practices
import jwt
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class SecureJWTManager:
    """Secure JWT token management with comprehensive security measures."""
    
    def __init__(self, secret_key: str, refresh_secret_key: str):
        self.secret_key = secret_key
        self.refresh_secret_key = refresh_secret_key
        self.algorithm = "HS256"  # HMAC SHA-256
        
        # Validate secret key strength
        if len(secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")
    
    def create_access_token(
        self,
        user_id: str,
        client_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires_minutes: int = 30
    ) -> tuple[str, str]:
        """Create secure access token with JTI for revocation tracking."""
        
        jti = secrets.token_urlsafe(32)  # Cryptographically secure random JTI
        now = datetime.utcnow()
        
        payload = {
            # Standard claims
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "jti": jti,
            "iss": "authly",
            "aud": ["authly-api"],
            
            # Custom claims
            "type": "access",
            "scopes": scopes or [],
        }
        
        # Add OAuth-specific claims
        if client_id:
            payload["client_id"] = client_id
            payload["aud"].append(client_id)
        
        # Sign token
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        return token, jti
    
    def create_refresh_token(
        self,
        user_id: str,
        client_id: Optional[str] = None,
        expires_days: int = 7
    ) -> tuple[str, str]:
        """Create secure refresh token with separate secret."""
        
        jti = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=expires_days)).timestamp()),
            "jti": jti,
            "iss": "authly",
            "type": "refresh"
        }
        
        if client_id:
            payload["client_id"] = client_id
        
        # Use separate secret for refresh tokens
        token = jwt.encode(payload, self.refresh_secret_key, algorithm=self.algorithm)
        
        return token, jti
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token with comprehensive validation."""
        
        try:
            # Choose appropriate secret based on token type
            secret = self.refresh_secret_key if token_type == "refresh" else self.secret_key
            
            # Decode and verify token
            payload = jwt.decode(
                token,
                secret,
                algorithms=[self.algorithm],
                # Security options
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_jti": True
                },
                # Expected values
                issuer="authly",
                # Add small leeway for clock skew
                leeway=30
            )
            
            # Verify token type matches expected
            if payload.get("type") != token_type:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            # Log unexpected errors but don't leak information
            return None
```

#### Token Revocation and Blacklisting
```python
# JTI-based token revocation system
class TokenRevocationManager:
    """Manage token revocation with JTI tracking."""
    
    def __init__(self, token_repository):
        self.token_repository = token_repository
    
    async def revoke_token(self, jti: str, reason: str = "user_request") -> bool:
        """Revoke token by marking it as invalid in database."""
        try:
            # Mark token as invalidated
            success = await self.token_repository.invalidate_token(jti)
            
            if success:
                # Log revocation for audit
                logger.info(f"Token revoked: jti={jti}, reason={reason}")
            
            return success
            
        except Exception as e:
            logger.error(f"Token revocation failed: jti={jti}, error={e}")
            return False
    
    async def revoke_user_tokens(
        self,
        user_id: str,
        exclude_jti: Optional[str] = None
    ) -> int:
        """Revoke all tokens for a user (except optionally one)."""
        try:
            count = await self.token_repository.invalidate_user_tokens(
                user_id, exclude_jti
            )
            
            logger.info(f"Revoked {count} tokens for user: {user_id}")
            return count
            
        except Exception as e:
            logger.error(f"User token revocation failed: user_id={user_id}, error={e}")
            return 0
    
    async def is_token_revoked(self, jti: str) -> bool:
        """Check if token is revoked using JTI."""
        try:
            return await self.token_repository.is_token_invalidated(jti)
        except Exception:
            # Fail secure - assume revoked if check fails
            return True
```

### Multi-Factor Authentication Support

#### TOTP Implementation
```python
# Time-based One-Time Password support
import pyotp
import qrcode
import io
import base64

class TOTPManager:
    """Time-based One-Time Password management for 2FA."""
    
    def __init__(self, issuer: str = "Authly"):
        self.issuer = issuer
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret for user."""
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email: str, secret: str) -> str:
        """Generate QR code for TOTP setup."""
        totp = pyotp.TOTP(secret)
        
        # Create provisioning URI
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Convert to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token with time window tolerance."""
        totp = pyotp.TOTP(secret)
        
        # Allow 1 time step in either direction (30-second window)
        return totp.verify(token, valid_window=1)
    
    def get_current_token(self, secret: str) -> str:
        """Get current TOTP token (for testing)."""
        totp = pyotp.TOTP(secret)
        return totp.now()
```

## 🔒 OAuth 2.1 Security Features

### PKCE (Proof Key for Code Exchange)

#### Mandatory PKCE Implementation
```python
# PKCE implementation with security validation
import hashlib
import base64
import secrets
import re

class PKCEManager:
    """Secure PKCE implementation for OAuth 2.1 compliance."""
    
    # OAuth 2.1 requires only S256 method
    SUPPORTED_METHODS = ["S256"]
    
    # PKCE parameter validation patterns
    CODE_VERIFIER_PATTERN = re.compile(r'^[A-Za-z0-9\-._~]{43,128}$')
    CODE_CHALLENGE_PATTERN = re.compile(r'^[A-Za-z0-9\-._~]{43}$')
    
    @staticmethod
    def generate_code_verifier() -> str:
        """Generate cryptographically secure code verifier."""
        # Generate 32 random bytes, encode as base64url
        random_bytes = secrets.token_bytes(32)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        # Ensure length is within valid range (43-128 characters)
        if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
            raise ValueError("Generated code verifier is invalid")
        
        return code_verifier
    
    @staticmethod
    def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
        """Generate code challenge from verifier using S256 method."""
        
        if method not in PKCEManager.SUPPORTED_METHODS:
            raise ValueError(f"Unsupported PKCE method: {method}")
        
        if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
            raise ValueError("Invalid code verifier format")
        
        # S256: BASE64URL(SHA256(code_verifier))
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        
        return code_challenge
    
    @staticmethod
    def verify_code_challenge(
        code_verifier: str,
        code_challenge: str,
        method: str = "S256"
    ) -> bool:
        """Verify PKCE code verifier against stored challenge."""
        
        try:
            # Validate inputs
            if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
                return False
            
            if not PKCEManager.CODE_CHALLENGE_PATTERN.match(code_challenge):
                return False
            
            if method not in PKCEManager.SUPPORTED_METHODS:
                return False
            
            # Generate challenge from verifier
            computed_challenge = PKCEManager.generate_code_challenge(code_verifier, method)
            
            # Constant-time comparison to prevent timing attacks
            return secrets.compare_digest(computed_challenge, code_challenge)
            
        except Exception:
            # Fail securely on any error
            return False

# Example usage
def example_pkce_flow():
    """Example of secure PKCE flow."""
    
    # Client generates PKCE pair
    code_verifier = PKCEManager.generate_code_verifier()
    code_challenge = PKCEManager.generate_code_challenge(code_verifier)
    
    print(f"Code Verifier: {code_verifier}")
    print(f"Code Challenge: {code_challenge}")
    
    # Later, during token exchange
    is_valid = PKCEManager.verify_code_challenge(
        code_verifier, code_challenge, "S256"
    )
    print(f"PKCE Verification: {is_valid}")
```

### Authorization Code Security

#### Secure Code Generation and Validation
```python
# Authorization code management with security measures
class AuthorizationCodeManager:
    """Secure authorization code generation and validation."""
    
    # OAuth 2.1 maximum code lifetime
    MAX_CODE_LIFETIME_MINUTES = 10
    
    def __init__(self, repository):
        self.repository = repository
    
    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scopes: List[str],
        code_challenge: str,
        code_challenge_method: str = "S256"
    ) -> str:
        """Create secure authorization code with PKCE data."""
        
        # Generate cryptographically secure code
        code = secrets.token_urlsafe(32)
        
        # Calculate expiration (OAuth 2.1 maximum)
        expires_at = datetime.utcnow() + timedelta(
            minutes=self.MAX_CODE_LIFETIME_MINUTES
        )
        
        # Store code with all required data
        await self.repository.create({
            "code": code,
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "scopes": scopes,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": expires_at
        })
        
        # Log creation for audit
        logger.info(f"Authorization code created: client_id={client_id}, user_id={user_id}")
        
        return code
    
    async def exchange_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens with full validation."""
        
        try:
            # Retrieve and delete code atomically (single use)
            auth_data = await self.repository.get_and_delete(code)
            
            if not auth_data:
                logger.warning(f"Authorization code not found or already used: {code}")
                return None
            
            # Validate expiration
            if auth_data.expires_at < datetime.utcnow():
                logger.warning(f"Authorization code expired: {code}")
                return None
            
            # Validate client_id
            if auth_data.client_id != client_id:
                logger.warning(f"Client ID mismatch for code: {code}")
                return None
            
            # Validate redirect_uri (exact match required)
            if auth_data.redirect_uri != redirect_uri:
                logger.warning(f"Redirect URI mismatch for code: {code}")
                return None
            
            # Validate PKCE
            pkce_valid = PKCEManager.verify_code_challenge(
                code_verifier,
                auth_data.code_challenge,
                auth_data.code_challenge_method
            )
            
            if not pkce_valid:
                logger.warning(f"PKCE verification failed for code: {code}")
                return None
            
            # All validations passed
            logger.info(f"Authorization code exchanged successfully: client_id={client_id}")
            
            return {
                "client_id": auth_data.client_id,
                "user_id": auth_data.user_id,
                "scopes": auth_data.scopes
            }
            
        except Exception as e:
            logger.error(f"Authorization code exchange error: {e}")
            return None
```

### Client Authentication Security

#### Secure Client Secret Management
```python
# Client authentication with multiple methods
class ClientAuthenticationManager:
    """Secure OAuth client authentication."""
    
    def __init__(self, client_repository):
        self.client_repository = client_repository
    
    async def authenticate_client(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        auth_header: Optional[str] = None
    ) -> Optional[OAuthClient]:
        """Authenticate OAuth client using multiple methods."""
        
        # Retrieve client
        client = await self.client_repository.get_by_client_id(client_id)
        if not client or not client.is_active:
            # Log failed attempt
            logger.warning(f"Client authentication failed - invalid client: {client_id}")
            return None
        
        # Public clients don't require authentication
        if client.client_type == "public":
            logger.info(f"Public client authenticated: {client_id}")
            return client
        
        # Confidential clients require authentication
        if client.client_type == "confidential":
            return await self._authenticate_confidential_client(
                client, client_secret, auth_header
            )
        
        return None
    
    async def _authenticate_confidential_client(
        self,
        client: OAuthClient,
        client_secret: Optional[str],
        auth_header: Optional[str]
    ) -> Optional[OAuthClient]:
        """Authenticate confidential client with multiple methods."""
        
        # Try HTTP Basic authentication first
        if auth_header and auth_header.startswith("Basic "):
            return await self._authenticate_basic(client, auth_header)
        
        # Try client_secret_post method
        if client_secret:
            return await self._authenticate_post(client, client_secret)
        
        logger.warning(f"No valid authentication method for client: {client.client_id}")
        return None
    
    async def _authenticate_basic(
        self,
        client: OAuthClient,
        auth_header: str
    ) -> Optional[OAuthClient]:
        """Authenticate using HTTP Basic method."""
        
        try:
            # Parse Basic authentication header
            encoded_credentials = auth_header[6:]  # Remove "Basic "
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
            
            # Verify client_id matches
            if username != client.client_id:
                logger.warning(f"Client ID mismatch in Basic auth: {client.client_id}")
                return None
            
            # Verify client secret
            if self._verify_client_secret(password, client.client_secret_hash):
                logger.info(f"Client authenticated via Basic: {client.client_id}")
                return client
            
        except Exception as e:
            logger.warning(f"Basic authentication parsing error: {e}")
        
        logger.warning(f"Basic authentication failed: {client.client_id}")
        return None
    
    async def _authenticate_post(
        self,
        client: OAuthClient,
        client_secret: str
    ) -> Optional[OAuthClient]:
        """Authenticate using client_secret_post method."""
        
        if self._verify_client_secret(client_secret, client.client_secret_hash):
            logger.info(f"Client authenticated via POST: {client.client_id}")
            return client
        
        logger.warning(f"POST authentication failed: {client.client_id}")
        return None
    
    def _verify_client_secret(self, provided_secret: str, stored_hash: str) -> bool:
        """Verify client secret with constant-time comparison."""
        try:
            return bcrypt.checkpw(
                provided_secret.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception:
            # Invalid hash format or other error
            # Consume time to prevent timing attacks
            bcrypt.checkpw(b"dummy", bcrypt.gensalt())
            return False
    
    def generate_client_secret(self) -> tuple[str, str]:
        """Generate new client secret and return (secret, hash)."""
        # Generate cryptographically secure secret
        secret = f"cs_live_{secrets.token_urlsafe(32)}"
        
        # Hash for storage
        secret_hash = bcrypt.hashpw(secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        return secret, secret_hash
```

## 🛡️ Access Control and Authorization

### Scope-Based Access Control

#### Dynamic Scope Validation
```python
# Comprehensive scope management and validation
class ScopeAuthorizationManager:
    """Manage OAuth 2.1 scope-based access control."""
    
    def __init__(self, scope_repository):
        self.scope_repository = scope_repository
    
    async def validate_requested_scopes(
        self,
        client_id: str,
        requested_scopes: List[str]
    ) -> List[str]:
        """Validate and filter scopes based on client permissions."""
        
        # Get client's allowed scopes
        allowed_scopes = await self.scope_repository.get_client_scopes(client_id)
        allowed_scope_names = {scope.scope_name for scope in allowed_scopes}
        
        # Filter requested scopes to only allowed ones
        valid_scopes = []
        for scope in requested_scopes:
            if scope in allowed_scope_names:
                valid_scopes.append(scope)
            else:
                logger.warning(f"Unauthorized scope requested: client={client_id}, scope={scope}")
        
        return valid_scopes
    
    async def get_default_scopes(self, client_id: str) -> List[str]:
        """Get default scopes for client when none specified."""
        
        # Get client's default scopes
        default_scopes = await self.scope_repository.get_default_scopes_for_client(client_id)
        return [scope.scope_name for scope in default_scopes]
    
    async def check_token_scope(
        self,
        token_scopes: List[str],
        required_scope: str
    ) -> bool:
        """Check if token has required scope for API access."""
        
        # Exact scope match
        if required_scope in token_scopes:
            return True
        
        # Check for hierarchical scope permissions
        return self._check_hierarchical_scopes(token_scopes, required_scope)
    
    def _check_hierarchical_scopes(
        self,
        token_scopes: List[str],
        required_scope: str
    ) -> bool:
        """Check hierarchical scope permissions (e.g., admin > write > read)."""
        
        # Define scope hierarchy
        hierarchy = {
            "admin": ["admin", "write", "read", "profile"],
            "write": ["write", "read"],
            "read": ["read"]
        }
        
        # Check if any token scope grants the required scope
        for token_scope in token_scopes:
            if token_scope in hierarchy:
                if required_scope in hierarchy[token_scope]:
                    return True
        
        return False

# FastAPI dependency for scope validation
from fastapi import Depends, HTTPException, status

def require_scope(required_scope: str):
    """FastAPI dependency factory for scope-based protection."""
    
    async def scope_dependency(
        current_user: dict = Depends(get_current_user),
        scope_manager: ScopeAuthorizationManager = Depends(get_scope_manager)
    ) -> dict:
        """Verify user has required scope."""
        
        token_scopes = current_user.get("scopes", [])
        
        has_scope = await scope_manager.check_token_scope(token_scopes, required_scope)
        
        if not has_scope:
            logger.warning(
                f"Insufficient scope: user={current_user['sub']}, "
                f"required={required_scope}, available={token_scopes}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scope for this operation"
            )
        
        return current_user
    
    return scope_dependency

# Usage in API endpoints
@router.get("/api/v1/admin/users")
async def list_users(
    current_user: dict = Depends(require_scope("admin"))
):
    """Admin endpoint requiring admin scope."""
    pass

@router.get("/api/v1/profile")
async def get_profile(
    current_user: dict = Depends(require_scope("profile"))
):
    """Profile endpoint requiring profile scope."""
    pass
```

### Rate Limiting and Brute Force Protection

#### Advanced Rate Limiting
```python
# Multi-tier rate limiting with different strategies
from collections import defaultdict
import time
from typing import Dict, Any
import redis.asyncio as redis

class AdvancedRateLimiter:
    """Multi-tier rate limiting with different strategies."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self.memory_buckets = defaultdict(list)  # Fallback for non-distributed
        
        # Rate limiting tiers
        self.limits = {
            "auth": {"requests": 10, "window": 60},      # 10 auth requests per minute
            "api": {"requests": 100, "window": 60},      # 100 API requests per minute
            "discovery": {"requests": 1000, "window": 60}, # 1000 discovery per minute
        }
    
    async def is_allowed(
        self,
        identifier: str,
        limit_type: str = "api"
    ) -> tuple[bool, Dict[str, Any]]:
        """Check if request is allowed with detailed response."""
        
        if self.redis:
            return await self._redis_rate_limit(identifier, limit_type)
        else:
            return await self._memory_rate_limit(identifier, limit_type)
    
    async def _redis_rate_limit(
        self,
        identifier: str,
        limit_type: str
    ) -> tuple[bool, Dict[str, Any]]:
        """Redis-based distributed rate limiting with sliding window."""
        
        config = self.limits.get(limit_type, self.limits["api"])
        window = config["window"]
        max_requests = config["requests"]
        
        key = f"rate_limit:{limit_type}:{identifier}"
        now = time.time()
        window_start = now - window
        
        # Lua script for atomic sliding window
        lua_script = """
        local key = KEYS[1]
        local window_start = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local max_requests = tonumber(ARGV[3])
        local window = tonumber(ARGV[4])
        
        -- Remove expired entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Count current requests
        local current_requests = redis.call('ZCARD', key)
        
        if current_requests < max_requests then
            -- Add current request
            redis.call('ZADD', key, now, now)
            redis.call('EXPIRE', key, window)
            return {1, max_requests - current_requests - 1, window}
        else
            -- Rate limit exceeded
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local reset_time = 0
            if #oldest > 0 then
                reset_time = tonumber(oldest[2]) + window
            end
            return {0, 0, reset_time - now}
        end
        """
        
        result = await self.redis.eval(
            lua_script, 1, key, window_start, now, max_requests, window
        )
        
        allowed = bool(result[0])
        remaining = int(result[1])
        reset_time = float(result[2])
        
        return allowed, {
            "allowed": allowed,
            "remaining": remaining,
            "reset_time": reset_time,
            "limit": max_requests,
            "window": window
        }
    
    async def _memory_rate_limit(
        self,
        identifier: str,
        limit_type: str
    ) -> tuple[bool, Dict[str, Any]]:
        """Memory-based rate limiting for single-instance deployments."""
        
        config = self.limits.get(limit_type, self.limits["api"])
        window = config["window"]
        max_requests = config["requests"]
        
        key = f"{limit_type}:{identifier}"
        now = time.time()
        window_start = now - window
        
        # Clean old entries
        requests = self.memory_buckets[key]
        requests[:] = [req_time for req_time in requests if req_time > window_start]
        
        if len(requests) < max_requests:
            requests.append(now)
            return True, {
                "allowed": True,
                "remaining": max_requests - len(requests),
                "reset_time": window,
                "limit": max_requests,
                "window": window
            }
        else:
            return False, {
                "allowed": False,
                "remaining": 0,
                "reset_time": requests[0] + window - now,
                "limit": max_requests,
                "window": window
            }

# Adaptive rate limiting based on client behavior
class AdaptiveRateLimiter(AdvancedRateLimiter):
    """Adaptive rate limiting that adjusts based on client behavior."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        super().__init__(redis_client)
        self.trust_scores = defaultdict(float)  # Client trust scores
    
    async def update_trust_score(
        self,
        identifier: str,
        event_type: str,
        value: float = 1.0
    ):
        """Update client trust score based on behavior."""
        
        # Trust score adjustments
        adjustments = {
            "successful_auth": 0.1,
            "failed_auth": -0.5,
            "token_revoked": -0.3,
            "valid_request": 0.05,
            "invalid_request": -0.2,
            "security_violation": -1.0
        }
        
        adjustment = adjustments.get(event_type, 0) * value
        self.trust_scores[identifier] += adjustment
        
        # Keep trust score in reasonable range
        self.trust_scores[identifier] = max(-5.0, min(5.0, self.trust_scores[identifier]))
    
    async def is_allowed(
        self,
        identifier: str,
        limit_type: str = "api"
    ) -> tuple[bool, Dict[str, Any]]:
        """Check rate limit with trust score adjustment."""
        
        base_allowed, info = await super().is_allowed(identifier, limit_type)
        
        # Adjust based on trust score
        trust_score = self.trust_scores.get(identifier, 0.0)
        
        if trust_score < -2.0:
            # Reduce limits for untrusted clients
            info["limit"] = int(info["limit"] * 0.5)
            info["remaining"] = max(0, int(info["remaining"] * 0.5))
            
            if info["remaining"] == 0:
                base_allowed = False
        
        elif trust_score > 2.0:
            # Increase limits for trusted clients
            info["limit"] = int(info["limit"] * 1.5)
            info["remaining"] = int(info["remaining"] * 1.5)
            base_allowed = True
        
        info["trust_score"] = trust_score
        return base_allowed, info
```

## 🔐 Cryptographic Security

### Secure Secret Management

#### Memory-Safe Secret Handling
```python
# Secure secret management with memory wiping
import ctypes
import mmap
import os
from typing import Optional

class SecureSecret:
    """Memory-safe secret storage with automatic cleanup."""
    
    def __init__(self, secret: str):
        self._length = len(secret)
        
        # Allocate locked memory pages
        self._memory = mmap.mmap(-1, self._length, 
                                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        
        # Lock memory to prevent swapping
        try:
            self._memory.mlock()
        except OSError:
            # mlock may fail due to permissions - continue without
            pass
        
        # Copy secret to locked memory
        self._memory.write(secret.encode('utf-8'))
        self._memory.seek(0)
        
        # Clear original secret from regular memory
        self._wipe_string(secret)
    
    def get_secret(self) -> str:
        """Get secret value (use sparingly)."""
        self._memory.seek(0)
        return self._memory.read(self._length).decode('utf-8')
    
    def compare_secret(self, other: str) -> bool:
        """Compare secret with constant-time comparison."""
        secret = self.get_secret()
        try:
            return secrets.compare_digest(secret, other)
        finally:
            self._wipe_string(secret)
    
    def __del__(self):
        """Secure cleanup on object destruction."""
        if hasattr(self, '_memory'):
            # Overwrite memory with random data
            self._memory.seek(0)
            self._memory.write(os.urandom(self._length))
            
            # Unlock and close
            try:
                self._memory.munlock()
            except OSError:
                pass
            self._memory.close()
    
    @staticmethod
    def _wipe_string(s: str):
        """Attempt to wipe string from memory."""
        # This is best-effort - Python string immutability makes this difficult
        if hasattr(s, '_clear'):
            s._clear()

class SecretProvider:
    """Provide secrets from various sources with secure handling."""
    
    def __init__(self):
        self._secrets = {}
    
    def load_from_env(self, key: str, env_var: str) -> bool:
        """Load secret from environment variable."""
        value = os.getenv(env_var)
        if value:
            self._secrets[key] = SecureSecret(value)
            return True
        return False
    
    def load_from_file(self, key: str, file_path: str) -> bool:
        """Load secret from file with secure handling."""
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            self._secrets[key] = SecureSecret(content)
            
            # Attempt to clear file content from memory
            content = '\x00' * len(content)
            return True
            
        except Exception as e:
            logger.error(f"Failed to load secret from file {file_path}: {e}")
            return False
    
    def get_secret(self, key: str) -> Optional[str]:
        """Get secret value."""
        secret_obj = self._secrets.get(key)
        return secret_obj.get_secret() if secret_obj else None
    
    def compare_secret(self, key: str, value: str) -> bool:
        """Compare secret with constant-time comparison."""
        secret_obj = self._secrets.get(key)
        return secret_obj.compare_secret(value) if secret_obj else False
```

### Encryption at Rest

#### Database Field Encryption
```python
# Symmetric encryption for sensitive database fields
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class FieldEncryption:
    """Encrypt sensitive database fields."""
    
    def __init__(self, master_key: str, salt: bytes = None):
        self.salt = salt or os.urandom(16)
        
        # Derive encryption key from master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        self.cipher = Fernet(key)
    
    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt field value for database storage."""
        if not plaintext:
            return plaintext
        
        encrypted_bytes = self.cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('ascii')
    
    def decrypt_field(self, ciphertext: str) -> str:
        """Decrypt field value from database."""
        if not ciphertext:
            return ciphertext
        
        try:
            encrypted_bytes = base64.b64decode(ciphertext.encode('ascii'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Field decryption failed: {e}")
            raise ValueError("Failed to decrypt field")
    
    def get_salt(self) -> str:
        """Get salt for storage (needed for decryption)."""
        return base64.b64encode(self.salt).decode('ascii')

# Model with encrypted fields
class EncryptedUserModel(UserModel):
    """User model with encrypted sensitive fields."""
    
    def __init__(self, **data):
        # Decrypt sensitive fields if they're encrypted
        if 'email_encrypted' in data:
            encryption = FieldEncryption(get_encryption_key())
            data['email'] = encryption.decrypt_field(data['email_encrypted'])
        
        super().__init__(**data)
    
    def to_encrypted_dict(self) -> dict:
        """Convert to dictionary with encrypted sensitive fields."""
        data = self.dict()
        encryption = FieldEncryption(get_encryption_key())
        
        # Encrypt sensitive fields
        if 'email' in data:
            data['email_encrypted'] = encryption.encrypt_field(data['email'])
            del data['email']
        
        return data
```

## 🔍 Security Monitoring and Audit

### Comprehensive Audit Logging

#### Security Event Logging
```python
# Security-focused audit logging
import json
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any

class SecurityEventType(Enum):
    """Types of security events to log."""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    
    # OAuth events
    OAUTH_AUTHORIZATION = "oauth_authorization"
    OAUTH_TOKEN_ISSUED = "oauth_token_issued"
    OAUTH_TOKEN_REVOKED = "oauth_token_revoked"
    OAUTH_CLIENT_CREATED = "oauth_client_created"
    OAUTH_CLIENT_DELETED = "oauth_client_deleted"
    
    # Security violations
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_TOKEN = "invalid_token"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PKCE_FAILURE = "pkce_failure"
    
    # Administrative events
    ADMIN_LOGIN = "admin_login"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    PERMISSION_CHANGE = "permission_change"

class SecurityAuditLogger:
    """Comprehensive security audit logging."""
    
    def __init__(self, logger_name: str = "authly.security"):
        self.logger = logging.getLogger(logger_name)
        
        # Configure structured logging
        self.logger.setLevel(logging.INFO)
        
        # Ensure audit logs are always written
        if not self.logger.handlers:
            handler = logging.FileHandler('/var/log/authly/security_audit.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_security_event(
        self,
        event_type: SecurityEventType,
        user_id: Optional[str] = None,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True
    ):
        """Log structured security event."""
        
        event_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "success": success,
            "user_id": user_id,
            "client_id": client_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {}
        }
        
        # Remove None values
        event_data = {k: v for k, v in event_data.items() if v is not None}
        
        # Log as structured JSON
        self.logger.info(json.dumps(event_data))
        
        # For critical security events, also log at ERROR level
        if event_type in [
            SecurityEventType.UNAUTHORIZED_ACCESS,
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            SecurityEventType.PKCE_FAILURE
        ] and not success:
            self.logger.error(f"SECURITY ALERT: {json.dumps(event_data)}")

# Security event decorator
def log_security_event(event_type: SecurityEventType):
    """Decorator to automatically log security events."""
    
    def decorator(func):
        async def wrapper(*args, **kwargs):
            audit_logger = SecurityAuditLogger()
            
            try:
                result = await func(*args, **kwargs)
                
                # Extract context from request if available
                context = {}
                if hasattr(kwargs.get('request'), 'client'):
                    context['ip_address'] = kwargs['request'].client.host
                if hasattr(kwargs.get('request'), 'headers'):
                    context['user_agent'] = kwargs['request'].headers.get('user-agent')
                
                audit_logger.log_security_event(
                    event_type=event_type,
                    success=True,
                    **context
                )
                
                return result
                
            except Exception as e:
                audit_logger.log_security_event(
                    event_type=event_type,
                    success=False,
                    details={"error": str(e)}
                )
                raise
        
        return wrapper
    return decorator

# Usage example
@log_security_event(SecurityEventType.OAUTH_TOKEN_ISSUED)
async def create_oauth_token(user_id: str, client_id: str, scopes: List[str]):
    """Create OAuth token with automatic audit logging."""
    # Token creation logic
    pass
```

### Threat Detection

#### Anomaly Detection System
```python
# Basic anomaly detection for security threats
from collections import defaultdict, deque
import statistics

class SecurityAnomalyDetector:
    """Detect security anomalies and potential threats."""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        
        # Track metrics per user/IP
        self.request_counts = defaultdict(deque)
        self.failed_attempts = defaultdict(deque)
        self.response_times = defaultdict(deque)
        self.endpoints_accessed = defaultdict(set)
        
        # Thresholds
        self.thresholds = {
            "max_requests_per_minute": 60,
            "max_failed_attempts": 5,
            "max_response_time_deviation": 3.0,  # Standard deviations
            "max_unique_endpoints": 20
        }
    
    def analyze_request(
        self,
        identifier: str,
        endpoint: str,
        response_time: float,
        status_code: int,
        timestamp: float
    ) -> List[str]:
        """Analyze request for anomalies."""
        
        anomalies = []
        
        # Update metrics
        self._update_metrics(identifier, endpoint, response_time, status_code, timestamp)
        
        # Check for anomalies
        anomalies.extend(self._check_request_rate(identifier))
        anomalies.extend(self._check_failed_attempts(identifier))
        anomalies.extend(self._check_response_time_anomaly(identifier, response_time))
        anomalies.extend(self._check_endpoint_scanning(identifier))
        
        return anomalies
    
    def _update_metrics(
        self,
        identifier: str,
        endpoint: str,
        response_time: float,
        status_code: int,
        timestamp: float
    ):
        """Update metrics for identifier."""
        
        # Request count
        self.request_counts[identifier].append(timestamp)
        self._trim_window(self.request_counts[identifier])
        
        # Failed attempts
        if status_code >= 400:
            self.failed_attempts[identifier].append(timestamp)
            self._trim_window(self.failed_attempts[identifier])
        
        # Response times
        self.response_times[identifier].append(response_time)
        self._trim_window(self.response_times[identifier])
        
        # Endpoints accessed
        self.endpoints_accessed[identifier].add(endpoint)
        if len(self.endpoints_accessed[identifier]) > self.window_size:
            # Reset periodically to prevent memory growth
            self.endpoints_accessed[identifier] = set(list(self.endpoints_accessed[identifier])[-50:])
    
    def _trim_window(self, deque_obj: deque):
        """Trim deque to window size."""
        while len(deque_obj) > self.window_size:
            deque_obj.popleft()
    
    def _check_request_rate(self, identifier: str) -> List[str]:
        """Check for excessive request rate."""
        anomalies = []
        
        requests = self.request_counts[identifier]
        if len(requests) < 2:
            return anomalies
        
        # Count requests in last minute
        now = time.time()
        recent_requests = sum(1 for req_time in requests if now - req_time <= 60)
        
        if recent_requests > self.thresholds["max_requests_per_minute"]:
            anomalies.append(f"Excessive request rate: {recent_requests}/min")
        
        return anomalies
    
    def _check_failed_attempts(self, identifier: str) -> List[str]:
        """Check for excessive failed attempts."""
        anomalies = []
        
        failed = self.failed_attempts[identifier]
        if len(failed) < 2:
            return anomalies
        
        # Count failed attempts in last 5 minutes
        now = time.time()
        recent_failures = sum(1 for fail_time in failed if now - fail_time <= 300)
        
        if recent_failures > self.thresholds["max_failed_attempts"]:
            anomalies.append(f"Excessive failed attempts: {recent_failures}")
        
        return anomalies
    
    def _check_response_time_anomaly(
        self,
        identifier: str,
        current_response_time: float
    ) -> List[str]:
        """Check for response time anomalies."""
        anomalies = []
        
        response_times = list(self.response_times[identifier])
        if len(response_times) < 10:  # Need baseline
            return anomalies
        
        # Calculate baseline statistics
        mean_time = statistics.mean(response_times[:-1])  # Exclude current
        std_dev = statistics.stdev(response_times[:-1])
        
        if std_dev == 0:
            return anomalies
        
        # Check if current response time is anomalous
        z_score = abs(current_response_time - mean_time) / std_dev
        
        if z_score > self.thresholds["max_response_time_deviation"]:
            anomalies.append(f"Response time anomaly: {current_response_time:.2f}s (z-score: {z_score:.2f})")
        
        return anomalies
    
    def _check_endpoint_scanning(self, identifier: str) -> List[str]:
        """Check for potential endpoint scanning."""
        anomalies = []
        
        endpoints = self.endpoints_accessed[identifier]
        
        if len(endpoints) > self.thresholds["max_unique_endpoints"]:
            anomalies.append(f"Potential endpoint scanning: {len(endpoints)} unique endpoints")
        
        return anomalies

# Integration with security monitoring
class SecurityMonitor:
    """Comprehensive security monitoring system."""
    
    def __init__(self):
        self.anomaly_detector = SecurityAnomalyDetector()
        self.audit_logger = SecurityAuditLogger()
        self.alert_manager = SecurityAlertManager()
    
    async def analyze_request(
        self,
        request: Request,
        response: Response,
        response_time: float
    ):
        """Analyze request for security issues."""
        
        identifier = request.client.host
        endpoint = request.url.path
        status_code = response.status_code
        timestamp = time.time()
        
        # Check for anomalies
        anomalies = self.anomaly_detector.analyze_request(
            identifier, endpoint, response_time, status_code, timestamp
        )
        
        # Handle detected anomalies
        if anomalies:
            await self._handle_anomalies(request, anomalies)
    
    async def _handle_anomalies(self, request: Request, anomalies: List[str]):
        """Handle detected security anomalies."""
        
        # Log security event
        self.audit_logger.log_security_event(
            event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent'),
            details={"anomalies": anomalies},
            success=False
        )
        
        # Send alerts for severe anomalies
        severe_keywords = ["excessive", "scanning", "anomaly"]
        if any(keyword in anomaly.lower() for anomaly in anomalies for keyword in severe_keywords):
            await self.alert_manager.send_security_alert(
                title="Security Anomaly Detected",
                message=f"Anomalies detected from {request.client.host}: {', '.join(anomalies)}",
                severity="high"
            )

# FastAPI middleware for security monitoring
@app.middleware("http")
async def security_monitoring_middleware(request: Request, call_next):
    """Security monitoring middleware."""
    
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate response time
    response_time = time.time() - start_time
    
    # Analyze request
    security_monitor = SecurityMonitor()
    await security_monitor.analyze_request(request, response, response_time)
    
    return response
```

This comprehensive security features guide covers all aspects of Authly's security implementation, from cryptographic fundamentals to advanced threat detection, ensuring enterprise-grade protection for OAuth 2.1 operations.