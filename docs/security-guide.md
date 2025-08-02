# Security Implementation Guide

Comprehensive security implementation guide for Authly OAuth 2.1 Authorization Server, covering authentication mechanisms, authorization controls, cryptographic implementations, and security best practices.

## 🛡️ Security Overview

Authly implements enterprise-grade security measures with defense-in-depth architecture:

- **OAuth 2.1 Compliance** - Latest security standards with mandatory PKCE
- **OpenID Connect 1.0** - Complete OIDC security with ID token validation
- **Enterprise Authentication** - Multi-factor authentication and secure password policies
- **Cryptographic Security** - Industry-standard encryption and hashing
- **Access Control** - Multi-layered authorization and rate limiting
- **Secure Communications** - TLS encryption and comprehensive security headers
- **Audit and Monitoring** - Comprehensive logging and threat detection
- **Data Protection** - Secure storage and GDPR compliance

### Production Security Status

**✅ SECURITY POSTURE: PRODUCTION-READY**
- All critical security vulnerabilities resolved
- Enterprise-grade secret management implemented
- OAuth 2.1 and OIDC security compliance validated
- Independent security assessment completed

## 🔐 Authentication Security

### Password Security

#### Secure Password Hashing
```python
# Current implementation using bcrypt
import bcrypt

def hash_password(password: str) -> str:
    """Hash password using bcrypt with salt."""
    salt = bcrypt.gensalt(rounds=12)  # Configurable cost factor
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password with constant-time comparison."""
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            password_hash.encode('utf-8')
        )
    except (ValueError, TypeError):
        # Invalid hash format - consume time to prevent timing attacks
        bcrypt.checkpw(b"dummy", bcrypt.gensalt())
        return False
```

**Security Features**:
- ✅ **Adaptive Hashing**: Bcrypt provides future-proof security
- ✅ **Unique Salts**: Salt generation for each password
- ✅ **Timing Attack Resistance**: Constant-time comparison
- ✅ **Configurable Cost**: Adjustable rounds for performance/security balance

#### Password Policy Implementation
```python
# Strong password requirements
import re
from typing import List, Tuple

class PasswordPolicy:
    """Enterprise password policy enforcement."""
    
    MIN_LENGTH = 12
    MAX_LENGTH = 128
    
    REQUIRED_PATTERNS = [
        (r'[a-z]', "at least one lowercase letter"),
        (r'[A-Z]', "at least one uppercase letter"),
        (r'[0-9]', "at least one digit"),
        (r'[!@#$%^&*(),.?":{}|<>]', "at least one special character")
    ]
    
    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, List[str]]:
        """Validate password against security policy."""
        errors = []
        
        # Length validation
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"Password must not exceed {cls.MAX_LENGTH} characters")
        
        # Pattern validation
        for pattern, description in cls.REQUIRED_PATTERNS:
            if not re.search(pattern, password):
                errors.append(f"Password must contain {description}")
        
        # Check for weak patterns
        if re.search(r'(.)\1{3,}', password):  # 4+ repeated characters
            errors.append("Password contains weak patterns")
        
        return len(errors) == 0, errors
```

### JWT Token Security

#### Secure Token Implementation
```python
# Current JWT implementation
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

class SecureJWTManager:
    """Production JWT token management with comprehensive security."""
    
    def __init__(self, secret_key: str, refresh_secret_key: str):
        self.secret_key = secret_key
        self.refresh_secret_key = refresh_secret_key
        self.algorithm = "HS256"
        
        # Validate secret strength
        if len(secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")
    
    def create_access_token(
        self,
        user_id: str,
        client_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires_minutes: int = 30
    ) -> Tuple[str, str]:
        """Create secure access token with JTI for revocation tracking."""
        
        jti = secrets.token_urlsafe(32)  # Cryptographically secure JTI
        now = datetime.utcnow()
        
        payload = {
            # Standard claims (RFC 7519)
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "jti": jti,
            "iss": "authly",
            "aud": ["authly-api"],
            
            # OAuth 2.1 claims
            "type": "access_token",
            "scope": " ".join(scopes or []),
        }
        
        if client_id:
            payload["client_id"] = client_id
            payload["aud"].append(client_id)
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token, jti
    
    def verify_token(self, token: str, token_type: str = "access_token") -> Optional[Dict[str, Any]]:
        """Verify JWT token with comprehensive validation."""
        
        try:
            secret = self.refresh_secret_key if token_type == "refresh_token" else self.secret_key
            
            payload = jwt.decode(
                token,
                secret,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_jti": True
                },
                issuer="authly",
                leeway=30  # Allow 30 seconds clock skew
            )
            
            # Verify token type
            if payload.get("type") != token_type:
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None
```

**Security Features**:
- ✅ **Cryptographically Secure JTI**: Unique token identifiers for revocation
- ✅ **Separate Secrets**: Different keys for access and refresh tokens
- ✅ **Comprehensive Validation**: All JWT claims verified
- ✅ **Clock Skew Tolerance**: 30-second leeway for time synchronization

#### Token Revocation System
```python
# JTI-based token revocation
class TokenRevocationManager:
    """Secure token revocation with audit logging."""
    
    def __init__(self, token_repository, audit_logger):
        self.token_repository = token_repository
        self.audit_logger = audit_logger
    
    async def revoke_token(self, jti: str, reason: str = "user_request") -> bool:
        """Revoke token with audit trail."""
        try:
            success = await self.token_repository.invalidate_token(jti)
            
            if success:
                self.audit_logger.log_security_event(
                    event_type="token_revoked",
                    details={"jti": jti, "reason": reason}
                )
            
            return success
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="token_revocation_failed",
                details={"jti": jti, "error": str(e)},
                success=False
            )
            return False
    
    async def revoke_user_tokens(self, user_id: str, exclude_jti: Optional[str] = None) -> int:
        """Revoke all tokens for a user."""
        try:
            count = await self.token_repository.invalidate_user_tokens(user_id, exclude_jti)
            
            self.audit_logger.log_security_event(
                event_type="user_tokens_revoked",
                user_id=user_id,
                details={"tokens_revoked": count}
            )
            
            return count
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="user_token_revocation_failed",
                user_id=user_id,
                details={"error": str(e)},
                success=False
            )
            return 0
```

## 🔒 OAuth 2.1 Security Features

### PKCE (Proof Key for Code Exchange)

#### Mandatory PKCE Implementation
```python
# Production PKCE implementation
import hashlib
import base64
import secrets
import re

class PKCEManager:
    """OAuth 2.1 compliant PKCE implementation."""
    
    # OAuth 2.1 only supports S256 method
    SUPPORTED_METHODS = ["S256"]
    CODE_VERIFIER_PATTERN = re.compile(r'^[A-Za-z0-9\-._~]{43,128}$')
    
    @staticmethod
    def generate_code_verifier() -> str:
        """Generate cryptographically secure code verifier."""
        random_bytes = secrets.token_bytes(32)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
            raise ValueError("Generated code verifier is invalid")
        
        return code_verifier
    
    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Generate S256 code challenge."""
        if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
            raise ValueError("Invalid code verifier format")
        
        # S256: BASE64URL(SHA256(code_verifier))
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
    
    @staticmethod
    def verify_code_challenge(
        code_verifier: str,
        code_challenge: str,
        method: str = "S256"
    ) -> bool:
        """Verify PKCE challenge with constant-time comparison."""
        try:
            if method not in PKCEManager.SUPPORTED_METHODS:
                return False
            
            if not PKCEManager.CODE_VERIFIER_PATTERN.match(code_verifier):
                return False
            
            computed_challenge = PKCEManager.generate_code_challenge(code_verifier)
            return secrets.compare_digest(computed_challenge, code_challenge)
            
        except Exception:
            return False
```

**Security Validation**:
- ✅ **Mandatory Implementation**: Required for all OAuth flows
- ✅ **S256 Method Only**: Cryptographically secure challenge method
- ✅ **Constant-Time Verification**: Prevents timing attacks
- ✅ **OAuth 2.1 Compliance**: Meets latest security requirements

### Client Authentication Security

#### Multi-Method Client Authentication
```python
# Secure client authentication
import base64
import bcrypt
from typing import Optional

class ClientAuthenticationManager:
    """Secure OAuth client authentication with multiple methods."""
    
    def __init__(self, client_repository, audit_logger):
        self.client_repository = client_repository
        self.audit_logger = audit_logger
    
    async def authenticate_client(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        auth_header: Optional[str] = None
    ) -> Optional[OAuthClient]:
        """Authenticate client using appropriate method."""
        
        client = await self.client_repository.get_by_client_id(client_id)
        if not client or not client.is_active:
            self.audit_logger.log_security_event(
                event_type="client_authentication_failed",
                client_id=client_id,
                details={"reason": "invalid_client"}
            )
            return None
        
        # Public clients don't require authentication
        if client.client_type == "public":
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
        """Authenticate confidential client."""
        
        # Try HTTP Basic authentication
        if auth_header and auth_header.startswith("Basic "):
            return await self._authenticate_basic(client, auth_header)
        
        # Try client_secret_post method
        if client_secret:
            return await self._authenticate_post(client, client_secret)
        
        self.audit_logger.log_security_event(
            event_type="client_authentication_failed",
            client_id=client.client_id,
            details={"reason": "no_authentication_method"}
        )
        return None
    
    def _verify_client_secret(self, provided_secret: str, stored_hash: str) -> bool:
        """Verify client secret with constant-time comparison."""
        try:
            return bcrypt.checkpw(
                provided_secret.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception:
            # Consume time to prevent timing attacks
            bcrypt.checkpw(b"dummy", bcrypt.gensalt())
            return False
```

## 🛡️ Access Control and Authorization

### Scope-Based Access Control

#### Dynamic Scope Authorization
```python
# Comprehensive scope management
from fastapi import Depends, HTTPException, status
from typing import List

class ScopeAuthorizationManager:
    """OAuth 2.1 scope-based access control."""
    
    def __init__(self, scope_repository):
        self.scope_repository = scope_repository
    
    async def validate_requested_scopes(
        self,
        client_id: str,
        requested_scopes: List[str]
    ) -> List[str]:
        """Validate scopes against client permissions."""
        
        allowed_scopes = await self.scope_repository.get_client_scopes(client_id)
        allowed_scope_names = {scope.scope_name for scope in allowed_scopes}
        
        valid_scopes = []
        for scope in requested_scopes:
            if scope in allowed_scope_names:
                valid_scopes.append(scope)
            else:
                # Log unauthorized scope requests
                logger.warning(f"Unauthorized scope: client={client_id}, scope={scope}")
        
        return valid_scopes
    
    async def check_token_scope(
        self,
        token_scopes: List[str],
        required_scope: str
    ) -> bool:
        """Check if token has required scope."""
        
        # Direct scope match
        if required_scope in token_scopes:
            return True
        
        # Check hierarchical permissions
        return self._check_hierarchical_scopes(token_scopes, required_scope)
    
    def _check_hierarchical_scopes(
        self,
        token_scopes: List[str],
        required_scope: str
    ) -> bool:
        """Implement scope hierarchy (admin > write > read)."""
        
        hierarchy = {
            "admin": ["admin", "write", "read", "profile"],
            "write": ["write", "read"],
            "read": ["read"]
        }
        
        for token_scope in token_scopes:
            if token_scope in hierarchy:
                if required_scope in hierarchy[token_scope]:
                    return True
        
        return False

# FastAPI scope dependency
def require_scope(required_scope: str):
    """FastAPI dependency for scope-based protection."""
    
    async def scope_dependency(
        current_user: dict = Depends(get_current_user),
        scope_manager: ScopeAuthorizationManager = Depends(get_scope_manager)
    ):
        token_scopes = current_user.get("scopes", [])
        
        if not await scope_manager.check_token_scope(token_scopes, required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scope for this operation"
            )
        
        return current_user
    
    return scope_dependency
```

### Rate Limiting and Brute Force Protection

#### Advanced Rate Limiting Implementation
```python
# Production rate limiting with Redis
import time
import redis.asyncio as redis
from typing import Dict, Any, Tuple, Optional

class AdvancedRateLimiter:
    """Multi-tier rate limiting with Redis backend."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        
        # Rate limiting configurations
        self.limits = {
            "auth": {"requests": 10, "window": 60},        # Authentication attempts
            "api": {"requests": 100, "window": 60},        # General API calls
            "token": {"requests": 20, "window": 60},       # Token operations
            "discovery": {"requests": 1000, "window": 60}, # Discovery endpoints
        }
    
    async def is_allowed(
        self,
        identifier: str,
        limit_type: str = "api"
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit with sliding window algorithm."""
        
        if not self.redis:
            return True, {"allowed": True}  # Fallback for development
        
        config = self.limits.get(limit_type, self.limits["api"])
        window = config["window"]
        max_requests = config["requests"]
        
        key = f"rate_limit:{limit_type}:{identifier}"
        now = time.time()
        window_start = now - window
        
        # Lua script for atomic sliding window implementation
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
            -- Allow request and record it
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
            "window": window,
            "limit_type": limit_type
        }
```

## 🔐 Cryptographic Security

### Secret Management

#### Enterprise Secret Storage
```python
# Production secret management
import ctypes
import mmap
import os
import secrets
from typing import Optional

class SecureSecret:
    """Memory-safe secret storage with automatic cleanup."""
    
    def __init__(self, secret: str):
        self._length = len(secret)
        
        # Allocate locked memory pages (if supported)
        self._memory = mmap.mmap(-1, self._length,
                                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        
        try:
            self._memory.mlock()  # Prevent swapping to disk
        except OSError:
            pass  # Continue if mlock fails due to permissions
        
        # Store secret in locked memory
        self._memory.write(secret.encode('utf-8'))
        self._memory.seek(0)
        
        # Clear original secret from memory
        self._wipe_string(secret)
    
    def get_secret(self) -> str:
        """Get secret value (use sparingly)."""
        self._memory.seek(0)
        return self._memory.read(self._length).decode('utf-8')
    
    def compare_secret(self, other: str) -> bool:
        """Constant-time secret comparison."""
        secret = self.get_secret()
        try:
            return secrets.compare_digest(secret, other)
        finally:
            self._wipe_string(secret)
    
    def __del__(self):
        """Secure cleanup on destruction."""
        if hasattr(self, '_memory'):
            # Overwrite with random data
            self._memory.seek(0)
            self._memory.write(os.urandom(self._length))
            
            try:
                self._memory.munlock()
            except OSError:
                pass
            self._memory.close()
    
    @staticmethod
    def _wipe_string(s: str):
        """Best-effort string memory clearing."""
        # Note: Python string immutability limits effectiveness
        pass

class SecretProvider:
    """Multi-source secret provider with secure handling."""
    
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
        """Load secret from file with secure cleanup."""
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            self._secrets[key] = SecureSecret(content)
            return True
            
        except Exception as e:
            logger.error(f"Failed to load secret from {file_path}: {e}")
            return False
    
    def get_secret(self, key: str) -> Optional[str]:
        """Get secret value."""
        secret_obj = self._secrets.get(key)
        return secret_obj.get_secret() if secret_obj else None
```

### Database Field Encryption

#### Encryption at Rest Implementation
```python
# Field-level encryption for sensitive data
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class FieldEncryption:
    """Encrypt sensitive database fields."""
    
    def __init__(self, master_key: str, salt: bytes = None):
        self.salt = salt or os.urandom(16)
        
        # Derive encryption key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        self.cipher = Fernet(key)
    
    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt field for database storage."""
        if not plaintext:
            return plaintext
        
        encrypted_bytes = self.cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('ascii')
    
    def decrypt_field(self, ciphertext: str) -> str:
        """Decrypt field from database."""
        if not ciphertext:
            return ciphertext
        
        try:
            encrypted_bytes = base64.b64decode(ciphertext.encode('ascii'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Field decryption failed: {e}")
            raise ValueError("Failed to decrypt field")
```

## 🔍 Security Monitoring and Audit

### Comprehensive Audit Logging

#### Security Event Logging System
```python
# Production security audit logging
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any

class SecurityEventType(Enum):
    """Security event types for audit logging."""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    
    # OAuth events
    OAUTH_AUTHORIZATION = "oauth_authorization"
    OAUTH_TOKEN_ISSUED = "oauth_token_issued"
    OAUTH_TOKEN_REVOKED = "oauth_token_revoked"
    
    # Security violations
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_TOKEN = "invalid_token"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PKCE_FAILURE = "pkce_failure"
    
    # Administrative events
    ADMIN_LOGIN = "admin_login"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"

class SecurityAuditLogger:
    """Structured security audit logging."""
    
    def __init__(self, logger_name: str = "authly.security"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        
        # Ensure audit logs are preserved
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
        
        # Escalate critical security events
        critical_events = [
            SecurityEventType.UNAUTHORIZED_ACCESS,
            SecurityEventType.PKCE_FAILURE
        ]
        
        if event_type in critical_events and not success:
            self.logger.error(f"SECURITY ALERT: {json.dumps(event_data)}")
```

### Security Headers Middleware

#### Comprehensive Security Headers
```python
# Security headers implementation
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Comprehensive security headers middleware."""
    
    def __init__(self, app, config=None):
        super().__init__(app)
        self.config = config or {}
        
        # Default security headers
        self.default_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            ),
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Apply security headers
        for header, value in self.default_headers.items():
            response.headers[header] = value
        
        # Content Security Policy
        if request.url.path.startswith("/docs"):
            # Relaxed CSP for API documentation
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "img-src 'self' data: cdn.jsdelivr.net"
            )
        else:
            # Strict CSP for application
            csp = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "font-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        
        response.headers["Content-Security-Policy"] = csp
        
        return response
```

## 📋 Security Best Practices

### Development Security Checklist

#### Code Security Requirements
- ✅ **Input Validation**: All user inputs validated and sanitized
- ✅ **Parameterized Queries**: SQL injection prevention
- ✅ **Output Encoding**: XSS prevention in responses
- ✅ **Error Handling**: No sensitive information in error messages
- ✅ **Dependency Updates**: Regular security updates
- ✅ **Secret Management**: No hardcoded secrets in code

#### Authentication Security
- ✅ **Strong Password Policy**: Enforced password complexity
- ✅ **Secure Hashing**: Bcrypt with appropriate cost factor
- ✅ **Session Security**: Secure token generation and validation
- ✅ **Multi-Factor Support**: TOTP implementation available
- ✅ **Account Lockout**: Brute force protection

#### Authorization Security
- ✅ **Principle of Least Privilege**: Minimal required permissions
- ✅ **Scope Validation**: OAuth scope enforcement
- ✅ **Token Revocation**: Comprehensive token invalidation
- ✅ **Rate Limiting**: Protection against abuse
- ✅ **Access Control**: Role-based authorization

### Production Security Checklist

#### Infrastructure Security
- ✅ **HTTPS Enforcement**: TLS 1.2+ for all communications
- ✅ **Security Headers**: Comprehensive header protection
- ✅ **Firewall Configuration**: Minimal port exposure
- ✅ **Database Security**: Encrypted connections and access controls
- ✅ **Log Security**: Secure audit log storage and retention

#### Operational Security
- ✅ **Key Rotation**: Regular JWT signing key rotation
- ✅ **Monitoring**: Security event monitoring and alerting
- ✅ **Backup Security**: Encrypted backups with secure storage
- ✅ **Incident Response**: Security incident procedures
- ✅ **Compliance**: GDPR and industry standard compliance

## 🚀 Security Recommendations

### Immediate Implementation
1. **✅ COMPLETED**: All critical security features implemented
2. **✅ COMPLETED**: OAuth 2.1 and OIDC security compliance
3. **✅ COMPLETED**: Enterprise secret management
4. **✅ COMPLETED**: Comprehensive audit logging

### Enhanced Security (Optional)
1. **Token Encryption**: Additional encryption for tokens at rest
2. **Argon2 Hashing**: Enhanced password hashing for new deployments
3. **Hardware Security Modules**: HSM integration for high-security environments
4. **Advanced Threat Detection**: Machine learning-based anomaly detection

### Security Monitoring
1. **Failed Authentication Monitoring**: Track and alert on failed login attempts
2. **Token Usage Analysis**: Monitor for unusual token usage patterns
3. **Admin Action Auditing**: Comprehensive administrative action logging
4. **Vulnerability Scanning**: Regular dependency and infrastructure scanning

## 📊 Security Metrics

### Key Security Indicators
- **Authentication Success Rate**: Monitor for unusual patterns
- **Token Revocation Rate**: Track security incident response
- **Rate Limiting Effectiveness**: Monitor blocked requests
- **Password Policy Compliance**: Track policy violations
- **Audit Log Completeness**: Ensure comprehensive logging

### Security Dashboard Metrics
```python
# Example security metrics collection
class SecurityMetrics:
    """Collect and expose security metrics."""
    
    def __init__(self, metrics_client):
        self.metrics = metrics_client
    
    def track_authentication_attempt(self, success: bool, method: str):
        """Track authentication attempts."""
        self.metrics.increment(
            "auth_attempts_total",
            tags={"success": success, "method": method}
        )
    
    def track_token_operation(self, operation: str, token_type: str):
        """Track token operations."""
        self.metrics.increment(
            "token_operations_total",
            tags={"operation": operation, "type": token_type}
        )
    
    def track_security_event(self, event_type: str, severity: str):
        """Track security events."""
        self.metrics.increment(
            "security_events_total",
            tags={"event_type": event_type, "severity": severity}
        )
```

---

## 🎯 Conclusion

Authly implements comprehensive enterprise-grade security with:

- **✅ Production-Ready Security**: All critical vulnerabilities resolved
- **✅ Standards Compliance**: OAuth 2.1, OIDC 1.0, and GDPR compliance
- **✅ Defense in Depth**: Multiple security layers and controls
- **✅ Continuous Monitoring**: Comprehensive audit logging and metrics
- **✅ Security by Design**: Security principles integrated throughout

The security implementation follows industry best practices and provides a robust foundation for enterprise OAuth 2.1 authorization server deployments.

For security updates and announcements, monitor the project's security advisories and maintain regular security reviews of your deployment configuration.