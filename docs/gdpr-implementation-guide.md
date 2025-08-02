# GDPR Implementation Guide for Authly

This guide provides practical implementation steps and code examples for achieving GDPR compliance in your Authly deployment.

## Table of Contents

1. [Quick Start Checklist](#quick-start-checklist)
2. [User Rights Implementation](#user-rights-implementation)
3. [Consent Management](#consent-management)
4. [Data Retention Automation](#data-retention-automation)
5. [Audit Logging](#audit-logging)
6. [Security Enhancements](#security-enhancements)
7. [Privacy Dashboard](#privacy-dashboard)
8. [Testing Compliance](#testing-compliance)

## Quick Start Checklist

### Immediate Actions (Week 1)
- [ ] Update privacy policy with GDPR-compliant template
- [ ] Add consent checkboxes to registration
- [ ] Implement cookie banner
- [ ] Create privacy@domain email address
- [ ] Set up data retention schedules

### Short-term Actions (Month 1)
- [ ] Implement data export API
- [ ] Add account deletion workflow
- [ ] Create consent management system
- [ ] Set up audit logging
- [ ] Train team on GDPR requirements

### Medium-term Actions (Quarter 1)
- [ ] Build privacy dashboard
- [ ] Automate data retention
- [ ] Conduct privacy impact assessment
- [ ] Implement right to be forgotten
- [ ] Create vendor assessment process

## User Rights Implementation

### 1. Right to Access - Data Export API

Create a new file `src/authly/api/privacy_router.py`:

```python
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from authly.api.users_dependencies import get_current_user
from authly.users import UserModel, UserRepository
from authly.tokens import TokenRepository
from authly.oauth.client_repository import ClientRepository
from authly.core.dependencies import get_database_connection

router = APIRouter(prefix="/api/v1/privacy", tags=["privacy"])


class DataExportFormat(BaseModel):
    format: str = "json"  # json, csv


class UserDataExport(BaseModel):
    """Complete user data export schema"""
    export_date: datetime
    export_version: str = "1.0"
    user_data: dict
    authentication_data: dict
    authorization_data: dict
    activity_data: dict
    consent_records: list


@router.post("/export", response_model=UserDataExport)
async def export_user_data(
    format_request: DataExportFormat,
    current_user: UserModel = Depends(get_current_user),
    db_connection=Depends(get_database_connection)
):
    """
    Export all user data in machine-readable format.
    Implements GDPR Article 15 - Right to Access.
    """
    user_repo = UserRepository(db_connection)
    token_repo = TokenRepository(db_connection)
    client_repo = ClientRepository(db_connection)
    
    # Gather all user data
    user_data = {
        "account": {
            "user_id": str(current_user.id),
            "username": current_user.username,
            "email": current_user.email,
            "created_at": current_user.created_at.isoformat(),
            "updated_at": current_user.updated_at.isoformat() if current_user.updated_at else None,
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
            "is_active": current_user.is_active,
            "is_verified": current_user.is_verified,
            "is_superuser": current_user.is_superuser,
            "requires_password_change": current_user.requires_password_change
        },
        "profile": {
            "full_name": current_user.full_name,
            "phone_number": current_user.phone_number,
            "locale": current_user.locale,
            "picture": current_user.picture
        }
    }
    
    # Get authentication data
    tokens = await token_repo.get_user_tokens(current_user.id)
    authentication_data = {
        "active_sessions": len(tokens),
        "tokens": [
            {
                "jti": token.jti,
                "token_type": token.token_type,
                "created_at": token.created_at.isoformat(),
                "expires_at": token.expires_at.isoformat(),
                "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None,
                "is_active": token.is_active
            } for token in tokens
        ]
    }
    
    # Get authorized clients
    # This would need a method to get user's authorized clients
    authorization_data = {
        "authorized_applications": [],  # TODO: Implement authorized clients lookup
        "granted_scopes": []
    }
    
    # Get activity data (last 90 days)
    activity_data = {
        "recent_logins": [],  # TODO: Implement login history
        "security_events": []  # TODO: Implement security event lookup
    }
    
    # Get consent records
    consent_records = []  # TODO: Implement consent record lookup
    
    export = UserDataExport(
        export_date=datetime.utcnow(),
        user_data=user_data,
        authentication_data=authentication_data,
        authorization_data=authorization_data,
        activity_data=activity_data,
        consent_records=consent_records
    )
    
    if format_request.format == "json":
        return JSONResponse(
            content=export.dict(),
            headers={
                "Content-Disposition": f"attachment; filename=user_data_{current_user.id}_{datetime.utcnow().date()}.json"
            }
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported export format")


@router.get("/export/status")
async def check_export_status(
    current_user: UserModel = Depends(get_current_user)
):
    """Check if user has any pending data export requests"""
    return {
        "has_pending_export": False,
        "last_export": None,
        "export_available_until": None
    }
```

### 2. Right to Erasure - Account Deletion

Add to `privacy_router.py`:

```python
class AccountDeletionRequest(BaseModel):
    password: str  # Require password confirmation
    reason: Optional[str] = None
    feedback: Optional[str] = None
    confirm_deletion: bool = False


class DeletionResult(BaseModel):
    deletion_id: str
    status: str
    deleted_data: dict
    retained_data: dict
    retention_reason: Optional[str] = None


@router.post("/delete-account", response_model=DeletionResult)
async def delete_user_account(
    deletion_request: AccountDeletionRequest,
    current_user: UserModel = Depends(get_current_user),
    db_connection=Depends(get_database_connection)
):
    """
    Delete user account and all associated data.
    Implements GDPR Article 17 - Right to Erasure.
    """
    from authly.auth import verify_password
    
    # Verify password
    if not verify_password(deletion_request.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Require explicit confirmation
    if not deletion_request.confirm_deletion:
        raise HTTPException(
            status_code=400, 
            detail="Deletion not confirmed. Set confirm_deletion to true."
        )
    
    user_repo = UserRepository(db_connection)
    token_repo = TokenRepository(db_connection)
    
    deletion_id = f"del_{current_user.id}_{datetime.utcnow().timestamp()}"
    
    # Start transaction
    async with db_connection.transaction():
        # 1. Revoke all tokens
        tokens = await token_repo.get_user_tokens(current_user.id)
        for token in tokens:
            await token_repo.revoke_token(token.jti)
        
        # 2. Anonymize audit logs (keep for legal compliance)
        # Replace user_id with hash for audit trail
        anon_user_id = f"deleted_user_{hash(str(current_user.id))}"
        
        # 3. Delete user data
        deleted_data = {
            "tokens_revoked": len(tokens),
            "profile_deleted": True,
            "account_deleted": True
        }
        
        # 4. Check for data retention requirements
        retained_data = {}
        retention_reason = None
        
        # Example: Check if user has recent transactions that must be kept
        # if await has_recent_financial_transactions(current_user.id):
        #     retained_data["financial_records"] = "Retained for tax compliance (7 years)"
        #     retention_reason = "Legal requirement - tax records"
        
        # 5. Delete or anonymize user record
        if retained_data:
            # Anonymize instead of delete
            await user_repo.update(current_user.id, {
                "username": f"deleted_{deletion_id}",
                "email": f"deleted_{deletion_id}@deleted.local",
                "password_hash": "DELETED",
                "full_name": None,
                "phone_number": None,
                "picture": None,
                "is_active": False,
                "deleted_at": datetime.utcnow()
            })
        else:
            # Full deletion
            await user_repo.delete(current_user.id)
        
        # 6. Log the deletion event
        await log_deletion_event(deletion_id, current_user.id, deletion_request.reason)
    
    # 7. Send confirmation email (to a different email if provided)
    # await send_deletion_confirmation(current_user.email)
    
    return DeletionResult(
        deletion_id=deletion_id,
        status="completed",
        deleted_data=deleted_data,
        retained_data=retained_data,
        retention_reason=retention_reason
    )


@router.post("/request-deletion")
async def request_account_deletion(
    current_user: UserModel = Depends(get_current_user)
):
    """
    Initiate account deletion process with a 30-day grace period.
    User can cancel deletion during this period.
    """
    # TODO: Implement delayed deletion with cancellation option
    return {
        "deletion_scheduled": datetime.utcnow() + timedelta(days=30),
        "cancellation_token": "...",
        "message": "Your account is scheduled for deletion in 30 days. You can cancel anytime before then."
    }
```

### 3. Right to Rectification - Update Personal Data

Add to `privacy_router.py`:

```python
from pydantic import EmailStr, validator

class PersonalDataUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    locale: Optional[str] = None
    
    @validator('full_name')
    def validate_name(cls, v):
        if v and len(v) > 100:
            raise ValueError('Name too long')
        return v
    
    @validator('locale')
    def validate_locale(cls, v):
        valid_locales = ['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko', 'zh']
        if v and v not in valid_locales:
            raise ValueError(f'Invalid locale. Must be one of: {valid_locales}')
        return v


@router.patch("/personal-data", response_model=UserModel)
async def update_personal_data(
    updates: PersonalDataUpdate,
    current_user: UserModel = Depends(get_current_user),
    db_connection=Depends(get_database_connection)
):
    """
    Update user's personal data.
    Implements GDPR Article 16 - Right to Rectification.
    """
    user_repo = UserRepository(db_connection)
    
    # Prepare update dict with only provided fields
    update_data = updates.dict(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    # Add audit metadata
    update_data["updated_at"] = datetime.utcnow()
    
    # Update user
    updated_user = await user_repo.update(current_user.id, update_data)
    
    # Log the update
    await log_privacy_event(
        event_type="personal_data_update",
        user_id=current_user.id,
        updated_fields=list(update_data.keys()),
        ip_address=None  # Get from request context
    )
    
    return updated_user
```

### 4. Right to Data Portability

Add to `privacy_router.py`:

```python
import csv
import io
from typing import List


class PortabilityFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    XML = "xml"


@router.get("/portability")
async def export_portable_data(
    format: PortabilityFormat = PortabilityFormat.JSON,
    current_user: UserModel = Depends(get_current_user),
    db_connection=Depends(get_database_connection)
):
    """
    Export user data in standard, portable format.
    Implements GDPR Article 20 - Right to Data Portability.
    """
    # Collect portable data (data provided by user or generated through use)
    portable_data = {
        "profile": {
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "phone_number": current_user.phone_number,
            "locale": current_user.locale,
            "created_at": current_user.created_at.isoformat()
        },
        "preferences": {
            # User preferences
        },
        "authorized_applications": [
            # OAuth authorizations
        ]
    }
    
    if format == PortabilityFormat.JSON:
        return JSONResponse(
            content={
                "format_version": "1.0",
                "export_date": datetime.utcnow().isoformat(),
                "data": portable_data
            },
            headers={
                "Content-Disposition": f"attachment; filename=portable_data_{current_user.id}.json"
            }
        )
    
    elif format == PortabilityFormat.CSV:
        # Flatten data for CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(["Category", "Field", "Value"])
        
        # Write data
        for category, fields in portable_data.items():
            for field, value in fields.items():
                writer.writerow([category, field, str(value)])
        
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=portable_data_{current_user.id}.csv"
            }
        )
    
    else:
        raise HTTPException(status_code=400, detail="Format not yet supported")
```

## Consent Management

Create `src/authly/consent/models.py`:

```python
from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ConsentPurpose(str, Enum):
    AUTHENTICATION = "authentication"
    PROFILING = "profiling"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    THIRD_PARTY_SHARING = "third_party_sharing"


class ConsentStatus(str, Enum):
    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


class ConsentRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    purpose: ConsentPurpose
    status: ConsentStatus
    version: str  # Version of privacy policy/terms
    granted_at: datetime
    withdrawn_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    class Config:
        orm_mode = True


class ConsentRequest(BaseModel):
    purpose: ConsentPurpose
    granted: bool
    version: str = "1.0"
```

Create `src/authly/consent/service.py`:

```python
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from authly.consent.models import ConsentPurpose, ConsentRecord, ConsentStatus
from authly.consent.repository import ConsentRepository


class ConsentService:
    def __init__(self, consent_repo: ConsentRepository):
        self.consent_repo = consent_repo
    
    async def record_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        version: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ConsentRecord:
        """Record user consent for a specific purpose"""
        
        # Check if there's an existing consent for this purpose
        existing = await self.consent_repo.get_active_consent(user_id, purpose)
        
        if existing:
            # Withdraw the old consent
            existing.status = ConsentStatus.WITHDRAWN
            existing.withdrawn_at = datetime.utcnow()
            await self.consent_repo.update(existing)
        
        # Create new consent record
        consent = ConsentRecord(
            user_id=user_id,
            purpose=purpose,
            status=ConsentStatus.GRANTED,
            version=version,
            granted_at=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return await self.consent_repo.create(consent)
    
    async def withdraw_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose
    ) -> Optional[ConsentRecord]:
        """Withdraw consent for a specific purpose"""
        
        consent = await self.consent_repo.get_active_consent(user_id, purpose)
        
        if not consent:
            return None
        
        consent.status = ConsentStatus.WITHDRAWN
        consent.withdrawn_at = datetime.utcnow()
        
        return await self.consent_repo.update(consent)
    
    async def get_user_consents(self, user_id: UUID) -> List[ConsentRecord]:
        """Get all consent records for a user"""
        return await self.consent_repo.get_user_consents(user_id)
    
    async def has_valid_consent(
        self,
        user_id: UUID,
        purpose: ConsentPurpose,
        required_version: Optional[str] = None
    ) -> bool:
        """Check if user has valid consent for a purpose"""
        
        consent = await self.consent_repo.get_active_consent(user_id, purpose)
        
        if not consent:
            return False
        
        if consent.status != ConsentStatus.GRANTED:
            return False
        
        if consent.expires_at and consent.expires_at < datetime.utcnow():
            return False
        
        if required_version and consent.version != required_version:
            return False
        
        return True
```

## Data Retention Automation

Create `src/authly/retention/policy.py`:

```python
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Optional

from authly.core.dependencies import get_database_connection


class RetentionPolicy(ABC):
    """Base class for data retention policies"""
    
    @abstractmethod
    def get_retention_period(self) -> Optional[timedelta]:
        """Return the retention period for this data type"""
        pass
    
    @abstractmethod
    async def apply_retention(self, cutoff_date: datetime) -> Dict[str, int]:
        """Apply retention policy and return deletion stats"""
        pass


class TokenRetentionPolicy(RetentionPolicy):
    """Retention policy for OAuth tokens"""
    
    def get_retention_period(self) -> timedelta:
        return timedelta(days=90)  # Keep tokens for 90 days after expiration
    
    async def apply_retention(self, cutoff_date: datetime) -> Dict[str, int]:
        from authly.tokens.repository import TokenRepository
        
        db = await get_database_connection()
        token_repo = TokenRepository(db)
        
        # Delete expired tokens older than cutoff
        deleted = await token_repo.delete_expired_before(cutoff_date)
        
        return {
            "expired_tokens_deleted": deleted
        }


class LoginHistoryRetentionPolicy(RetentionPolicy):
    """Retention policy for login history"""
    
    def get_retention_period(self) -> timedelta:
        return timedelta(days=365)  # Keep login history for 1 year
    
    async def apply_retention(self, cutoff_date: datetime) -> Dict[str, int]:
        # TODO: Implement login history deletion
        return {
            "login_records_deleted": 0
        }


class AuditLogRetentionPolicy(RetentionPolicy):
    """Retention policy for audit logs"""
    
    def get_retention_period(self) -> timedelta:
        return timedelta(days=2555)  # Keep audit logs for 7 years
    
    async def apply_retention(self, cutoff_date: datetime) -> Dict[str, int]:
        # Audit logs are typically kept for compliance
        # May need to archive instead of delete
        return {
            "audit_logs_archived": 0
        }
```

Create `src/authly/retention/scheduler.py`:

```python
import asyncio
import logging
from datetime import datetime
from typing import List

from authly.retention.policy import RetentionPolicy


logger = logging.getLogger(__name__)


class RetentionScheduler:
    """Manages automated data retention tasks"""
    
    def __init__(self, policies: List[RetentionPolicy]):
        self.policies = policies
        self.running = False
    
    async def run_retention_cycle(self):
        """Run one cycle of retention policies"""
        
        logger.info("Starting data retention cycle")
        total_stats = {}
        
        for policy in self.policies:
            try:
                retention_period = policy.get_retention_period()
                
                if retention_period:
                    cutoff_date = datetime.utcnow() - retention_period
                    stats = await policy.apply_retention(cutoff_date)
                    
                    # Merge stats
                    for key, value in stats.items():
                        total_stats[key] = total_stats.get(key, 0) + value
                    
                    logger.info(f"Applied {policy.__class__.__name__}: {stats}")
                
            except Exception as e:
                logger.error(f"Error applying retention policy {policy.__class__.__name__}: {e}")
        
        logger.info(f"Retention cycle completed. Total: {total_stats}")
        return total_stats
    
    async def start(self, interval_hours: int = 24):
        """Start the retention scheduler"""
        
        self.running = True
        
        while self.running:
            try:
                await self.run_retention_cycle()
            except Exception as e:
                logger.error(f"Error in retention scheduler: {e}")
            
            # Wait for next cycle
            await asyncio.sleep(interval_hours * 3600)
    
    def stop(self):
        """Stop the retention scheduler"""
        self.running = False
```

## Audit Logging

Create `src/authly/audit/models.py`:

```python
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    # Authentication events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"
    
    # Account events
    USER_REGISTERED = "user_registered"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    
    # Privacy events
    DATA_EXPORTED = "data_exported"
    DATA_DELETED = "data_deleted"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_WITHDRAWN = "consent_withdrawn"
    
    # Admin events
    ADMIN_ACCESS = "admin_access"
    ADMIN_ACTION = "admin_action"
    
    # Security events
    SECURITY_ALERT = "security_alert"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class AuditEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: AuditEventType
    user_id: Optional[UUID] = None
    actor_id: Optional[UUID] = None  # Who performed the action
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    result: str = "success"  # success, failure, error
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        orm_mode = True
```

Create `src/authly/audit/service.py`:

```python
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from authly.audit.models import AuditEvent, AuditEventType
from authly.audit.repository import AuditRepository


logger = logging.getLogger(__name__)


class AuditService:
    """Service for audit logging with GDPR compliance"""
    
    def __init__(self, audit_repo: AuditRepository):
        self.audit_repo = audit_repo
    
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[UUID] = None,
        actor_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        result: str = "success",
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Log an audit event"""
        
        # Sanitize metadata to remove sensitive data
        safe_metadata = self._sanitize_metadata(metadata or {})
        
        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            actor_id=actor_id,
            ip_address=self._anonymize_ip(ip_address) if ip_address else None,
            user_agent=user_agent[:200] if user_agent else None,  # Truncate
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            metadata=safe_metadata
        )
        
        # Log to application logger as well
        logger.info(
            f"Audit Event: {event_type} | "
            f"User: {user_id} | "
            f"Result: {result} | "
            f"IP: {event.ip_address}"
        )
        
        return await self.audit_repo.create(event)
    
    async def log_authentication(
        self,
        user_id: UUID,
        success: bool,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log authentication attempt"""
        
        event_type = AuditEventType.USER_LOGIN if success else AuditEventType.LOGIN_FAILED
        
        await self.log_event(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=f"login_via_{method}",
            result="success" if success else "failure",
            metadata={"method": method}
        )
    
    async def log_privacy_action(
        self,
        action: str,
        user_id: UUID,
        actor_id: Optional[UUID] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log privacy-related actions"""
        
        event_type_map = {
            "export": AuditEventType.DATA_EXPORTED,
            "delete": AuditEventType.DATA_DELETED,
            "consent_grant": AuditEventType.CONSENT_GRANTED,
            "consent_withdraw": AuditEventType.CONSENT_WITHDRAWN
        }
        
        event_type = event_type_map.get(action, AuditEventType.USER_UPDATED)
        
        await self.log_event(
            event_type=event_type,
            user_id=user_id,
            actor_id=actor_id or user_id,
            action=action,
            metadata=details or {}
        )
    
    async def get_user_audit_trail(
        self,
        user_id: UUID,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEvent]:
        """Get audit trail for a specific user"""
        
        return await self.audit_repo.get_by_user(
            user_id=user_id,
            limit=limit,
            offset=offset
        )
    
    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from metadata"""
        
        sensitive_keys = {
            "password", "token", "secret", "key", "authorization",
            "credit_card", "ssn", "pin"
        }
        
        sanitized = {}
        
        for key, value in metadata.items():
            # Check if key contains sensitive words
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_metadata(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address for privacy"""
        
        if "." in ip_address:  # IPv4
            parts = ip_address.split(".")
            parts[-1] = "0"  # Zero out last octet
            return ".".join(parts)
        elif ":" in ip_address:  # IPv6
            parts = ip_address.split(":")
            # Zero out last 64 bits
            return ":".join(parts[:4] + ["0"] * 4)
        
        return ip_address
```

## Security Enhancements

### Enhanced Password Policy

Create `src/authly/security/password_policy.py`:

```python
import re
from typing import List, Tuple

from pydantic import BaseModel


class PasswordPolicyConfig(BaseModel):
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    prevent_common_passwords: bool = True
    prevent_user_info: bool = True
    max_length: int = 128


class PasswordPolicyValidator:
    def __init__(self, config: PasswordPolicyConfig):
        self.config = config
        self._load_common_passwords()
    
    def _load_common_passwords(self):
        """Load list of common passwords to block"""
        # In production, load from file or database
        self.common_passwords = {
            "password", "12345678", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome",
            "monkey", "dragon", "baseball", "football"
        }
    
    def validate(
        self, 
        password: str, 
        username: Optional[str] = None,
        email: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate password against policy.
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        # Length check
        if len(password) < self.config.min_length:
            errors.append(f"Password must be at least {self.config.min_length} characters")
        
        if len(password) > self.config.max_length:
            errors.append(f"Password must not exceed {self.config.max_length} characters")
        
        # Character requirements
        if self.config.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.config.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.config.require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if self.config.require_special:
            special_pattern = f"[{re.escape(self.config.special_chars)}]"
            if not re.search(special_pattern, password):
                errors.append("Password must contain at least one special character")
        
        # Common password check
        if self.config.prevent_common_passwords:
            if password.lower() in self.common_passwords:
                errors.append("Password is too common. Please choose a more unique password")
        
        # User info check
        if self.config.prevent_user_info:
            password_lower = password.lower()
            
            if username and username.lower() in password_lower:
                errors.append("Password must not contain your username")
            
            if email:
                email_parts = email.lower().split('@')[0].split('.')
                for part in email_parts:
                    if len(part) > 3 and part in password_lower:
                        errors.append("Password must not contain parts of your email")
        
        return len(errors) == 0, errors
    
    def generate_policy_description(self) -> str:
        """Generate human-readable policy description"""
        
        requirements = [
            f"At least {self.config.min_length} characters long",
            f"Maximum {self.config.max_length} characters"
        ]
        
        if self.config.require_uppercase:
            requirements.append("At least one uppercase letter (A-Z)")
        
        if self.config.require_lowercase:
            requirements.append("At least one lowercase letter (a-z)")
        
        if self.config.require_digits:
            requirements.append("At least one number (0-9)")
        
        if self.config.require_special:
            requirements.append(f"At least one special character ({self.config.special_chars})")
        
        if self.config.prevent_common_passwords:
            requirements.append("Not a commonly used password")
        
        if self.config.prevent_user_info:
            requirements.append("Not contain your username or email")
        
        return "Password must be:\n" + "\n".join(f"• {req}" for req in requirements)
```

## Privacy Dashboard

Create `src/authly/api/privacy_dashboard.py`:

```python
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from authly.api.users_dependencies import get_current_user
from authly.users import UserModel
from authly.consent.service import ConsentService
from authly.audit.service import AuditService


router = APIRouter(prefix="/api/v1/privacy/dashboard", tags=["privacy-dashboard"])


class PrivacyDashboardData(BaseModel):
    """Complete privacy dashboard data"""
    
    # Account info
    account_created: datetime
    last_login: Optional[datetime]
    data_retention_period: str
    
    # Data categories
    data_collected: List[str]
    data_purposes: List[str]
    
    # Consents
    consents: List[dict]
    
    # Connected apps
    authorized_applications: List[dict]
    
    # Activity
    recent_activity: List[dict]
    
    # Rights
    available_actions: List[str]


@router.get("/", response_model=PrivacyDashboardData)
async def get_privacy_dashboard(
    current_user: UserModel = Depends(get_current_user),
    consent_service: ConsentService = Depends(get_consent_service),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Get comprehensive privacy dashboard for user"""
    
    # Get user's consents
    consents = await consent_service.get_user_consents(current_user.id)
    
    # Get recent activity
    recent_activity = await audit_service.get_user_audit_trail(
        current_user.id,
        limit=10
    )
    
    # TODO: Get authorized applications
    authorized_apps = []
    
    dashboard_data = PrivacyDashboardData(
        account_created=current_user.created_at,
        last_login=current_user.last_login,
        data_retention_period="Until account deletion",
        
        data_collected=[
            "Email address",
            "Username",
            "Password (encrypted)",
            "Login history",
            "IP address (anonymized)",
            "Profile information (optional)"
        ],
        
        data_purposes=[
            "Authentication and authorization",
            "Account security",
            "Service provision",
            "Legal compliance"
        ],
        
        consents=[
            {
                "purpose": c.purpose,
                "status": c.status,
                "granted_at": c.granted_at.isoformat(),
                "version": c.version
            } for c in consents
        ],
        
        authorized_applications=authorized_apps,
        
        recent_activity=[
            {
                "timestamp": event.timestamp.isoformat(),
                "type": event.event_type,
                "description": _describe_event(event)
            } for event in recent_activity
        ],
        
        available_actions=[
            "export_data",
            "update_profile",
            "manage_consents",
            "revoke_applications",
            "delete_account"
        ]
    )
    
    return dashboard_data


def _describe_event(event) -> str:
    """Generate human-readable description of audit event"""
    
    descriptions = {
        "user_login": "You logged in",
        "user_logout": "You logged out",
        "password_changed": "You changed your password",
        "user_updated": "You updated your profile",
        "data_exported": "You exported your data",
        "consent_granted": f"You granted consent for {event.metadata.get('purpose', 'unknown')}",
        "consent_withdrawn": f"You withdrew consent for {event.metadata.get('purpose', 'unknown')}"
    }
    
    return descriptions.get(event.event_type, event.event_type.replace("_", " ").title())
```

## Testing Compliance

Create `tests/test_gdpr_compliance.py`:

```python
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from authly.consent.models import ConsentPurpose, ConsentStatus
from authly.consent.service import ConsentService
from authly.audit.service import AuditService
from authly.security.password_policy import PasswordPolicyValidator, PasswordPolicyConfig


class TestGDPRCompliance:
    """Test suite for GDPR compliance features"""
    
    @pytest.mark.asyncio
    async def test_data_export(self, client, test_user):
        """Test data export functionality"""
        
        response = await client.post(
            "/api/v1/privacy/export",
            json={"format": "json"},
            headers={"Authorization": f"Bearer {test_user.token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify export structure
        assert "export_date" in data
        assert "export_version" in data
        assert "user_data" in data
        assert "authentication_data" in data
        
        # Verify personal data is included
        user_data = data["user_data"]["account"]
        assert user_data["email"] == test_user.email
        assert user_data["username"] == test_user.username
    
    @pytest.mark.asyncio
    async def test_account_deletion(self, client, test_user):
        """Test right to erasure"""
        
        response = await client.post(
            "/api/v1/privacy/delete-account",
            json={
                "password": test_user.password,
                "reason": "no_longer_needed",
                "confirm_deletion": True
            },
            headers={"Authorization": f"Bearer {test_user.token}"}
        )
        
        assert response.status_code == 200
        result = response.json()
        
        assert result["status"] == "completed"
        assert "deletion_id" in result
        
        # Verify user can't login after deletion
        login_response = await client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": test_user.password,
                "grant_type": "password"
            }
        )
        
        assert login_response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_consent_management(self, consent_service: ConsentService):
        """Test consent recording and withdrawal"""
        
        user_id = uuid4()
        
        # Record consent
        consent = await consent_service.record_consent(
            user_id=user_id,
            purpose=ConsentPurpose.MARKETING,
            version="1.0"
        )
        
        assert consent.status == ConsentStatus.GRANTED
        assert consent.purpose == ConsentPurpose.MARKETING
        
        # Check consent validity
        is_valid = await consent_service.has_valid_consent(
            user_id=user_id,
            purpose=ConsentPurpose.MARKETING
        )
        assert is_valid is True
        
        # Withdraw consent
        withdrawn = await consent_service.withdraw_consent(
            user_id=user_id,
            purpose=ConsentPurpose.MARKETING
        )
        
        assert withdrawn.status == ConsentStatus.WITHDRAWN
        assert withdrawn.withdrawn_at is not None
        
        # Check consent is no longer valid
        is_valid = await consent_service.has_valid_consent(
            user_id=user_id,
            purpose=ConsentPurpose.MARKETING
        )
        assert is_valid is False
    
    def test_password_policy(self):
        """Test enhanced password policy"""
        
        config = PasswordPolicyConfig(
            min_length=12,
            require_uppercase=True,
            require_lowercase=True,
            require_digits=True,
            require_special=True
        )
        
        validator = PasswordPolicyValidator(config)
        
        # Test weak passwords
        weak_passwords = [
            ("password", "too common"),
            ("short", "too short"),
            ("alllowercase123!", "no uppercase"),
            ("ALLUPPERCASE123!", "no lowercase"),
            ("NoNumbers!", "no digits"),
            ("NoSpecialChars123", "no special characters")
        ]
        
        for password, reason in weak_passwords:
            is_valid, errors = validator.validate(password)
            assert is_valid is False
            assert len(errors) > 0
        
        # Test strong password
        is_valid, errors = validator.validate("StrongP@ssw0rd123!")
        assert is_valid is True
        assert len(errors) == 0
        
        # Test password with username
        is_valid, errors = validator.validate(
            "MyUsername123!",
            username="myusername"
        )
        assert is_valid is False
        assert any("username" in error for error in errors)
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, audit_service: AuditService):
        """Test audit logging functionality"""
        
        user_id = uuid4()
        
        # Log authentication event
        await audit_service.log_authentication(
            user_id=user_id,
            success=True,
            method="password",
            ip_address="192.168.1.100"
        )
        
        # Log privacy action
        await audit_service.log_privacy_action(
            action="export",
            user_id=user_id,
            details={"format": "json"}
        )
        
        # Get audit trail
        events = await audit_service.get_user_audit_trail(user_id)
        
        assert len(events) == 2
        assert events[0].event_type == "user_login"
        assert events[1].event_type == "data_exported"
        
        # Verify IP anonymization
        assert events[0].ip_address == "192.168.1.0"
```

## Deployment Checklist

### Pre-deployment

```bash
# 1. Update environment variables
cat >> .env << EOF
# GDPR Configuration
GDPR_ENABLED=true
GDPR_CONSENT_VERSION=1.0
GDPR_RETENTION_DAYS=90
GDPR_PRIVACY_EMAIL=privacy@yourdomain.com
GDPR_DPO_EMAIL=dpo@yourdomain.com
EOF

# 2. Run database migrations for GDPR tables
alembic upgrade head

# 3. Initialize consent purposes
python scripts/init_gdpr_consents.py

# 4. Verify privacy endpoints
pytest tests/test_gdpr_compliance.py -v
```

### Post-deployment

1. **Update Privacy Policy**
   - Replace template placeholders
   - Publish to website
   - Email users about updates

2. **Configure Retention Jobs**
   ```python
   # Add to your scheduler or cron
   from authly.retention.scheduler import RetentionScheduler
   from authly.retention.policy import (
       TokenRetentionPolicy,
       LoginHistoryRetentionPolicy,
       AuditLogRetentionPolicy
   )
   
   scheduler = RetentionScheduler([
       TokenRetentionPolicy(),
       LoginHistoryRetentionPolicy(),
       AuditLogRetentionPolicy()
   ])
   
   # Run daily at 2 AM
   await scheduler.start(interval_hours=24)
   ```

3. **Monitor Compliance**
   - Set up alerts for data export requests
   - Monitor deletion requests
   - Track consent changes
   - Review audit logs regularly

4. **Train Your Team**
   - GDPR principles
   - Data subject rights
   - Incident response
   - Privacy by design

## Conclusion

This implementation guide provides a comprehensive foundation for GDPR compliance in Authly. Remember to:

1. Regularly review and update your privacy practices
2. Conduct privacy impact assessments for new features
3. Maintain clear documentation of data processing
4. Respond promptly to data subject requests
5. Keep audit trails of all privacy-related actions

For questions or assistance, contact the Authly team or consult with your data protection officer.