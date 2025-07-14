# Signed URLs with Policy-Based Access Control

**Document Type**: Technical Design Note  
**Status**: Conceptual Design  
**Priority**: Low (Future Enhancement)  
**Created**: 2025-07-11  
**Author**: AI Analysis  

## Overview

This document outlines the design and implementation approach for extending Authly's OAuth 2.1 authorization server with signed URL capabilities and policy-based access control. This feature would enable secure, time-limited, and usage-constrained access to protected resources without requiring traditional authentication flows.

## Problem Statement

Current OAuth 2.1 flows require:
- Interactive authentication for each resource access
- Bearer token headers for API calls
- Complex client-side token management
- Limited granular access control beyond scopes

Many use cases need:
- **Temporary resource sharing** (documents, media, files)
- **Usage-based access control** (download limits, view counts)
- **Contextual restrictions** (IP-based, time-based, geographic)
- **Audit trails** for compliance and security

## Solution Architecture

### Core Components

#### 1. Policy Engine
```python
class AccessPolicy:
    # Temporal constraints
    expires_at: datetime
    valid_for: timedelta
    not_before: datetime
    
    # Usage constraints
    max_uses: int
    rate_limit: RateLimit
    concurrent_limit: int
    
    # Contextual constraints
    allowed_ips: List[str]
    allowed_origins: List[str]
    user_agent_pattern: str
    
    # Resource permissions
    resource_scope: ResourceScope
    resource_subset: str
    transformation_rules: Dict[str, Any]
```

#### 2. Signed URL Generation
```python
class SignedUrlGenerator:
    def generate_signed_url(
        self,
        resource_id: str,
        user_id: str,
        policy: AccessPolicy,
        signing_method: SigningMethod = SigningMethod.JWT
    ) -> SignedUrl:
        # Generate cryptographically signed URL
        # Embed policy constraints
        # Return time-limited access URL
```

#### 3. Validation Service
```python
class AccessValidator:
    def validate_access(
        self,
        token: str,
        resource_id: str,
        request_context: RequestContext
    ) -> ValidationResult:
        # Verify signature/token
        # Check policy constraints
        # Track usage
        # Return access decision
```

### Implementation Approaches

#### Option A: JWT-Based Tokens
```
GET /protected-resource?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

Token Payload:
{
  "sub": "user-123",
  "aud": "resource-456",
  "exp": 1720713600,
  "iat": 1720627200,
  "policy": {
    "max_uses": 5,
    "allowed_ips": ["192.168.1.0/24"],
    "resource_scope": "read"
  },
  "jti": "access-token-789"
}
```

**Pros:**
- Leverages existing JWT infrastructure
- Self-contained (no database lookup for basic validation)
- Cryptographically secure
- Standards-compliant

**Cons:**
- Larger URL size
- Policy updates require new tokens
- Complex usage tracking

#### Option B: HMAC Signature-Based
```
GET /protected-resource?signature=abc123&expires=1720713600&policy_id=policy-456&nonce=xyz789
```

**Pros:**
- Smaller URLs
- Flexible policy updates
- Easier usage tracking
- Lower computational overhead

**Cons:**
- Requires database lookup for validation
- Custom implementation
- Less standardized

#### Recommended: Hybrid Approach
- **JWT tokens** for complex policies and offline validation
- **HMAC signatures** for simple time-based access
- **Policy references** for frequently updated constraints

### Database Schema Extensions

#### New Tables
```sql
-- Policy definitions
CREATE TABLE access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE
);

-- Signed URL tracking
CREATE TABLE signed_urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id),
    policy_id UUID REFERENCES access_policies(id),
    token_jti VARCHAR(255) UNIQUE,
    signature_hash VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id)
);

-- Usage tracking
CREATE TABLE access_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signed_url_id UUID REFERENCES signed_urls(id),
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    client_ip INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    request_context JSONB
);

-- Resource definitions (optional)
CREATE TABLE protected_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id VARCHAR(255) UNIQUE NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    owner_id UUID REFERENCES users(id),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### API Endpoints

#### Generate Signed URL
```http
POST /api/v1/signed-urls
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "resource_id": "document-123",
  "user_id": "user-456",
  "policy": {
    "expires_at": "2024-07-12T10:00:00Z",
    "max_uses": 5,
    "allowed_ips": ["192.168.1.0/24"],
    "resource_scope": "read"
  },
  "signing_method": "jwt"
}

Response:
{
  "signed_url": "https://api.example.com/resource/document-123?token=eyJ...",
  "expires_at": "2024-07-12T10:00:00Z",
  "policy_id": "policy-789",
  "token_id": "access-token-123"
}
```

#### Validate Access
```http
GET /api/v1/validate-access
Authorization: Bearer <service_token>

Parameters:
- token: JWT token or signature
- resource_id: Resource identifier
- client_ip: Client IP address
- user_agent: Client user agent

Response:
{
  "valid": true,
  "user_id": "user-456",
  "resource_scope": "read",
  "remaining_uses": 3,
  "expires_at": "2024-07-12T10:00:00Z",
  "policy_violations": []
}
```

#### Revoke Access
```http
DELETE /api/v1/signed-urls/{token_id}
Authorization: Bearer <admin_token>

Response:
{
  "revoked": true,
  "revoked_at": "2024-07-11T15:30:00Z"
}
```

#### Usage Analytics
```http
GET /api/v1/signed-urls/{token_id}/usage
Authorization: Bearer <admin_token>

Response:
{
  "total_uses": 3,
  "remaining_uses": 2,
  "last_accessed": "2024-07-11T14:25:00Z",
  "access_history": [
    {
      "accessed_at": "2024-07-11T14:25:00Z",
      "client_ip": "192.168.1.100",
      "success": true
    }
  ]
}
```

### Integration Patterns

#### Pattern 1: Direct Resource Protection
```python
# Resource server integration
@app.route('/protected-resource/<resource_id>')
def serve_resource(resource_id):
    token = request.args.get('token')
    
    # Validate with Authly
    validation = authly_client.validate_access(
        token=token,
        resource_id=resource_id,
        client_ip=request.remote_addr
    )
    
    if not validation.valid:
        return abort(403)
    
    # Serve resource based on permissions
    return serve_file(resource_id, validation.resource_scope)
```

#### Pattern 2: Proxy/Gateway Integration
```python
# API Gateway middleware
class AuthlyAccessMiddleware:
    def process_request(self, request):
        if self.is_protected_resource(request.path):
            validation = self.validate_with_authly(request)
            if not validation.valid:
                return HTTPForbidden()
            
            # Add user context to request
            request.authly_user = validation.user_id
            request.authly_scope = validation.resource_scope
```

### Security Considerations

#### Cryptographic Security
- **JWT signing**: RS256 or ES256 for production
- **HMAC signatures**: SHA-256 minimum
- **Key rotation**: Automatic key rotation support
- **Token entropy**: Cryptographically secure random generation

#### Policy Enforcement
- **Server-side validation**: Never trust client-side policy checks
- **Usage tracking**: Atomic counters for max_uses enforcement
- **Rate limiting**: Distributed rate limiting for concurrent access
- **Audit logging**: Complete access history for compliance

#### Attack Vectors
- **Token replay**: JTI tracking prevents token reuse
- **URL enumeration**: Cryptographically random tokens
- **Policy bypass**: Server-side policy evaluation only
- **Resource enumeration**: Resource ID validation required

### Performance Considerations

#### Caching Strategy
```python
# Token validation caching
@cache(ttl=60)  # Cache valid tokens for 1 minute
def validate_token(token_hash):
    # Validate signature
    # Check policy constraints
    # Return cached result

# Policy caching
@cache(ttl=300)  # Cache policies for 5 minutes
def get_policy(policy_id):
    # Load from database
    # Return cached policy
```

#### Database Optimization
- **Indexes**: token_jti, resource_id, expires_at
- **Partitioning**: access_usage by date for large datasets
- **Cleanup jobs**: Automatic expired token cleanup
- **Read replicas**: Distribute validation load

### Use Case Examples

#### Document Sharing
```python
# Generate 24-hour document access
signed_url = authly.generate_signed_url(
    resource_id="confidential-report.pdf",
    user_id="external-auditor-123",
    policy=AccessPolicy(
        expires_at=datetime.now() + timedelta(hours=24),
        max_uses=3,
        allowed_ips=["203.0.113.0/24"],
        resource_scope="read"
    )
)
```

#### Media Distribution
```python
# Generate usage-limited video access
signed_url = authly.generate_signed_url(
    resource_id="premium-video-456",
    user_id="subscriber-789",
    policy=AccessPolicy(
        expires_at=datetime.now() + timedelta(days=7),
        max_uses=10,
        rate_limit=RateLimit(requests=5, per=timedelta(minutes=1)),
        resource_scope="stream"
    )
)
```

#### API Access Control
```python
# Generate temporary API access
signed_url = authly.generate_signed_url(
    resource_id="api/v1/user-data",
    user_id="partner-service-123",
    policy=AccessPolicy(
        expires_at=datetime.now() + timedelta(hours=1),
        rate_limit=RateLimit(requests=1000, per=timedelta(hours=1)),
        resource_scope="read"
    )
)
```

### Implementation Phases

#### Phase 1: Core Foundation
- Basic JWT token generation and validation
- Simple time-based expiration policies
- Database schema implementation
- Core API endpoints

#### Phase 2: Policy Engine
- Complex policy evaluation
- Usage tracking and enforcement
- Rate limiting integration
- Admin interface for policy management

#### Phase 3: Advanced Features
- HMAC signature support
- Contextual constraints (IP, geo, user-agent)
- Resource transformation policies
- Advanced analytics and reporting

#### Phase 4: Enterprise Integration
- Multi-tenant support
- Enterprise authentication integration
- Advanced caching and performance optimization
- Compliance and audit features

### Integration with Existing Authly Features

#### OAuth 2.1 Integration
- **Client credentials flow**: Service-to-service signed URL generation
- **Authorization code flow**: User-initiated resource sharing
- **Scope management**: Resource-specific scopes for fine-grained access

#### OIDC Integration
- **UserInfo claims**: Include user context in signed URLs
- **ID token integration**: Combine identity with resource access
- **Session management**: Link signed URLs to user sessions

#### Admin API Integration
- **Policy management**: CRUD operations for access policies
- **Usage analytics**: Integration with existing admin dashboard
- **Audit logging**: Extend existing audit trails

### Future Enhancements

#### Advanced Policy Features
- **Condition-based policies**: Dynamic policy evaluation
- **Machine learning**: Anomaly detection for access patterns
- **Blockchain integration**: Immutable access logs
- **Federation**: Cross-domain resource access

#### Performance Optimizations
- **Edge caching**: CDN integration for validation
- **GraphQL integration**: Efficient batch validation
- **WebAssembly**: Client-side policy evaluation
- **Streaming validation**: Real-time access monitoring

### Conclusion

Signed URLs with policy-based access control would position Authly as a comprehensive access management platform, extending beyond traditional OAuth flows to enable secure, flexible, and auditable resource access. This feature would differentiate Authly in the market while building on its existing OAuth 2.1 and OIDC foundation.

The implementation should follow Authly's existing patterns:
- **Security-first design** with comprehensive validation
- **Standards-compliant** where possible
- **Extensible architecture** for future enhancements
- **Production-ready** with proper testing and monitoring

This enhancement represents a significant expansion of Authly's capabilities and should be prioritized after core OAuth/OIDC completion and GDPR compliance implementation.