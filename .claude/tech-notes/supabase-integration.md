# Technical Note: Integrating Authly with Supabase

## Executive Summary

This technical note describes integration patterns for using Authly as an OAuth 2.1 and OpenID Connect provider alongside existing Supabase deployments. While Supabase provides built-in authentication through GoTrue, organizations may require Authly's advanced OAuth capabilities for:

- **OAuth 2.1 Compliance**: Strict adherence to the latest OAuth specifications
- **Token Introspection**: RFC 7662 compliant token validation for resource servers
- **Enterprise SSO**: Advanced SAML/OIDC federation capabilities
- **Custom OAuth Flows**: Support for specialized grant types and extensions
- **Multi-tenant Architecture**: Isolated authentication contexts per tenant

Authly complements Supabase by providing enterprise-grade authentication while Supabase handles data persistence, real-time subscriptions, and edge functions.

## Architecture Overview

### The Complementary Stack

```
┌─────────────────────────────────────────────────────────┐
│                   Client Applications                    │
└─────────────┬────────────────────┬──────────────────────┘
              │                    │
         OAuth/OIDC           Data/Realtime
              │                    │
              ▼                    ▼
┌──────────────────────┐  ┌──────────────────────┐
│      Authly          │  │     Supabase         │
│  ┌────────────────┐  │  │  ┌────────────────┐  │
│  │ OAuth 2.1      │  │  │  │ PostgREST      │  │
│  │ OIDC Provider  │  │  │  │ Realtime       │  │
│  │ Token Intros.  │◄─┼──┼─▶│ Edge Functions │  │
│  │ Admin API      │  │  │  │ Storage        │  │
│  └────────────────┘  │  │  └────────────────┘  │
│                      │  │                      │
│  ┌────────────────┐  │  │  ┌────────────────┐  │
│  │ PostgreSQL     │  │  │  │ PostgreSQL     │  │
│  │ (Auth Data)    │  │  │  │ (App Data)     │  │
│  └────────────────┘  │  │  └────────────────┘  │
└──────────────────────┘  └──────────────────────┘
```

## Integration Patterns

### Pattern A: Authly as Primary Authentication Provider

In this pattern, Authly handles all authentication while Supabase services validate tokens through Authly's introspection endpoint.

**Use Cases:**
- Replacing Supabase Auth with OAuth 2.1 compliant solution
- Enterprises requiring specific compliance certifications
- Applications needing advanced token management

**Implementation:**

1. **Configure Shared JWT Secret**
```bash
# .env configuration
JWT_SECRET=your-shared-secret-minimum-256-bits
JWT_ALGORITHM=HS256

# Apply to both Authly and Supabase
AUTHLY_JWT_SECRET_KEY=${JWT_SECRET}
SUPABASE_JWT_SECRET=${JWT_SECRET}
```

2. **Configure PostgREST to Accept Authly Tokens**
```yaml
# docker-compose.yml (Supabase)
services:
  rest:
    environment:
      PGRST_JWT_SECRET: ${JWT_SECRET}
      PGRST_JWT_AUD: "authenticated"
      PGRST_JWT_ROLE_CLAIM_KEY: ".role"
```

3. **Token Validation in Edge Functions**
```typescript
// supabase/functions/validate-authly-token/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

const AUTHLY_INTROSPECTION_URL = Deno.env.get('AUTHLY_URL') + '/api/v1/oauth/introspect'

serve(async (req: Request) => {
  const token = req.headers.get('Authorization')?.replace('Bearer ', '')
  
  if (!token) {
    return new Response('Unauthorized', { status: 401 })
  }

  // Validate token through Authly's introspection endpoint
  const introspectionResponse = await fetch(AUTHLY_INTROSPECTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      token: token,
      token_type_hint: 'access_token'
    })
  })

  const tokenInfo = await introspectionResponse.json()
  
  if (!tokenInfo.active) {
    return new Response('Token invalid or expired', { status: 401 })
  }

  // Token is valid, proceed with business logic
  return new Response(JSON.stringify({
    user: tokenInfo.sub,
    scopes: tokenInfo.scope,
    expires_at: tokenInfo.exp
  }), {
    headers: { 'Content-Type': 'application/json' }
  })
})
```

### Pattern B: Dual Authentication System

Run both Authly and Supabase Auth for different purposes:
- Supabase Auth for end-user authentication (mobile/web apps)
- Authly for API authentication (B2B, service-to-service)

**Use Cases:**
- B2B SaaS with both end-users and API consumers
- Gradual migration from Supabase Auth to Authly
- Different authentication requirements per client type

**Implementation:**

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Authly for OAuth/API Authentication
  authly:
    image: descoped/authly-standalone:latest
    ports:
      - "8000:8000"  # OAuth endpoints
    environment:
      DATABASE_URL: postgresql://authly:authly@authly-db:5432/authly
      JWT_SECRET_KEY: ${SHARED_JWT_SECRET}
      OAUTH_ISSUER: https://api.example.com
    networks:
      - auth-network

  # Supabase Stack
  supabase-auth:
    image: supabase/gotrue:latest
    environment:
      GOTRUE_JWT_SECRET: ${SHARED_JWT_SECRET}
      # Configure to coexist with Authly
      GOTRUE_JWT_AUD: "supabase"
    networks:
      - auth-network

  supabase-rest:
    image: postgrest/postgrest:latest
    environment:
      PGRST_JWT_SECRET: ${SHARED_JWT_SECRET}
      # Accept tokens from both providers
      PGRST_JWT_AUD: "authenticated,supabase,api"
    networks:
      - auth-network

networks:
  auth-network:
    driver: bridge
```

### Pattern C: Authly as OAuth Gateway

Use Authly as an OAuth gateway that issues tokens for accessing Supabase resources.

**Use Cases:**
- Third-party integrations requiring OAuth
- Marketplace/partner API access
- Compliance with specific OAuth profiles

**Implementation:**

1. **Configure OAuth Scopes for Supabase Resources**
```sql
-- In Authly's database
INSERT INTO oauth_scopes (scope_name, description) VALUES
  ('supabase:read', 'Read access to Supabase data'),
  ('supabase:write', 'Write access to Supabase data'),
  ('supabase:realtime', 'Access to real-time subscriptions'),
  ('supabase:storage', 'Access to file storage');
```

2. **Token Exchange Service**
```python
# token_exchange.py
from fastapi import FastAPI, Depends, HTTPException
from authly.auth import verify_token
import httpx

app = FastAPI()

@app.post("/exchange/supabase-token")
async def exchange_for_supabase_token(
    authly_token: str = Depends(verify_token)
):
    """Exchange Authly token for Supabase service token"""
    
    # Validate Authly token has required scopes
    if "supabase:read" not in authly_token.scopes:
        raise HTTPException(403, "Missing required scope")
    
    # Generate Supabase-compatible token
    supabase_claims = {
        "role": "authenticated",
        "sub": authly_token.sub,
        "aud": "authenticated",
        "exp": authly_token.exp,
        # Map Authly scopes to Supabase RLS policies
        "app_metadata": {
            "authly_scopes": authly_token.scopes,
            "provider": "authly"
        }
    }
    
    # Sign with shared secret
    return create_jwt(supabase_claims, settings.SHARED_JWT_SECRET)
```

## Database Integration

### Approach 1: Separate Databases

Maintain separate PostgreSQL instances for Authly and Supabase:

```sql
-- Authly Database (authly_db)
CREATE SCHEMA auth;
-- Users, clients, tokens, sessions

-- Supabase Database (app_db)  
CREATE SCHEMA public;
-- Application data

-- Optional: Foreign Data Wrapper for cross-database queries
CREATE EXTENSION postgres_fdw;
CREATE SERVER authly_server
  FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'authly-db', port '5432', dbname 'authly');
```

### Approach 2: Shared Database with Schema Isolation

Use a single PostgreSQL instance with separate schemas:

```sql
-- Shared PostgreSQL Instance
CREATE SCHEMA authly;      -- Authly tables
CREATE SCHEMA app;          -- Application data
CREATE SCHEMA supabase;     -- Supabase metadata

-- Grant appropriate permissions
GRANT USAGE ON SCHEMA authly TO postgrest_role;
GRANT SELECT ON authly.users TO postgrest_role;  -- Read-only for user info
```

## Security Considerations

### JWT Security

1. **Use RS256 for Production**
```yaml
# Authly configuration
JWT_ALGORITHM: RS256
JWT_PRIVATE_KEY_PATH: /secrets/private.pem
JWT_PUBLIC_KEY_PATH: /secrets/public.pem

# Share public key with Supabase
PGRST_JWT_SECRET: "@/secrets/public.pem"
```

2. **Token Validation Strategy**
- Always validate tokens at the edge (API Gateway/CDN)
- Use introspection for sensitive operations
- Cache validation results (TTL < token expiry)

### Network Security

```yaml
# docker-compose.yml
services:
  authly:
    networks:
      - internal
      - public
    
  supabase-services:
    networks:
      - internal  # Only internal network
    
  nginx:
    networks:
      - public    # Public facing
      - internal  # Proxy to services

networks:
  internal:
    internal: true  # No external access
  public:
    driver: bridge
```

### Audit Logging

```sql
-- Unified audit log table
CREATE TABLE audit.authentication_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  provider TEXT CHECK (provider IN ('authly', 'supabase')),
  event_type TEXT,
  user_id UUID,
  client_id TEXT,
  ip_address INET,
  user_agent TEXT,
  metadata JSONB
);

-- Trigger for Authly events
CREATE TRIGGER authly_audit_trigger
  AFTER INSERT OR UPDATE ON authly.tokens
  FOR EACH ROW EXECUTE FUNCTION audit.log_auth_event();
```

## Production Deployment

### High Availability Architecture

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  authly-1:
    image: descoped/authly:latest
    deploy:
      replicas: 2
    environment:
      DATABASE_URL: postgresql://authly:${DB_PASSWORD}@pgbouncer:6432/authly
      REDIS_URL: redis://redis-sentinel:26379
    networks:
      - authly-ha

  authly-2:
    extends: authly-1

  pgbouncer:
    image: pgbouncer/pgbouncer:latest
    environment:
      DATABASES_HOST: postgres-primary
      DATABASES_PORT: 5432
      POOL_MODE: transaction
      MAX_CLIENT_CONN: 1000
    networks:
      - authly-ha

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis-sentinel.conf
    networks:
      - authly-ha

  haproxy:
    image: haproxy:latest
    ports:
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    networks:
      - authly-ha

networks:
  authly-ha:
    driver: overlay
    encrypted: true
```

### Monitoring Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'authly'
    static_configs:
      - targets: ['authly:9090']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'authly_.*'
        action: keep

  - job_name: 'supabase'
    static_configs:
      - targets: ['supabase-metrics:9100']
```

### Performance Optimization

1. **Connection Pooling**
```yaml
# PgBouncer configuration
[databases]
authly = host=postgres-primary dbname=authly pool_mode=transaction
supabase = host=postgres-primary dbname=supabase pool_mode=session

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
```

2. **Caching Strategy**
```python
# Redis caching for token validation
import redis
import json
from datetime import timedelta

redis_client = redis.Redis(host='redis', decode_responses=True)

def cached_introspection(token: str) -> dict:
    # Check cache first
    cached = redis_client.get(f"token:{token}")
    if cached:
        return json.loads(cached)
    
    # Introspect token
    result = introspect_token(token)
    
    # Cache if valid (TTL = remaining token lifetime)
    if result['active']:
        ttl = result['exp'] - time.time()
        redis_client.setex(
            f"token:{token}", 
            timedelta(seconds=min(ttl, 300)),  # Max 5 min cache
            json.dumps(result)
        )
    
    return result
```

## Migration Guide

### Migrating from Supabase Auth to Authly

1. **Export Existing Users**
```sql
-- From Supabase
COPY (
  SELECT 
    id,
    email,
    encrypted_password,
    created_at,
    updated_at,
    raw_user_meta_data
  FROM auth.users
) TO '/tmp/users.csv' CSV HEADER;
```

2. **Import to Authly**
```python
# migrate_users.py
import csv
import asyncio
from authly.users import UserService

async def migrate_users():
    with open('/tmp/users.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            await UserService.create_user(
                email=row['email'],
                password_hash=row['encrypted_password'],
                metadata=json.loads(row['raw_user_meta_data'])
            )
```

3. **Parallel Run Period**
- Run both auth systems simultaneously
- Gradually migrate clients to Authly endpoints
- Monitor and validate before full cutover

## Code Examples

### Supabase Edge Function with Authly Token

```typescript
// supabase/functions/protected-api/index.ts
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import jwt from 'https://esm.sh/jsonwebtoken@9'

const supabase = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
)

serve(async (req) => {
  const token = req.headers.get('Authorization')?.replace('Bearer ', '')
  
  if (!token) {
    return new Response('Unauthorized', { status: 401 })
  }

  try {
    // Verify Authly token
    const payload = jwt.verify(token, Deno.env.get('JWT_SECRET')!)
    
    // Use Authly user ID to query Supabase
    const { data, error } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('authly_user_id', payload.sub)
      .single()
    
    if (error) throw error
    
    return new Response(JSON.stringify(data), {
      headers: { 'Content-Type': 'application/json' }
    })
  } catch (error) {
    return new Response('Invalid token', { status: 401 })
  }
})
```

### RLS Policy with Authly Claims

```sql
-- Enable RLS
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;

-- Policy using Authly token claims
CREATE POLICY "Users can view own documents" ON app.documents
  FOR SELECT
  USING (
    owner_id = current_setting('request.jwt.claims', true)::json->>'sub'
    AND 
    current_setting('request.jwt.claims', true)::json->'scope' ? 'documents:read'
  );

-- Policy for Authly admin users
CREATE POLICY "Admins can view all documents" ON app.documents
  FOR ALL
  USING (
    current_setting('request.jwt.claims', true)::json->>'role' = 'admin'
  );
```

## Troubleshooting

### Common Issues

1. **Token Signature Verification Fails**
   - Ensure JWT secrets match exactly
   - Check algorithm compatibility (HS256 vs RS256)
   - Verify token hasn't expired

2. **CORS Errors**
   - Configure Authly CORS settings
   - Add Supabase domain to allowed origins
   - Check preflight request handling

3. **Database Connection Issues**
   - Verify network connectivity between containers
   - Check PostgreSQL authentication settings
   - Ensure proper DNS resolution

### Debug Logging

```yaml
# Enable debug logging
services:
  authly:
    environment:
      LOG_LEVEL: DEBUG
      
  postgrest:
    environment:
      PGRST_LOG_LEVEL: info
```

## Conclusion

Integrating Authly with Supabase provides organizations with enterprise-grade OAuth 2.1 capabilities while leveraging Supabase's excellent data platform. The patterns described in this document can be adapted based on specific requirements, with the flexibility to start simple and evolve toward more sophisticated architectures as needs grow.

For production deployments, consider:
- Starting with Pattern A (Authly as primary auth) for greenfield projects
- Using Pattern B (dual auth) for gradual migrations
- Implementing Pattern C (OAuth gateway) for API marketplace scenarios

The key to successful integration is maintaining clear boundaries between authentication (Authly) and application services (Supabase), while ensuring secure and efficient token validation across the stack.

---

*This technical note is maintained independently of the Authly project and represents integration patterns for external implementations. For official Authly documentation, see [docs.authly.com](https://docs.authly.com).*