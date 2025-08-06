# Deployment Guide for Authly

⚠️ **Warning**: Authly is a work in progress with ~90% OIDC compliance. Not recommended for production use without extensive testing and security audit.

This guide covers deployment scenarios for Authly OAuth 2.1 Authorization Server. Use at your own risk in production environments.

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Docker Deployment](#docker-deployment)
3. [Production Infrastructure](#production-infrastructure)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Security Configuration](#security-configuration)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Operations and Maintenance](#operations-and-maintenance)
8. [Troubleshooting](#troubleshooting)

## Deployment Overview

### Architecture Options

Authly supports multiple deployment architectures:

```mermaid
graph TB
    subgraph "Development"
        DEV_LOCAL[Local Source Code]
        DEV_DOCKER[Docker Compose Dev]
    end
    
    subgraph "Testing"
        TEST_HUB[Docker Hub Images]
        TEST_STAGING[Staging Environment]
    end
    
    subgraph "Production"
        PROD_DOCKER[Docker Compose Production]
        PROD_K8S[Kubernetes Cluster]
        PROD_CLOUD[Cloud Services]
    end
    
    DEV_LOCAL --> TEST_HUB
    DEV_DOCKER --> TEST_STAGING
    TEST_HUB --> PROD_DOCKER
    TEST_STAGING --> PROD_K8S
    PROD_DOCKER --> PROD_CLOUD
```

### Feature Matrix

| Feature | Development | Docker Hub | Production | Kubernetes |
|---------|-------------|------------|------------|------------|
| Source Code Mounting | ✅ | ❌ | ❌ | ❌ |
| Admin Tools | ✅ | Optional | ❌ | Optional |
| SSL/TLS Termination | Self-signed | Self-signed | Required | Required |
| Monitoring Stack | Optional | Optional | Recommended | Required |
| High Availability | ❌ | ❌ | Optional | ✅ |
| Auto-scaling | ❌ | ❌ | ❌ | ✅ |
| Secret Management | Environment | Environment | Docker Secrets | K8s Secrets |

## Docker Deployment

### Quick Start Matrix

| Scenario | Command | Use Case |
|----------|---------|----------|
| **Development** | `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d` | Local development with tools |
| **Docker Hub Testing** | `docker compose -f docker-compose.hub.yml up -d` | Test released versions |
| **Production** | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | Production deployment |
| **Full Monitoring** | `docker compose -f docker-compose.hub.yml --profile monitoring up -d` | With Prometheus/Grafana |

### Development Environment

Perfect for local development with hot reloading and debugging tools.

```bash
# Clone repository
git clone <repository-url>
cd authly

# Generate development SSL certificates
./scripts/setup-dev-certs.sh

# Start development environment
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Access services
echo "Authly API: http://localhost:8000"
echo "pgAdmin: http://localhost:5050 (admin@authly.dev / admin)"
echo "Redis Commander: http://localhost:8081 (admin / admin)"
echo "Mailhog: http://localhost:8025"
```

**Development Features:**
- Hot code reloading (source mounted)
- Debug logging enabled
- Relaxed rate limiting
- Development admin tools
- Email testing with Mailhog

### Docker Hub Deployment

Use pre-built images for testing and production without building from source.

```bash
# Setup environment
cp .env.hub.example .env.hub
vim .env.hub  # Configure for your environment

# Basic deployment
docker compose -f docker-compose.hub.yml up -d

# With admin tools
docker compose -f docker-compose.hub.yml --profile admin up -d

# With monitoring
docker compose -f docker-compose.hub.yml --profile monitoring up -d

# Full stack
docker compose -f docker-compose.hub.yml --profile admin --profile monitoring up -d
```

#### Version Management

```bash
# Use specific version (recommended for production)
AUTHLY_VERSION=0.5.3 docker compose -f docker-compose.hub.yml up -d

# Use latest (testing only)
AUTHLY_VERSION=latest docker compose -f docker-compose.hub.yml up -d

# Use minor version (automatic patch updates)
AUTHLY_VERSION=0.5 docker compose -f docker-compose.hub.yml up -d
```

### Production Docker Deployment

Enterprise-ready deployment with security, monitoring, and high availability.

```bash
# 1. Setup environment
cp .env.example .env
vim .env  # Configure production values

# 2. Generate secure secrets
echo "$(openssl rand -base64 32)" | docker secret create postgres_password -
echo "$(openssl rand -base64 32)" | docker secret create redis_password -
echo "$(openssl rand -base64 32)" | docker secret create jwt_secret_key -
echo "$(openssl rand -base64 32)" | docker secret create jwt_refresh_secret_key -

# 3. Deploy production stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 4. Deploy with monitoring
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile production --profile monitoring up -d
```

#### Production Features
- SSL/TLS termination with Nginx
- Docker secrets for sensitive data
- Stricter rate limiting and security headers
- Resource limits and health checks
- Log aggregation with structured JSON
- Admin endpoints access control

### SSL/TLS Configuration

#### Development (Self-signed)
```bash
# Automatic generation
./scripts/setup-dev-certs.sh
```

#### Production (Let's Encrypt)
```bash
# Generate certificates
sudo certbot certonly --standalone -d auth.yourdomain.com

# Copy to Docker volumes
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem docker-compose/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem docker-compose/nginx/ssl/key.pem

# Set proper permissions
sudo chown $USER:$USER docker-compose/nginx/ssl/*.pem
```

### Environment Configuration Templates

#### Development (.env.dev)
```bash
# Development defaults - insecure but convenient
POSTGRES_PASSWORD=dev_password
REDIS_PASSWORD=redis_dev_password
JWT_SECRET_KEY=dev-secret-key-not-for-production
JWT_REFRESH_SECRET_KEY=dev-refresh-secret-not-for-production
AUTHLY_BOOTSTRAP_DEV_MODE=true
AUTHLY_LOG_LEVEL=DEBUG
RATE_LIMIT_MAX_REQUESTS=1000
```

#### Production (.env)
```bash
# Core Configuration
AUTHLY_VERSION=0.5.3
DEFAULT_API_URL=https://auth.yourdomain.com
DEFAULT_ISSUER_URL=https://auth.yourdomain.com

# Database
POSTGRES_PASSWORD=your_secure_database_password
DATABASE_URL=postgresql://authly:${POSTGRES_PASSWORD}@postgres:5432/authly

# Redis
REDIS_PASSWORD=your_secure_redis_password
AUTHLY_REDIS_CACHE=true
AUTHLY_REDIS_RATE_LIMIT=true

# JWT Configuration (CRITICAL - must be secure)
JWT_SECRET_KEY=your-256-bit-secret-key
JWT_REFRESH_SECRET_KEY=your-256-bit-refresh-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
AUTHLY_BOOTSTRAP_DEV_MODE=false
AUTHLY_LOG_LEVEL=INFO
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60

# Admin
AUTHLY_ADMIN_USERNAME=admin
AUTHLY_ADMIN_PASSWORD=your_secure_admin_password
```

## Production Infrastructure

### Minimum Requirements

#### Application Servers (per instance)
- **CPU**: 4 cores (8 threads)
- **Memory**: 8GB RAM
- **Storage**: 50GB SSD
- **Network**: 1Gbps connection

#### Database Server
- **CPU**: 8 cores (16 threads) 
- **Memory**: 16GB RAM (min), 32GB recommended
- **Storage**: 500GB SSD with high IOPS
- **Network**: 10Gbps connection

#### Load Balancer
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Network**: 10Gbps connection
- **SSL**: Hardware or software SSL acceleration

### Production Architecture

```mermaid
graph TB
    subgraph "External"
        USERS[Users/Clients]
        ADMIN[Administrators]
    end
    
    subgraph "Edge Layer"
        LB[Load Balancer<br/>nginx/HAProxy]
        SSL[SSL Termination]
        WAF[Web Application Firewall]
    end
    
    subgraph "Application Layer"
        APP1[Authly Instance 1]
        APP2[Authly Instance 2]
        APP3[Authly Instance 3]
    end
    
    subgraph "Data Layer"
        DB_PRIMARY[(PostgreSQL Primary)]
        DB_REPLICA[(PostgreSQL Replica)]
        REDIS[(Redis Cluster)]
        VAULT[HashiCorp Vault]
    end
    
    subgraph "Monitoring"
        PROMETHEUS[Prometheus]
        GRAFANA[Grafana]
        ALERTS[AlertManager]
    end
    
    USERS --> LB
    ADMIN --> LB
    LB --> SSL
    SSL --> WAF
    WAF --> APP1
    WAF --> APP2
    WAF --> APP3
    
    APP1 --> DB_PRIMARY
    APP2 --> DB_PRIMARY
    APP3 --> DB_PRIMARY
    
    APP1 --> DB_REPLICA
    APP2 --> DB_REPLICA
    APP3 --> DB_REPLICA
    
    APP1 --> REDIS
    APP2 --> REDIS
    APP3 --> REDIS
    
    APP1 --> VAULT
    APP2 --> VAULT
    APP3 --> VAULT
    
    APP1 --> PROMETHEUS
    APP2 --> PROMETHEUS
    APP3 --> PROMETHEUS
    
    PROMETHEUS --> GRAFANA
    PROMETHEUS --> ALERTS
```

### Database Configuration

#### Schema Setup
```sql
-- Core extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    phone_number VARCHAR(50),
    locale VARCHAR(10) DEFAULT 'en',
    picture VARCHAR(512),
    is_verified BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    requires_password_change BOOLEAN DEFAULT false,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth clients table
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT[] NOT NULL,
    client_uri VARCHAR(255),
    logo_uri VARCHAR(255),
    contacts TEXT[],
    tos_uri VARCHAR(255),
    policy_uri VARCHAR(255),
    jwks_uri VARCHAR(255),
    software_id VARCHAR(255),
    software_version VARCHAR(255),
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    response_types TEXT[] DEFAULT ARRAY['code'],
    grant_types TEXT[] DEFAULT ARRAY['authorization_code'],
    require_pkce BOOLEAN DEFAULT true,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth scopes table
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Client-scope associations
CREATE TABLE client_scopes (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, scope_id)
);

-- Tokens table
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Authorization codes table
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) DEFAULT 'S256',
    redirect_uri TEXT NOT NULL,
    nonce VARCHAR(255),
    state VARCHAR(255),
    max_age INTEGER,
    acr_values TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- JWKS table
CREATE TABLE jwks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kid VARCHAR(255) UNIQUE NOT NULL,
    kty VARCHAR(20) NOT NULL,
    use_type VARCHAR(20) DEFAULT 'sig',
    alg VARCHAR(20) DEFAULT 'RS256',
    key_data JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### Performance Indexes
```sql
-- User indexes
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_users_last_login ON users(last_login);

-- Client indexes
CREATE INDEX CONCURRENTLY idx_clients_client_id ON clients(client_id);
CREATE INDEX CONCURRENTLY idx_clients_active ON clients(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_clients_type ON clients(client_type);

-- Scope indexes
CREATE INDEX CONCURRENTLY idx_scopes_name ON scopes(scope_name);
CREATE INDEX CONCURRENTLY idx_scopes_active ON scopes(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_scopes_default ON scopes(is_default) WHERE is_default = true;

-- Token indexes (critical for performance)
CREATE INDEX CONCURRENTLY idx_tokens_jti ON tokens(jti);
CREATE INDEX CONCURRENTLY idx_tokens_user_id ON tokens(user_id);
CREATE INDEX CONCURRENTLY idx_tokens_client_id ON tokens(client_id);
CREATE INDEX CONCURRENTLY idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX CONCURRENTLY idx_tokens_active ON tokens(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_tokens_user_type_active ON tokens(user_id, token_type, is_active);

-- Authorization code indexes
CREATE INDEX CONCURRENTLY idx_auth_codes_code ON authorization_codes(code);
CREATE INDEX CONCURRENTLY idx_auth_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX CONCURRENTLY idx_auth_codes_client_user ON authorization_codes(client_id, user_id);
CREATE INDEX CONCURRENTLY idx_auth_codes_unused ON authorization_codes(used) WHERE used = false;

-- JWKS indexes
CREATE INDEX CONCURRENTLY idx_jwks_kid ON jwks(kid);
CREATE INDEX CONCURRENTLY idx_jwks_active ON jwks(is_active) WHERE is_active = true;
```

## Kubernetes Deployment

### Namespace and Configuration

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: authly
  labels:
    name: authly
    app.kubernetes.io/name: authly
    app.kubernetes.io/version: "0.5.3"

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authly-config
  namespace: authly
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "info"
  OAUTH_ENABLED: "true"
  PKCE_REQUIRED: "true"
  REQUIRE_USER_CONSENT: "true"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_MAX_REQUESTS: "100"
  RATE_LIMIT_WINDOW_SECONDS: "60"
  ACCESS_TOKEN_EXPIRE_MINUTES: "15"
  REFRESH_TOKEN_EXPIRE_DAYS: "7"
  AUTHORIZATION_CODE_EXPIRE_MINUTES: "10"
  CORS_ORIGINS: "https://app.example.com,https://admin.example.com"
  ALLOWED_HOSTS: "auth.example.com,api.example.com"
  METRICS_ENABLED: "true"
  HEALTH_CHECK_ENABLED: "true"
```

### Secrets Management

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: authly-secrets
  namespace: authly
type: Opaque
data:
  # Base64 encoded values - generate with: echo -n "value" | base64
  DATABASE_URL: <base64-encoded-database-url>
  JWT_SECRET_KEY: <base64-encoded-jwt-secret>
  JWT_REFRESH_SECRET_KEY: <base64-encoded-refresh-secret>
  ADMIN_PASSWORD: <base64-encoded-admin-password>
  SMTP_PASSWORD: <base64-encoded-smtp-password>
  REDIS_PASSWORD: <base64-encoded-redis-password>
```

### Application Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authly-deployment
  namespace: authly
  labels:
    app: authly
    version: "0.5.3"
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: authly
  template:
    metadata:
      labels:
        app: authly
        version: "0.5.3"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: authly
        image: descoped/authly:0.5.3
        ports:
        - containerPort: 8000
          name: http
          protocol: TCP
        envFrom:
        - configMapRef:
            name: authly-config
        - secretRef:
            name: authly-secrets
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 15"]
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      terminationGracePeriodSeconds: 30
      restartPolicy: Always

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: authly-service
  namespace: authly
  labels:
    app: authly
spec:
  selector:
    app: authly
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
    name: http
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authly-ingress
  namespace: authly
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "1m"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "30"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - auth.example.com
    secretName: authly-tls
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: authly-service
            port:
              number: 80
```

### Database Deployment

```yaml
# k8s/postgres.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: authly
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  storageClassName: fast-ssd

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-deployment
  namespace: authly
  labels:
    app: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      securityContext:
        runAsUser: 999
        runAsGroup: 999
        fsGroup: 999
      containers:
      - name: postgres
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: authly
        - name: POSTGRES_USER
          value: authly
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - authly
            - -d
            - authly
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - authly
            - -d
            - authly
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc

---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: authly
  labels:
    app: postgres
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

### HorizontalPodAutoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: authly-hpa
  namespace: authly
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: authly-deployment
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

## Security Configuration

### SSL/TLS Configuration

#### Nginx Production Configuration

```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none'; child-src 'none'; worker-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; manifest-src 'self';" always;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Performance optimization
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 1M;
    server_tokens off;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_comp_level 6;
    gzip_types
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml
        text/plain
        text/css
        text/xml
        text/javascript;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=discovery:10m rate=60r/m;
    
    # IP whitelist for admin endpoints
    geo $admin_allowed {
        default 0;
        10.0.0.0/8 1;
        172.16.0.0/12 1;
        192.168.0.0/16 1;
        # Add your admin IP ranges here
    }
    
    upstream authly_backend {
        least_conn;
        server authly:8000 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }
    
    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name auth.example.com;
        return 301 https://$server_name$request_uri;
    }
    
    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name auth.example.com;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        
        # OAuth authorization endpoints (strict rate limiting)
        location ~ ^/(oauth/authorize|auth/token|auth/refresh|oauth/revoke) {
            limit_req zone=auth burst=5 nodelay;
            
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_connect_timeout 5s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
            
            proxy_buffering off;
            proxy_request_buffering off;
        }
        
        # Discovery endpoints (cached, higher rate limit)
        location ~ ^/\.well-known/(oauth-authorization-server|openid_configuration|jwks\.json) {
            limit_req zone=discovery burst=20 nodelay;
            
            proxy_pass http://authly_backend;
            proxy_cache_valid 200 1h;
            add_header Cache-Control "public, max-age=3600";
            expires 1h;
            
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # OIDC endpoints
        location ~ ^/(oidc/userinfo|oidc/logout) {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # API endpoints
        location /api {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Admin endpoints (IP restricted)
        location /admin {
            if ($admin_allowed = 0) {
                return 403;
            }
            
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Health check (no rate limiting)
        location /health {
            proxy_pass http://authly_backend;
            access_log off;
            
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Metrics endpoint (IP restricted)
        location /metrics {
            if ($admin_allowed = 0) {
                return 403;
            }
            
            proxy_pass http://authly_backend;
            access_log off;
            
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Default location
        location / {
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### Firewall Configuration

```bash
#!/bin/bash
# scripts/configure_firewall.sh

# Configure UFW firewall for production Authly deployment
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# SSH access (customize port as needed)
ufw allow 22/tcp

# HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Database access (internal networks only)
ufw allow from 10.0.0.0/8 to any port 5432
ufw allow from 172.16.0.0/12 to any port 5432
ufw allow from 192.168.0.0/16 to any port 5432

# Redis access (internal networks only)
ufw allow from 10.0.0.0/8 to any port 6379
ufw allow from 172.16.0.0/12 to any port 6379
ufw allow from 192.168.0.0/16 to any port 6379

# Monitoring (internal networks only)
ufw allow from 10.0.0.0/8 to any port 9090  # Prometheus
ufw allow from 10.0.0.0/8 to any port 3000  # Grafana

# Enable firewall
ufw --force enable
ufw status verbose
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'authly-production'
    env: 'production'

rule_files:
  - "authly_rules.yml"

scrape_configs:
  - job_name: 'authly'
    static_configs:
      - targets: ['authly-service:80']
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 10s
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
    scrape_interval: 60s
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 30s
    
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']
    scrape_interval: 30s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Alert Rules

```yaml
# monitoring/authly_rules.yml
groups:
  - name: authly_alerts
    rules:
      - alert: AuthlyHighErrorRate
        expr: rate(authly_http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
          service: authly
        annotations:
          summary: "Authly high error rate detected"
          description: "Error rate is {{ $value }} errors per second"
          
      - alert: AuthlyHighLatency
        expr: histogram_quantile(0.95, rate(authly_http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
          service: authly
        annotations:
          summary: "Authly high latency detected"
          description: "95th percentile latency is {{ $value }}s"
          
      - alert: AuthlyDatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
          service: authly
        annotations:
          summary: "Authly database connection lost"
          description: "PostgreSQL database is unreachable"
          
      - alert: AuthlyRedisDown
        expr: up{job="redis"} == 0
        for: 2m
        labels:
          severity: warning
          service: authly
        annotations:
          summary: "Authly Redis connection lost"
          description: "Redis cache is unreachable"
          
      - alert: AuthlyLowAuthSuccess
        expr: rate(authly_oauth_token_requests_total{status="success"}[5m]) / rate(authly_oauth_token_requests_total[5m]) < 0.9
        for: 5m
        labels:
          severity: warning
          service: authly
        annotations:
          summary: "Authly low authentication success rate"
          description: "Authentication success rate is {{ $value | humanizePercentage }}"
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "id": null,
    "title": "Authly OAuth 2.1 Production Dashboard",
    "tags": ["authly", "oauth", "oidc"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(authly_http_requests_total[5m])) by (endpoint)",
            "legendFormat": "{{endpoint}}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec"
          }
        ]
      },
      {
        "id": 2,
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(authly_http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(authly_http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(authly_http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds"
          }
        ]
      },
      {
        "id": 3,
        "title": "OAuth Token Requests",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(rate(authly_oauth_token_requests_total[5m])) by (grant_type, status)",
            "legendFormat": "{{grant_type}} - {{status}}"
          }
        ]
      },
      {
        "id": 4,
        "title": "Authentication Success Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(authly_auth_login_attempts_total{status=\"success\"}[5m]) / rate(authly_auth_login_attempts_total[5m])",
            "legendFormat": "Success Rate"
          }
        ],
        "format": "percentunit",
        "valueName": "current"
      },
      {
        "id": 5,
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "authly_database_connections_active",
            "legendFormat": "Active"
          },
          {
            "expr": "authly_database_connections_idle",
            "legendFormat": "Idle"
          }
        ]
      },
      {
        "id": 6,
        "title": "Redis Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "authly_cache_memory_usage_bytes",
            "legendFormat": "Memory Usage"
          }
        ],
        "yAxes": [
          {
            "label": "Bytes"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
```

## Operations and Maintenance

### Deployment Scripts

#### Automated Deployment

```bash
#!/bin/bash
# scripts/deploy_production.sh

set -e

ENVIRONMENT=${ENVIRONMENT:-production}
VERSION=${VERSION:-0.5.3}
NAMESPACE=${NAMESPACE:-authly}

echo "Starting Authly production deployment..."
echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"
echo "Namespace: $NAMESPACE"

# Pre-deployment checks
echo "Running pre-deployment checks..."

# Check Kubernetes connectivity
kubectl cluster-info > /dev/null 2>&1 || {
    echo "Error: Cannot connect to Kubernetes cluster"
    exit 1
}

# Check if namespace exists
kubectl get namespace $NAMESPACE > /dev/null 2>&1 || {
    echo "Creating namespace $NAMESPACE..."
    kubectl create namespace $NAMESPACE
}

# Validate configurations
echo "Validating Kubernetes configurations..."
kubectl apply --dry-run=client -f k8s/ > /dev/null 2>&1 || {
    echo "Error: Invalid Kubernetes configuration"
    exit 1
}

# Database migration
echo "Running database migrations..."
kubectl apply -f k8s/migration-job.yaml
kubectl wait --for=condition=complete job/database-migration -n $NAMESPACE --timeout=300s

# Deploy services
echo "Deploying services..."
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml

# Deploy database
if [ "$DATABASE_EXTERNAL" != "true" ]; then
    kubectl apply -f k8s/postgres.yaml
    kubectl wait --for=condition=available deployment/postgres-deployment -n $NAMESPACE --timeout=300s
fi

# Deploy Redis
if [ "$REDIS_ENABLED" = "true" ]; then
    kubectl apply -f k8s/redis.yaml
    kubectl wait --for=condition=available deployment/redis-deployment -n $NAMESPACE --timeout=300s
fi

# Deploy main application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml

# Wait for deployment
echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available deployment/authly-deployment -n $NAMESPACE --timeout=600s

# Verify deployment
echo "Verifying deployment..."
kubectl get pods -n $NAMESPACE
kubectl get services -n $NAMESPACE
kubectl get ingress -n $NAMESPACE

# Run post-deployment tests
echo "Running post-deployment tests..."
./scripts/post_deployment_tests.sh

echo "Deployment completed successfully!"

# Display access information
INGRESS_IP=$(kubectl get ingress authly-ingress -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "Application available at: https://auth.example.com"
echo "Ingress IP: $INGRESS_IP"
```

#### Post-Deployment Testing

```bash
#!/bin/bash
# scripts/post_deployment_tests.sh

set -e

BASE_URL=${BASE_URL:-https://auth.example.com}
TIMEOUT=30

echo "Running post-deployment tests for $BASE_URL..."

# Test 1: Health check
echo "Testing health endpoint..."
curl -f -s --max-time $TIMEOUT "$BASE_URL/health" > /dev/null && {
    echo "✓ Health check passed"
} || {
    echo "✗ Health check failed"
    exit 1
}

# Test 2: OAuth discovery
echo "Testing OAuth discovery endpoint..."
DISCOVERY_RESPONSE=$(curl -f -s --max-time $TIMEOUT "$BASE_URL/.well-known/oauth-authorization-server")
echo "$DISCOVERY_RESPONSE" | jq -e '.authorization_endpoint' > /dev/null 2>&1 && {
    echo "✓ OAuth discovery endpoint working"
} || {
    echo "✗ OAuth discovery endpoint failed"
    exit 1
}

# Test 3: OIDC discovery
echo "Testing OIDC discovery endpoint..."
OIDC_RESPONSE=$(curl -f -s --max-time $TIMEOUT "$BASE_URL/.well-known/openid_configuration")
echo "$OIDC_RESPONSE" | jq -e '.userinfo_endpoint' > /dev/null 2>&1 && {
    echo "✓ OIDC discovery endpoint working"
} || {
    echo "✗ OIDC discovery endpoint failed"
    exit 1
}

# Test 4: JWKS endpoint
echo "Testing JWKS endpoint..."
JWKS_RESPONSE=$(curl -f -s --max-time $TIMEOUT "$BASE_URL/.well-known/jwks.json")
echo "$JWKS_RESPONSE" | jq -e '.keys' > /dev/null 2>&1 && {
    echo "✓ JWKS endpoint working"
} || {
    echo "✗ JWKS endpoint failed"
    exit 1
}

# Test 5: Authorization endpoint (should return 400 for invalid params)
echo "Testing authorization endpoint..."
AUTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT \
    "$BASE_URL/oauth/authorize?response_type=code&client_id=invalid")
[ "$AUTH_RESPONSE" = "400" ] && {
    echo "✓ Authorization endpoint responding correctly"
} || {
    echo "✗ Authorization endpoint failed (HTTP $AUTH_RESPONSE)"
    exit 1
}

# Test 6: SSL certificate
echo "Testing SSL certificate..."
SSL_CHECK=$(echo | openssl s_client -servername auth.example.com -connect auth.example.com:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
[ -n "$SSL_CHECK" ] && {
    echo "✓ SSL certificate valid"
} || {
    echo "✗ SSL certificate check failed"
    exit 1
}

echo "All post-deployment tests passed successfully!"
```

### Backup and Recovery

#### Database Backup

```bash
#!/bin/bash
# scripts/backup_database.sh

set -e

BACKUP_DIR=${BACKUP_DIR:-/backups}
RETENTION_DAYS=${RETENTION_DAYS:-30}
S3_BUCKET=${S3_BUCKET:-authly-backups}

mkdir -p $BACKUP_DIR

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="authly_backup_${TIMESTAMP}.sql"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"

echo "Starting database backup..."

# Create database backup
pg_dump "$DATABASE_URL" --clean --if-exists --create > "$BACKUP_PATH"

if [ $? -eq 0 ]; then
    echo "Database backup created: $BACKUP_PATH"
    
    # Compress backup
    gzip "$BACKUP_PATH"
    BACKUP_PATH="${BACKUP_PATH}.gz"
    
    # Upload to S3 if configured
    if [ -n "$S3_BUCKET" ]; then
        aws s3 cp "$BACKUP_PATH" "s3://${S3_BUCKET}/database/" --storage-class STANDARD_IA
        echo "Backup uploaded to S3: s3://${S3_BUCKET}/database/$(basename $BACKUP_PATH)"
    fi
    
    # Clean up old backups
    find "$BACKUP_DIR" -name "authly_backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete
    
    echo "Backup completed successfully!"
else
    echo "Backup failed!"
    exit 1
fi
```

#### Disaster Recovery

```bash
#!/bin/bash
# scripts/disaster_recovery.sh

set -e

BACKUP_FILE=${1}
ENVIRONMENT=${2:-production}

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [environment]"
    echo "Example: $0 authly_backup_20240101_120000.sql.gz production"
    exit 1
fi

echo "Starting disaster recovery for environment: $ENVIRONMENT"
echo "Backup file: $BACKUP_FILE"

# Confirm before proceeding
read -p "This will replace the current database. Are you sure? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Recovery cancelled."
    exit 1
fi

# Download backup from S3 if needed
if [[ "$BACKUP_FILE" == s3://* ]]; then
    echo "Downloading backup from S3..."
    aws s3 cp "$BACKUP_FILE" "/tmp/$(basename $BACKUP_FILE)"
    BACKUP_FILE="/tmp/$(basename $BACKUP_FILE)"
fi

# Decompress if needed
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Decompressing backup..."
    gunzip -c "$BACKUP_FILE" > "/tmp/recovery.sql"
    BACKUP_FILE="/tmp/recovery.sql"
fi

# Stop application
echo "Stopping application..."
kubectl scale deployment authly-deployment --replicas=0 -n authly

# Restore database
echo "Restoring database..."
psql "$DATABASE_URL" < "$BACKUP_FILE"

# Restart application
echo "Restarting application..."
kubectl scale deployment authly-deployment --replicas=3 -n authly

# Wait for application to be ready
kubectl wait --for=condition=available deployment/authly-deployment -n authly --timeout=300s

# Verify recovery
echo "Verifying recovery..."
./scripts/post_deployment_tests.sh

echo "Disaster recovery completed successfully!"
```

### Maintenance Procedures

```bash
#!/bin/bash
# scripts/maintenance.sh

set -e

echo "Starting routine maintenance..."

# Database maintenance
echo "Running database maintenance..."
psql "$DATABASE_URL" << EOF
-- Clean up expired tokens
DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '1 day';

-- Clean up expired authorization codes
DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';

-- Update table statistics
VACUUM ANALYZE tokens;
VACUUM ANALYZE authorization_codes;
VACUUM ANALYZE users;
VACUUM ANALYZE clients;

-- Reindex if needed
REINDEX INDEX CONCURRENTLY idx_tokens_expires_at;
REINDEX INDEX CONCURRENTLY idx_auth_codes_expires_at;
EOF

# Application cache cleanup (if Redis enabled)
if [ "$REDIS_ENABLED" = "true" ]; then
    echo "Redis maintenance..."
    redis-cli --scan --pattern "authly:cache:*" | head -1000 | xargs redis-cli del
fi

# Log cleanup
echo "Cleaning up logs..."
find /var/log/authly -name "*.log" -mtime +7 -delete
find /var/log/authly -name "*.log.*" -mtime +30 -delete

# Backup cleanup
echo "Cleaning up old backups..."
find /backups -name "authly_backup_*.sql.gz" -mtime +30 -delete

# Container cleanup
echo "Docker system cleanup..."
docker system prune -f --volumes --filter "until=168h"

echo "Maintenance completed successfully!"
```

## Troubleshooting

### Common Issues and Solutions

#### Service Won't Start

```bash
# Check service status
docker compose ps
kubectl get pods -n authly

# Check service logs
docker compose logs authly
kubectl logs -f deployment/authly-deployment -n authly

# Check resource usage
docker stats
kubectl top pods -n authly
```

#### Database Connection Issues

```bash
# Test database connectivity (Docker)
docker compose exec authly python -c "
import asyncpg
import asyncio
async def test():
    conn = await asyncpg.connect('postgresql://authly:password@postgres:5432/authly')
    print('Database connected!')
    await conn.close()
asyncio.run(test())
"

# Test database connectivity (Kubernetes)
kubectl exec -it deployment/authly-deployment -n authly -- python -c "
import asyncpg
import asyncio
import os
async def test():
    conn = await asyncpg.connect(os.environ['DATABASE_URL'])
    print('Database connected!')
    await conn.close()
asyncio.run(test())
"
```

#### SSL/TLS Issues

```bash
# Test SSL configuration
openssl s_client -connect auth.example.com:443 -servername auth.example.com

# Check certificate validity
openssl x509 -in docker-compose/nginx/ssl/cert.pem -text -noout

# Verify certificate chain
curl -I https://auth.example.com
```

#### Performance Issues

```bash
# Check application metrics
curl http://localhost:8000/metrics

# Database performance analysis
psql "$DATABASE_URL" -c "
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY total_time DESC LIMIT 10;"

# Redis performance
redis-cli info memory
redis-cli slowlog get 10
```

### Monitoring Queries

#### Key Performance Indicators

```promql
# Request rate
sum(rate(authly_http_requests_total[5m]))

# Error rate
sum(rate(authly_http_requests_total{status=~"5.."}[5m])) / sum(rate(authly_http_requests_total[5m]))

# Response time (95th percentile)
histogram_quantile(0.95, rate(authly_http_request_duration_seconds_bucket[5m]))

# Authentication success rate
rate(authly_oauth_token_requests_total{status="success"}[5m]) / rate(authly_oauth_token_requests_total[5m])

# Database connection utilization
authly_database_connections_active / (authly_database_connections_active + authly_database_connections_idle)
```

This comprehensive deployment guide provides everything needed to deploy Authly from development through enterprise production environments, with proper security, monitoring, and operational procedures.