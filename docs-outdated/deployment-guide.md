# Production Deployment Guide

This comprehensive guide covers production deployment of Authly with OAuth 2.1 compliance, including infrastructure setup, security configuration, monitoring, and operational procedures.

## 🎯 Deployment Overview

Authly is designed for enterprise production deployment with:

- **OAuth 2.1 Authorization Server** - Full RFC compliance with PKCE, discovery, and token revocation
- **High-Performance Architecture** - Async FastAPI with PostgreSQL and connection pooling
- **Enterprise Security** - JWT tokens, bcrypt password hashing, and comprehensive rate limiting
- **Production Monitoring** - Health checks, metrics, and comprehensive logging
- **Scalable Design** - Horizontal scaling with load balancing and database clustering

## 🏗️ Infrastructure Requirements

### Minimum Production Requirements

**Application Servers (per instance):**
- **CPU**: 4 cores (8 threads)
- **Memory**: 8GB RAM
- **Storage**: 50GB SSD
- **Network**: 1Gbps connection

**Database Server:**
- **CPU**: 8 cores (16 threads)
- **Memory**: 16GB RAM (min), 32GB recommended
- **Storage**: 500GB SSD with high IOPS
- **Network**: 10Gbps connection for high throughput

**Load Balancer:**
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Network**: 10Gbps connection
- **SSL Termination**: Hardware or software SSL acceleration

### Recommended Production Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────┐
│           Load Balancer                 │
│         (Nginx/HAProxy)                 │
│     SSL Termination & Caching          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│        Application Tier                 │
│  ┌─────────────┬─────────────────────┐  │
│  │ Authly-1    │    Authly-2         │  │
│  │ (Primary)   │    (Secondary)      │  │
│  └─────────────┴─────────────────────┘  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│          Database Tier                  │
│  ┌─────────────┬─────────────────────┐  │
│  │ PostgreSQL  │   PostgreSQL        │  │
│  │ Primary     │   Read Replica      │  │
│  └─────────────┴─────────────────────┘  │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│        Supporting Services              │
│  ┌─────────────┬─────────────────────┐  │
│  │ Redis       │   Monitoring        │  │
│  │ (Optional)  │   (Prometheus)      │  │
│  └─────────────┴─────────────────────┘  │
└─────────────────────────────────────────┘
```

## 🐳 Docker Deployment

### Production Dockerfile

```dockerfile
# Multi-stage build for optimized production image
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.6.1

# Configure Poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Copy dependency files
WORKDIR /app
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --only=main && rm -rf $POETRY_CACHE_DIR

# Production stage
FROM python:3.11-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r authly && useradd -r -g authly authly

# Copy virtual environment
ENV VIRTUAL_ENV=/app/.venv
COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy application code
WORKDIR /app
COPY . .
RUN chown -R authly:authly /app

# Switch to non-root user
USER authly

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UVLOOP_ENABLED=1

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "authly.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Docker Compose for Production

```yaml
version: '3.8'

services:
  authly:
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://authly_user:${DB_PASSWORD}@postgres:5432/authly_prod
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - JWT_REFRESH_SECRET_KEY=${JWT_REFRESH_SECRET_KEY}
      - ENVIRONMENT=production
      - LOG_LEVEL=info
      - CORS_ORIGINS=https://app.example.com,https://admin.example.com
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - authly_network
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=authly_prod
      - POSTGRES_USER=authly_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
      - ./sql/indexes.sql:/docker-entrypoint-initdb.d/02-indexes.sql
    ports:
      - "5432:5432"
    networks:
      - authly_network
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authly_user -d authly_prod"]
      interval: 10s
      timeout: 5s
      retries: 5
    command: >
      postgres
      -c shared_buffers=2GB
      -c effective_cache_size=6GB
      -c maintenance_work_mem=512MB
      -c checkpoint_completion_target=0.9
      -c wal_buffers=16MB
      -c default_statistics_target=100
      -c random_page_cost=1.1
      -c effective_io_concurrency=200
      -c work_mem=64MB
      -c min_wal_size=1GB
      -c max_wal_size=4GB

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - authly
    networks:
      - authly_network
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - authly_network
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru

volumes:
  postgres_data:
  redis_data:

networks:
  authly_network:
    driver: bridge
```

### Environment Configuration

```bash
# .env.production
# Database Configuration
DATABASE_URL=postgresql://authly_user:${DB_PASSWORD}@postgres:5432/authly_prod
DB_PASSWORD=your_secure_db_password_here

# JWT Configuration
JWT_SECRET_KEY=your_jwt_secret_key_32_chars_min
JWT_REFRESH_SECRET_KEY=your_refresh_secret_key_32_chars_min
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# OAuth 2.1 Configuration
OAUTH_ENABLED=true
AUTHORIZATION_CODE_EXPIRE_MINUTES=10
PKCE_REQUIRED=true
REQUIRE_USER_CONSENT=true

# Security Configuration
CORS_ORIGINS=https://app.example.com,https://admin.example.com
ALLOWED_HOSTS=auth.example.com,api.example.com
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# Application Configuration
ENVIRONMENT=production
LOG_LEVEL=info
DEBUG=false

# Email Configuration (for user verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=noreply@example.com
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_EMAIL=noreply@example.com

# Monitoring Configuration
METRICS_ENABLED=true
HEALTH_CHECK_ENABLED=true

# Cache Configuration (Redis)
REDIS_URL=redis://redis:6379/0
CACHE_TTL=300
```

## ☸️ Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: authly
  labels:
    name: authly

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
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_REQUESTS_PER_MINUTE: "100"
  ACCESS_TOKEN_EXPIRE_MINUTES: "30"
  REFRESH_TOKEN_EXPIRE_DAYS: "7"
  AUTHORIZATION_CODE_EXPIRE_MINUTES: "10"
  CORS_ORIGINS: "https://app.example.com,https://admin.example.com"
  ALLOWED_HOSTS: "auth.example.com,api.example.com"
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
  # Base64 encoded values
  DATABASE_URL: cG9zdGdyZXNxbDovL2F1dGhseV91c2VyOnBhc3N3b3JkQHBvc3RncmVzOjU0MzIvYXV0aGx5X3Byb2Q=
  JWT_SECRET_KEY: eW91cl9qd3Rfc2VjcmV0X2tleV8zMl9jaGFyc19taW4=
  JWT_REFRESH_SECRET_KEY: eW91cl9yZWZyZXNoX3NlY3JldF9rZXlfMzJfY2hhcnNfbWlu
  SMTP_PASSWORD: eW91cl9zbXRwX3Bhc3N3b3Jk
  REDIS_URL: cmVkaXM6Ly9yZWRpcy1zZXJ2aWNlOjYzNzkvMA==
```

### Deployment Configuration

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authly-deployment
  namespace: authly
  labels:
    app: authly
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
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: authly
        image: authly:latest
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
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
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
      storage: 500Gi
  storageClassName: ssd

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-deployment
  namespace: authly
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
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: authly_prod
        - name: POSTGRES_USER
          value: authly_user
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
            memory: "4Gi"
            cpu: "2000m"
          limits:
            memory: "8Gi"
            cpu: "4000m"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - authly_user
            - -d
            - authly_prod
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - authly_user
            - -d
            - authly_prod
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
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

## 🔧 Database Setup and Migration

### Initial Database Schema

```sql
-- sql/schema.sql
-- Core users table
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT false,
    is_admin BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth clients table
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255), -- NULL for public clients
    client_type VARCHAR(20) NOT NULL, -- 'confidential' or 'public'
    redirect_uris TEXT[] NOT NULL,
    client_uri VARCHAR(255),
    logo_uri VARCHAR(255),
    auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
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

-- Enhanced tokens table
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    token_type VARCHAR(20) NOT NULL, -- 'access', 'refresh'
    scopes TEXT[], -- Granted scopes for OAuth tokens
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    invalidated BOOLEAN DEFAULT false,
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
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Performance Indexes

```sql
-- sql/indexes.sql
-- Core user indexes
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY idx_users_verified ON users(is_verified);

-- OAuth client indexes
CREATE INDEX CONCURRENTLY idx_clients_client_id ON clients(client_id);
CREATE INDEX CONCURRENTLY idx_clients_active ON clients(is_active);

-- Scope indexes
CREATE INDEX CONCURRENTLY idx_scopes_name ON scopes(scope_name);
CREATE INDEX CONCURRENTLY idx_scopes_active ON scopes(is_active);
CREATE INDEX CONCURRENTLY idx_scopes_default ON scopes(is_default);

-- Association indexes
CREATE INDEX CONCURRENTLY idx_client_scopes_client_id ON client_scopes(client_id);
CREATE INDEX CONCURRENTLY idx_client_scopes_scope_id ON client_scopes(scope_id);

-- Token indexes
CREATE INDEX CONCURRENTLY idx_tokens_jti ON tokens(jti);
CREATE INDEX CONCURRENTLY idx_tokens_user_id ON tokens(user_id);
CREATE INDEX CONCURRENTLY idx_tokens_client_id ON tokens(client_id);
CREATE INDEX CONCURRENTLY idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX CONCURRENTLY idx_tokens_user_type_active ON tokens(user_id, token_type) WHERE invalidated = false;

-- Authorization code indexes
CREATE INDEX CONCURRENTLY idx_authorization_codes_code ON authorization_codes(code);
CREATE INDEX CONCURRENTLY idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX CONCURRENTLY idx_authorization_codes_client_id ON authorization_codes(client_id);
CREATE INDEX CONCURRENTLY idx_authorization_codes_user_id ON authorization_codes(user_id);
```

### Database Migration Script

```bash
#!/bin/bash
# scripts/migrate_database.sh

set -e

DB_URL="${DATABASE_URL:-postgresql://authly_user:password@localhost:5432/authly_prod}"

echo "Starting database migration..."

# Check database connectivity
psql "$DB_URL" -c "SELECT version();" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Cannot connect to database"
    exit 1
fi

# Apply schema
echo "Applying database schema..."
psql "$DB_URL" -f sql/schema.sql

# Apply indexes
echo "Creating performance indexes..."
psql "$DB_URL" -f sql/indexes.sql

# Insert default scopes
echo "Creating default OAuth scopes..."
psql "$DB_URL" << EOF
INSERT INTO scopes (scope_name, description, is_default, is_active) VALUES
('read', 'Read access to user data', true, true),
('write', 'Write access to user data', false, true),
('profile', 'Access to user profile information', true, true),
('admin', 'Administrative access', false, true)
ON CONFLICT (scope_name) DO NOTHING;
EOF

# Create admin user if specified
if [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
    echo "Creating admin user..."
    python -c "
import asyncio
import bcrypt
import sys
from authly.database import get_connection_pool
from authly.users.repositories import UserRepository

async def create_admin():
    pool = await get_connection_pool('$DB_URL')
    async with pool.connection() as conn:
        repo = UserRepository(conn)
        password_hash = bcrypt.hashpw('$ADMIN_PASSWORD'.encode(), bcrypt.gensalt()).decode()
        
        try:
            await repo.create({
                'email': '$ADMIN_EMAIL',
                'username': '$ADMIN_EMAIL',
                'password_hash': password_hash,
                'is_verified': True,
                'is_admin': True
            })
            print('Admin user created successfully')
        except Exception as e:
            print(f'Admin user already exists or error: {e}')
    
    await pool.close()

asyncio.run(create_admin())
"
fi

echo "Database migration completed successfully!"
```

## 🔐 Security Configuration

### SSL/TLS Configuration

```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
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
    keepalive_timeout 75s;
    types_hash_max_size 2048;
    client_max_body_size 1M;
    
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
        
        ssl_certificate /etc/nginx/ssl/auth.example.com.crt;
        ssl_certificate_key /etc/nginx/ssl/auth.example.com.key;
        
        # OAuth authorization endpoints (rate limited)
        location ~ ^/(authorize|auth/token|auth/refresh) {
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
        }
        
        # Discovery endpoint (cached)
        location /.well-known/oauth-authorization-server {
            proxy_pass http://authly_backend;
            proxy_cache_valid 200 1h;
            add_header Cache-Control "public, max-age=3600";
            expires 1h;
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
        
        # Health check (no rate limiting)
        location /health {
            proxy_pass http://authly_backend;
            access_log off;
        }
        
        # Admin endpoints (restricted access)
        location /admin {
            allow 10.0.0.0/8;      # Internal network
            allow 172.16.0.0/12;   # Docker networks
            allow 192.168.0.0/16;  # Private networks
            deny all;
            
            proxy_pass http://authly_backend;
            proxy_http_version 1.1;
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
# scripts/configure_firewall.sh
#!/bin/bash

# Configure UFW firewall for production Authly deployment

# Reset firewall
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# SSH access (adjust port as needed)
ufw allow 22/tcp

# HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Database access (only from application servers)
ufw allow from 10.0.1.0/24 to any port 5432

# Redis access (only from application servers)
ufw allow from 10.0.1.0/24 to any port 6379

# Monitoring
ufw allow from 10.0.2.0/24 to any port 9090  # Prometheus
ufw allow from 10.0.2.0/24 to any port 3000  # Grafana

# Enable firewall
ufw --force enable

# Show status
ufw status verbose
```

## 📊 Monitoring and Logging

### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "authly_rules.yml"

scrape_configs:
  - job_name: 'authly'
    static_configs:
      - targets: ['authly-service:8000']
    metrics_path: /metrics
    scrape_interval: 30s
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Authly OAuth 2.1 Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(authly_requests_total[5m])",
            "legendFormat": "{{endpoint}} - {{method}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(authly_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "authly_db_connections_active",
            "legendFormat": "Active Connections"
          }
        ]
      },
      {
        "title": "OAuth Operations",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(authly_oauth_authorizations_total[5m])",
            "legendFormat": "{{result}}"
          }
        ]
      }
    ]
  }
}
```

### Application Logging

```python
# authly/logging_config.py
import logging
import sys
from pythonjsonlogger import jsonlogger

def configure_logging(log_level: str = "INFO", environment: str = "production"):
    """Configure structured logging for production."""
    
    # Create custom formatter
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(name)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Configure specific loggers
    loggers_config = {
        'authly': log_level.upper(),
        'uvicorn': 'INFO',
        'uvicorn.access': 'INFO' if environment == 'development' else 'WARNING',
        'psycopg': 'WARNING',
        'sqlalchemy': 'WARNING'
    }
    
    for logger_name, level in loggers_config.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level))
        logger.propagate = True

# Usage in main application
configure_logging(
    log_level=os.getenv("LOG_LEVEL", "INFO"),
    environment=os.getenv("ENVIRONMENT", "production")
)
```

## 🚀 Deployment Procedures

### Automated Deployment Script

```bash
#!/bin/bash
# scripts/deploy_production.sh

set -e

# Configuration
ENVIRONMENT=${ENVIRONMENT:-production}
VERSION=${VERSION:-latest}
NAMESPACE=${NAMESPACE:-authly}

echo "Starting Authly production deployment..."
echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"
echo "Namespace: $NAMESPACE"

# Pre-deployment checks
echo "Running pre-deployment checks..."

# Check Kubernetes connectivity
kubectl cluster-info > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Cannot connect to Kubernetes cluster"
    exit 1
fi

# Check if namespace exists
kubectl get namespace $NAMESPACE > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Creating namespace $NAMESPACE..."
    kubectl create namespace $NAMESPACE
fi

# Validate configuration
echo "Validating Kubernetes configurations..."
kubectl apply --dry-run=client -f k8s/ > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Invalid Kubernetes configuration"
    exit 1
fi

# Database migration
echo "Running database migrations..."
kubectl apply -f k8s/migration-job.yaml
kubectl wait --for=condition=complete job/database-migration -n $NAMESPACE --timeout=300s

# Deploy application
echo "Deploying application..."

# Apply configurations
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml

# Deploy database (if not external)
if [ "$DATABASE_EXTERNAL" != "true" ]; then
    kubectl apply -f k8s/postgres.yaml
    kubectl wait --for=condition=available deployment/postgres-deployment -n $NAMESPACE --timeout=300s
fi

# Deploy Redis (if enabled)
if [ "$REDIS_ENABLED" = "true" ]; then
    kubectl apply -f k8s/redis.yaml
    kubectl wait --for=condition=available deployment/redis-deployment -n $NAMESPACE --timeout=300s
fi

# Deploy main application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Wait for deployment to be ready
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
echo "Application is available at: https://auth.example.com"
echo "Ingress IP: $INGRESS_IP"
```

### Post-Deployment Testing

```bash
#!/bin/bash
# scripts/post_deployment_tests.sh

set -e

BASE_URL=${BASE_URL:-https://auth.example.com}
TIMEOUT=30

echo "Running post-deployment tests for $BASE_URL..."

# Test 1: Health check
echo "Testing health endpoint..."
curl -f -s --max-time $TIMEOUT "$BASE_URL/health" > /dev/null
if [ $? -eq 0 ]; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi

# Test 2: OAuth discovery endpoint
echo "Testing OAuth discovery endpoint..."
DISCOVERY_RESPONSE=$(curl -f -s --max-time $TIMEOUT "$BASE_URL/.well-known/oauth-authorization-server")
if echo "$DISCOVERY_RESPONSE" | jq -e '.authorization_endpoint' > /dev/null 2>&1; then
    echo "✓ OAuth discovery endpoint working"
else
    echo "✗ OAuth discovery endpoint failed"
    exit 1
fi

# Test 3: Authorization endpoint (GET)
echo "Testing authorization endpoint..."
AUTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT \
    "$BASE_URL/authorize?response_type=code&client_id=test&redirect_uri=https://test.com/callback&code_challenge=test&code_challenge_method=S256")
if [ "$AUTH_RESPONSE" = "400" ] || [ "$AUTH_RESPONSE" = "200" ]; then
    echo "✓ Authorization endpoint responding"
else
    echo "✗ Authorization endpoint failed (HTTP $AUTH_RESPONSE)"
    exit 1
fi

# Test 4: Database connectivity (via admin CLI if available)
if command -v authly-admin > /dev/null 2>&1; then
    echo "Testing database connectivity..."
    authly-admin status > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ Database connectivity verified"
    else
        echo "✗ Database connectivity failed"
        exit 1
    fi
fi

# Test 5: SSL certificate
echo "Testing SSL certificate..."
SSL_CHECK=$(echo | openssl s_client -servername auth.example.com -connect auth.example.com:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
if [ -n "$SSL_CHECK" ]; then
    echo "✓ SSL certificate valid"
else
    echo "✗ SSL certificate check failed"
    exit 1
fi

echo "All post-deployment tests passed successfully!"
```

## 🔄 Backup and Recovery

### Database Backup Script

```bash
#!/bin/bash
# scripts/backup_database.sh

set -e

# Configuration
BACKUP_DIR=${BACKUP_DIR:-/backups}
RETENTION_DAYS=${RETENTION_DAYS:-30}
S3_BUCKET=${S3_BUCKET:-authly-backups}

# Create backup directory
mkdir -p $BACKUP_DIR

# Generate backup filename
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
    
    # Upload to S3 (if configured)
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

### Disaster Recovery Procedures

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

## 🔍 Maintenance Procedures

### Routine Maintenance Script

```bash
#!/bin/bash
# scripts/maintenance.sh

set -e

echo "Starting routine maintenance..."

# Database maintenance
echo "Running database maintenance..."

# Clean up expired tokens
psql "$DATABASE_URL" << EOF
DELETE FROM tokens WHERE expires_at < NOW() - INTERVAL '1 day';
DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour';
VACUUM ANALYZE tokens;
VACUUM ANALYZE authorization_codes;
EOF

# Update statistics
psql "$DATABASE_URL" -c "ANALYZE;"

# Log cleanup
echo "Cleaning up logs..."
find /var/log/authly -name "*.log" -mtime +7 -delete
find /var/log/authly -name "*.log.*" -mtime +30 -delete

# Backup cleanup
echo "Cleaning up old backups..."
find /backups -name "authly_backup_*.sql.gz" -mtime +30 -delete

# Security updates
echo "Checking for security updates..."
apt update && apt upgrade -y

echo "Maintenance completed successfully!"
```

This deployment guide provides a comprehensive foundation for production deployment of Authly with OAuth 2.1 compliance, ensuring security, scalability, and operational excellence.