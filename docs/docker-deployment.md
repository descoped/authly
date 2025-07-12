# Docker Deployment Guide

Complete lifecycle management guide for Authly's Docker infrastructure.

## 🎯 Infrastructure Lifecycle Management

### What to Check Into Version Control

**✅ INCLUDE:**
- All Docker Compose files (`docker-compose*.yml`)
- Infrastructure configurations (`docker-compose/` directory)
  - Nginx configurations (`docker-compose/nginx/*.conf`)
  - Monitoring configs (`docker-compose/prometheus/`, `docker-compose/grafana/`)
  - Log aggregation (`docker-compose/fluentd/`)
  - Development tools (`docker-compose/pgadmin/`)
- Database initialization scripts (`docker/init-db-and-user.sql`)
- Environment templates (`.env.example`)
- SSL directory structure (`docker-compose/nginx/ssl/README.md`)

**❌ NEVER INCLUDE:**
- SSL certificates and private keys (`docker-compose/nginx/ssl/*.pem`, `*.key`, `*.crt`)
- Environment files with secrets (`.env`, `.env.dev`)
- Docker volumes and persistent data

### Certificate Lifecycle

**Development:**
- Generate self-signed certificates on-demand
- Include certificate generation in setup scripts
- Certificates expire after 1 year (suitable for development)

**Production:**
- Use Let's Encrypt for automatic certificate management
- Implement certificate renewal automation
- Store certificates outside the repository

### SSL Certificate Setup

**For Development:**
```bash
# Run the provided script (automatically creates self-signed certificates)
./scripts/setup-dev-certs.sh
```

**For Production:**
```bash
# Option 1: Let's Encrypt (Recommended)
sudo certbot certonly --standalone -d auth.yourdomain.com
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem docker-compose/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem docker-compose/nginx/ssl/key.pem

# Option 2: Custom certificates
# Place your certificates in docker-compose/nginx/ssl/
cp your-cert.pem docker-compose/nginx/ssl/cert.pem
cp your-key.pem docker-compose/nginx/ssl/key.pem
```

## 🚀 Quick Start

### **Development Environment**

```bash
# Clone and setup
git clone <repository-url>
cd authly

# Generate SSL certificates for development
./scripts/setup-dev-certs.sh

# Start development environment
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Access services
# - Authly API: http://localhost:8000
# - pgAdmin: http://localhost:5050 (admin@authly.dev / admin)
# - Redis Commander: http://localhost:8081 (admin / admin)
# - Mailhog: http://localhost:8025
```

### **Production Environment**

```bash
# Setup environment
cp .env.example .env
# Edit .env with production values

# Create Docker secrets
echo "your_postgres_password" | docker secret create postgres_password -
echo "your_redis_password" | docker secret create redis_password -
echo "your_jwt_secret" | docker secret create jwt_secret_key -
echo "your_jwt_refresh_secret" | docker secret create jwt_refresh_secret_key -

# Deploy with monitoring
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile production --profile monitoring up -d
```

---

## 📋 Architecture Overview

### **Services Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Nginx       │────│     Authly      │────│   PostgreSQL    │
│  Reverse Proxy  │    │   Application   │    │    Database     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │      Redis      │              │
         └──────────────│      Cache      │──────────────┘
                        └─────────────────┘
                                 │
                   ┌─────────────────────────────┐
                   │       Monitoring Stack      │
                   │  Prometheus + Grafana       │
                   └─────────────────────────────┘
```

### **Docker Compose Files**

- **`docker-compose.yml`** - Base configuration with core services
- **`docker-compose.dev.yml`** - Development overrides with debugging tools
- **`docker-compose.prod.yml`** - Production overrides with security and monitoring

---

## 🔧 Services Configuration

### **Core Services**

#### **Authly Application**
- **Image**: Built from Dockerfile (UV-based)
- **Port**: 8000
- **Environment**: Full configuration via environment variables
- **Health Check**: `/health` endpoint
- **Resources**: Configurable CPU/memory limits

#### **PostgreSQL Database**
- **Image**: postgres:16-alpine
- **Port**: 5432 (development) / internal (production)
- **Storage**: Named volumes with persistence
- **Initialization**: Automatic schema setup via init scripts
- **Health Check**: pg_isready

#### **Redis Cache**
- **Image**: redis:7-alpine
- **Port**: 6379 (development) / internal (production)  
- **Storage**: Named volumes with persistence
- **Security**: Password-protected
- **Health Check**: PING command

#### **Nginx Reverse Proxy**
- **Image**: nginx:alpine
- **Ports**: 80/443
- **Configuration**: OAuth-optimized with rate limiting
- **SSL**: Production SSL/TLS termination
- **Features**: Gzip, security headers, rate limiting

### **Development Tools**

#### **pgAdmin (Database Admin)**
- **Image**: dpage/pgadmin4
- **Port**: 5050
- **Access**: admin@authly.dev / admin
- **Features**: Pre-configured server connection

#### **Redis Commander (Redis Admin)**
- **Image**: rediscommander/redis-commander
- **Port**: 8081
- **Access**: admin / admin
- **Features**: Redis database management

#### **Mailhog (Email Testing)**
- **Image**: mailhog/mailhog
- **Ports**: 1025 (SMTP) / 8025 (Web UI)
- **Features**: Email capture and testing

### **Monitoring Stack**

#### **Prometheus (Metrics)**
- **Image**: prom/prometheus
- **Port**: 9090
- **Configuration**: Pre-configured scrape targets
- **Storage**: Named volumes with persistence

#### **Grafana (Dashboards)**
- **Image**: grafana/grafana
- **Port**: 3000
- **Configuration**: Auto-provisioned datasources
- **Storage**: Named volumes with persistence

---

## 🌍 Environment Configuration

### **Environment Files**

#### **`.env.example`** - Template for production
```bash
# Copy and customize
cp .env.example .env
```

#### **`.env.dev`** - Development defaults
```bash
# Included in development compose
# Contains insecure defaults for development
```

### **Key Environment Variables**

#### **Database Configuration**
```bash
POSTGRES_PASSWORD=your_secure_password
DATABASE_URL=postgresql://authly:password@postgres:5432/authly
```

#### **JWT Configuration**
```bash
JWT_SECRET_KEY=your-256-bit-secret-key
JWT_REFRESH_SECRET_KEY=your-256-bit-refresh-secret
JWT_ALGORITHM=HS256
```

#### **API Configuration**
```bash
DEFAULT_API_URL=https://auth.yourdomain.com
DEFAULT_ISSUER_URL=https://auth.yourdomain.com
AUTHLY_PORT=8000
```

#### **Security Settings**
```bash
AUTHLY_BOOTSTRAP_DEV_MODE=false
AUTHLY_DEV_MODE=false
AUTHLY_LOG_LEVEL=INFO
RATE_LIMIT_MAX_REQUESTS=100
```

---

## 🚀 Deployment Scenarios

### **Development Deployment**

```bash
# Full development stack with tools
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Check service status
docker compose ps

# View logs
docker compose logs -f authly

# Access development tools
open http://localhost:5050  # pgAdmin
open http://localhost:8081  # Redis Commander
open http://localhost:8025  # Mailhog
```

**Development Features:**
- Hot code reloading (source mounted)
- Debug logging enabled
- Relaxed rate limiting
- Development admin tools
- Insecure defaults for convenience

### **Production Deployment**

```bash
# 1. Setup environment
cp .env.example .env
vim .env  # Configure production values

# 2. Create Docker secrets (recommended for production)
echo "$(openssl rand -base64 32)" | docker secret create postgres_password -
echo "$(openssl rand -base64 32)" | docker secret create redis_password -
echo "$(openssl rand -base64 32)" | docker secret create jwt_secret_key -
echo "$(openssl rand -base64 32)" | docker secret create jwt_refresh_secret_key -

# 3. Deploy production stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 4. Deploy with monitoring (optional)
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile production --profile monitoring up -d
```

**Production Features:**
- SSL/TLS termination with Nginx
- Docker secrets for sensitive data
- Stricter rate limiting
- Resource limits and scaling
- Log aggregation with Fluentd
- Admin endpoints blocked
- Health checks and restart policies

### **Monitoring-Only Deployment**

```bash
# Add monitoring to existing deployment
docker compose -f docker-compose.yml --profile monitoring up -d

# Access monitoring
open http://localhost:9090  # Prometheus
open http://localhost:3000  # Grafana (admin/admin)
```

---

## 🔒 Security Configuration

### **Production Security Checklist**

#### **1. Secrets Management**
- ✅ Use Docker secrets for sensitive data
- ✅ Never commit secrets to version control
- ✅ Rotate secrets regularly
- ✅ Use secure random generation

```bash
# Generate secure secrets
openssl rand -base64 32  # For passwords
openssl rand -hex 32     # For tokens
```

#### **2. Network Security**
- ✅ Internal network isolation
- ✅ No exposed ports for internal services
- ✅ SSL/TLS for external communication
- ✅ Rate limiting with Nginx

#### **3. Container Security**
- ✅ Non-root user in containers
- ✅ Read-only filesystems where possible
- ✅ Resource limits configured
- ✅ Security updates via base image updates

#### **4. SSL/TLS Configuration**
```bash
# Generate SSL certificates (production)
# Place in docker/nginx/ssl/
cp your-cert.pem docker/nginx/ssl/cert.pem
cp your-key.pem docker/nginx/ssl/key.pem

# Or use Let's Encrypt with certbot
docker run -it --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v /var/lib/letsencrypt:/var/lib/letsencrypt \
  certbot/certbot certonly --standalone -d auth.yourdomain.com
```

---

## 📊 Monitoring and Observability

### **Metrics Collection**

#### **Application Metrics**
- OAuth/OIDC flow success/failure rates
- Token generation and validation metrics
- API endpoint response times
- Database connection pool status

#### **Infrastructure Metrics**
- Container resource usage (CPU, memory)
- Database performance (connections, queries)
- Redis performance (memory, commands)
- Nginx metrics (requests, errors)

### **Log Aggregation**

#### **Fluentd Configuration**
- Centralized log collection
- JSON structured logging
- Service tagging and enrichment
- External log shipping (Elasticsearch, etc.)

### **Alerting Setup**

```yaml
# Example Prometheus alert rules
groups:
  - name: authly_alerts
    rules:
      - alert: AuthlyHighErrorRate
        expr: rate(authly_http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          
      - alert: AuthlyDatabaseDown
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection lost"
```

---

## 🛠️ Operations and Maintenance

### **Health Checks**

```bash
# Check all services
docker compose ps

# Application health
curl http://localhost:8000/health

# Database health
docker compose exec postgres pg_isready -U authly

# Redis health
docker compose exec redis redis-cli ping
```

### **Log Management**

```bash
# View application logs
docker compose logs -f authly

# View all service logs
docker compose logs

# Log rotation (production)
docker compose exec authly logrotate /etc/logrotate.conf
```

### **Backup Procedures**

#### **Database Backup**
```bash
# Create backup
docker compose exec postgres pg_dump -U authly authly > backup.sql

# Restore backup
docker compose exec -T postgres psql -U authly authly < backup.sql
```

#### **Volume Backup**
```bash
# Backup all volumes
docker run --rm -v authly_postgres_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres_backup.tar.gz -C /data .
```

### **Scaling Configuration**

#### **Horizontal Scaling**
```yaml
# docker-compose.override.yml
services:
  authly:
    deploy:
      replicas: 3
    ports:
      - "8000-8002:8000"
```

#### **Load Balancer Configuration**
```nginx
# nginx upstream with multiple backends
upstream authly_backend {
    server authly_1:8000;
    server authly_2:8000;
    server authly_3:8000;
}
```

---

## 🐛 Troubleshooting

### **Common Issues**

#### **Service Won't Start**
```bash
# Check service status
docker compose ps

# Check service logs
docker compose logs service_name

# Check resource usage
docker stats
```

#### **Database Connection Issues**
```bash
# Test database connectivity
docker compose exec authly python -c "
import asyncpg
import asyncio
async def test():
    conn = await asyncpg.connect('postgresql://authly:password@postgres:5432/authly')
    print('Database connected!')
    await conn.close()
asyncio.run(test())
"
```

#### **SSL/TLS Issues**
```bash
# Test SSL configuration
openssl s_client -connect auth.yourdomain.com:443 -servername auth.yourdomain.com

# Check certificate validity
openssl x509 -in docker/nginx/ssl/cert.pem -text -noout
```

### **Performance Tuning**

#### **Database Optimization**
```sql
-- PostgreSQL performance queries
SELECT * FROM pg_stat_activity;
SELECT * FROM pg_stat_database;
```

#### **Redis Optimization**
```bash
# Redis memory usage
docker compose exec redis redis-cli info memory

# Redis slow log
docker compose exec redis redis-cli slowlog get 10
```

---

## 📚 Additional Resources

### **Docker Commands Reference**

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# Rebuild images
docker compose build

# Scale services
docker compose up -d --scale authly=3

# Update services
docker compose pull && docker compose up -d

# Clean up
docker compose down -v --remove-orphans
docker system prune -a
```

### **Environment Management**

```bash
# Development environment
export COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml

# Production environment
export COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml

# Use environment-specific commands
docker compose up -d
```

This comprehensive Docker deployment setup provides production-ready infrastructure for Authly with proper security, monitoring, and operational capabilities.