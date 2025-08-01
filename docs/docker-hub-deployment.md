# Docker Hub Deployment Guide

This guide explains how to deploy Authly using pre-built Docker images from Docker Hub instead of building locally.

## Overview

The `docker-compose.hub.yml` configuration pulls the official Authly image from Docker Hub (`descoped/authly`) rather than building from source. This is ideal for:

- **Testing releases** - Test specific versions without building
- **Production deployments** - Use stable, tested images
- **Quick setup** - No build time required
- **CI/CD pipelines** - Consistent image versions across environments

## Quick Start

### 1. Setup Environment

```bash
# Copy the example environment file
cp .env.hub.example .env.hub

# Edit configuration (required)
vi .env.hub
```

### 2. Basic Deployment

```bash
# Start core services (Authly + PostgreSQL + Redis)
docker-compose -f docker-compose.hub.yml up -d

# Check service status
docker-compose -f docker-compose.hub.yml ps

# View logs
docker-compose -f docker-compose.hub.yml logs -f authly
```

### 3. With Admin Tools

```bash
# Start with database admin tools (pgAdmin + Redis Commander)
docker-compose -f docker-compose.hub.yml --profile admin up -d

# Access tools:
# - pgAdmin: http://localhost:5050
# - Redis Commander: http://localhost:8081
```

### 4. With Monitoring

```bash
# Start with monitoring stack (Prometheus + Grafana)
docker-compose -f docker-compose.hub.yml --profile monitoring up -d

# Access monitoring:
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000
```

### 5. Full Stack

```bash
# Start everything
docker-compose -f docker-compose.hub.yml --profile admin --profile monitoring up -d
```

## Image Versions

### Available Tags

The `AUTHLY_VERSION` environment variable controls which image version to use:

```bash
# Latest release (recommended for testing)
AUTHLY_VERSION=latest

# Specific version (recommended for production)
AUTHLY_VERSION=0.5.3

# Minor version (receives patch updates)
AUTHLY_VERSION=0.5

# Major version (receives minor/patch updates)
AUTHLY_VERSION=0
```

### Version Examples

```bash
# Test latest features
AUTHLY_VERSION=latest docker-compose -f docker-compose.hub.yml up -d

# Pin to specific version for production
AUTHLY_VERSION=0.5.3 docker-compose -f docker-compose.hub.yml up -d

# Use minor version for automatic patch updates
AUTHLY_VERSION=0.5 docker-compose -f docker-compose.hub.yml up -d
```

## Configuration

### Environment Variables

Key variables in `.env.hub`:

```bash
# Image version
AUTHLY_VERSION=0.5.3

# Database
POSTGRES_PASSWORD=secure-password

# Redis
REDIS_PASSWORD=secure-redis-password

# JWT secrets (CRITICAL - change in production)
JWT_SECRET_KEY=your-256-bit-secret-key
JWT_REFRESH_SECRET_KEY=your-256-bit-refresh-secret-key

# Admin credentials
AUTHLY_ADMIN_USERNAME=admin
AUTHLY_ADMIN_PASSWORD=secure-admin-password
```

### Redis Features

Enable optional Redis features:

```bash
# Distributed rate limiting (recommended for multi-instance)
AUTHLY_REDIS_RATE_LIMIT=true

# High-performance caching (recommended)
AUTHLY_REDIS_CACHE=true

# Redis-based sessions (optional - defaults to database)
AUTHLY_REDIS_SESSION=false
```

## Service Access

| Service | URL | Purpose |
|---------|-----|---------|
| Authly | http://localhost:8000 | OAuth 2.1 + OIDC server |
| pgAdmin | http://localhost:5050 | Database administration |
| Redis Commander | http://localhost:8081 | Redis management |
| Prometheus | http://localhost:9090 | Metrics collection |
| Grafana | http://localhost:3000 | Monitoring dashboards |

## API Testing

### OAuth 2.1 Endpoints

```bash
# Health check
curl http://localhost:8000/health

# OAuth discovery
curl http://localhost:8000/.well-known/oauth-authorization-server

# OIDC discovery
curl http://localhost:8000/.well-known/openid_configuration

# JWKS endpoint
curl http://localhost:8000/.well-known/jwks.json
```

### Admin CLI

```bash
# Login to CLI
docker-compose -f docker-compose.hub.yml exec authly authly admin login

# Create OAuth client
docker-compose -f docker-compose.hub.yml exec authly authly admin client create \
  --name "Test App" \
  --client-type public \
  --redirect-uri "http://localhost:3000/callback"

# List clients
docker-compose -f docker-compose.hub.yml exec authly authly admin client list
```

## Production Considerations

### Security

1. **Change default passwords**:
   ```bash
   # Generate secure passwords
   POSTGRES_PASSWORD=$(openssl rand -base64 32)
   REDIS_PASSWORD=$(openssl rand -base64 32)
   JWT_SECRET_KEY=$(openssl rand -base64 32)
   JWT_REFRESH_SECRET_KEY=$(openssl rand -base64 32)
   AUTHLY_ADMIN_PASSWORD=$(openssl rand -base64 16)
   ```

2. **Use specific image versions**:
   ```bash
   # Pin to specific version, not 'latest'
   AUTHLY_VERSION=0.5.3
   ```

3. **Configure proper URLs**:
   ```bash
   DEFAULT_API_URL=https://auth.yourdomain.com
   DEFAULT_ISSUER_URL=https://auth.yourdomain.com
   ```

### Networking

For production, consider:

1. **Remove port exposure** for database services
2. **Add reverse proxy** (nginx) with SSL termination
3. **Use Docker secrets** for sensitive data
4. **Configure firewall rules** appropriately

### Monitoring

Enable monitoring profile for production:

```bash
# Start with monitoring
docker-compose -f docker-compose.hub.yml --profile monitoring up -d

# Configure Grafana dashboards for:
# - Request rates and response times
# - Error rates and authentication metrics
# - Database and Redis performance
# - System resource usage
```

## Troubleshooting

### Common Issues

1. **Image pull fails**:
   ```bash
   # Check image exists
   docker pull descoped/authly:0.5.3
   
   # Check available tags
   curl -s https://registry.hub.docker.com/v2/repositories/descoped/authly/tags/ | jq
   ```

2. **Database connection issues**:
   ```bash
   # Check PostgreSQL health
   docker-compose -f docker-compose.hub.yml exec postgres pg_isready -U authly -d authly
   
   # Check database logs
   docker-compose -f docker-compose.hub.yml logs postgres
   ```

3. **Redis connection issues**:
   ```bash
   # Check Redis connectivity
   docker-compose -f docker-compose.hub.yml exec redis redis-cli -a redis_dev_password ping
   
   # Check Redis logs
   docker-compose -f docker-compose.hub.yml logs redis
   ```

4. **Application startup issues**:
   ```bash
   # Check Authly logs
   docker-compose -f docker-compose.hub.yml logs -f authly
   
   # Check health endpoint
   curl -f http://localhost:8000/health
   ```

### Version Compatibility

| Authly Version | Minimum PostgreSQL | Minimum Redis | Notes |
|----------------|-------------------|---------------|-------|
| 0.5.x | PostgreSQL 13+ | Redis 6+ | Current stable |
| 0.6.x+ | PostgreSQL 15+ | Redis 7+ | Future releases |

### Performance Tuning

For high-traffic deployments:

```bash
# Increase rate limits
RATE_LIMIT_MAX_REQUESTS=1000
RATE_LIMIT_WINDOW_SECONDS=60

# Enable Redis caching
AUTHLY_REDIS_CACHE=true
AUTHLY_REDIS_RATE_LIMIT=true

# Adjust token expiration
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=30
```

## Integration with Source Development

You can use both deployment methods simultaneously:

```bash
# Source development (port 8000)
docker-compose up -d

# Docker Hub testing (port 8001)
AUTHLY_PORT=8001 docker-compose -f docker-compose.hub.yml up -d
```

This allows you to:
- Develop with source code on port 8000
- Test releases from Docker Hub on port 8001
- Compare behavior between versions
- Validate before deploying to production

## Cleanup

```bash
# Stop services
docker-compose -f docker-compose.hub.yml down

# Remove volumes (WARNING: deletes data)  
docker-compose -f docker-compose.hub.yml down -v

# Remove images
docker-compose -f docker-compose.hub.yml down --rmi all
```