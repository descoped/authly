# Authly Docker Deployment

This directory contains Docker-related files for the Authly OAuth 2.1 + OIDC authorization server.

## 🐳 **Quick Start**

### Development
```bash
# Start development environment with database admin tools
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Access services:
# - Authly API: http://localhost:8000
# - pgAdmin: http://localhost:5050 (admin@authly.dev / admin)
# - Redis Commander: http://localhost:8081 (admin / admin)
# - Mailhog: http://localhost:8025
```

### Production
```bash
# Start production environment
docker-compose up -d

# With monitoring (optional)
docker-compose --profile monitoring up -d

# With reverse proxy (optional)
docker-compose --profile production up -d
```

## 📁 **Files Overview**

### Core Files
- **`Dockerfile`** - Multi-stage build optimized for production
- **`docker-compose.yml`** - Base production configuration
- **`docker-compose.dev.yml`** - Development environment extensions
- **`init-db-and-user.sql`** - PostgreSQL schema initialization

### Configuration Files
- **`docker-compose/nginx/`** - Nginx reverse proxy configuration
- **`docker-compose/prometheus/`** - Monitoring configuration
- **`docker-compose/grafana/`** - Dashboard configuration

## 🔧 **Unified Resource Manager Architecture**

The Docker deployment uses Authly's unified resource manager with automatic mode detection:

### Environment Variables
```bash
# Resource Manager Configuration
AUTHLY_MODE="production"              # Deployment mode (production/embedded/cli/testing)
AUTHLY_BOOTSTRAP_ENABLED="true"       # Auto-create admin user on startup

# Database Configuration
DATABASE_URL="postgresql://user:pass@host:5432/authly"

# JWT Configuration
JWT_SECRET_KEY="your-secret-key"
JWT_REFRESH_SECRET_KEY="your-refresh-secret"
```

### Supported Modes
| Mode | Use Case | Pool Settings | Bootstrap |
|------|----------|---------------|-----------|
| **production** | Docker containers | 5-20 connections | Environment controlled |
| **embedded** | Development | 2-8 connections | Always enabled |
| **cli** | Admin commands | 1-3 connections | Disabled |
| **testing** | Test suites | 1-10 connections | Test managed |

## 🚀 **Docker Build Process**

### Multi-Stage Build
1. **Builder Stage**: Install dependencies with UV package manager
2. **Production Stage**: Minimal runtime with security hardening

### Optimizations
- ✅ **Non-root user**: Runs as `authly` user (not root)
- ✅ **Minimal image**: Based on `python:3.13-slim`
- ✅ **Layer caching**: Optimized COPY order for faster rebuilds
- ✅ **Security**: No secrets in image layers
- ✅ **Health checks**: Built-in health monitoring

### Build Command
```bash
# Build production image
docker build -t authly:latest .

# Build with specific UV version
docker build --build-arg UV_VERSION=0.5.11 -t authly:latest .
```

## 🌍 **Environment Configuration**

### Production (.env file)
```bash
# Database
POSTGRES_PASSWORD=your-secure-password
DATABASE_URL=postgresql://authly:${POSTGRES_PASSWORD}@postgres:5432/authly

# JWT Secrets (CHANGE THESE!)
JWT_SECRET_KEY=your-production-jwt-secret
JWT_REFRESH_SECRET_KEY=your-production-refresh-secret

# Admin Configuration
AUTHLY_ADMIN_PASSWORD=your-admin-password
```

### Development
Development environment uses insecure defaults for convenience. **Never use in production!**

## 🔍 **Health Checks & Monitoring**

### Built-in Health Check
```bash
# Check container health
docker exec authly-app curl -f http://localhost:8000/health

# View health status
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Admin CLI Access
```bash
# Access admin CLI inside container
docker exec -it authly-app python -m authly admin status

# Create OAuth client
docker exec -it authly-app python -m authly admin client create \
  --name "My App" --type confidential \
  --redirect-uri "https://myapp.com/callback"
```

## 🧪 **Testing**

### Build Test
```bash
# Run comprehensive build test
./scripts/test-docker-build.sh
```

### Integration Test
```bash
# Start test environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Run integration tests
docker exec authly-app pytest tests/ -v

# Run specific test
docker exec authly-app pytest tests/test_oauth_integration.py -v
```

## 🔒 **Security Considerations**

### Container Security
- ✅ **Non-root execution**: Container runs as `authly` user
- ✅ **Read-only filesystem** (where possible)
- ✅ **Minimal attack surface**: Only necessary packages installed
- ✅ **Secret management**: Secrets via environment variables only

### Network Security
- ✅ **Internal networking**: Services communicate via Docker network
- ✅ **Port exposure**: Only necessary ports exposed
- ✅ **TLS termination**: Nginx handles SSL/TLS (production profile)

### Production Checklist
- [ ] Change default passwords in `.env` file
- [ ] Generate secure JWT secrets
- [ ] Configure proper TLS certificates
- [ ] Set up proper backup strategy
- [ ] Configure monitoring and alerting
- [ ] Review admin API access restrictions

## 📊 **Performance Tuning**

### Database Connection Pools
```bash
# Production mode (containers)
AUTHLY_MODE=production  # 5-20 connections, 5min idle

# Embedded mode (development)
AUTHLY_MODE=embedded    # 2-8 connections, 3min idle
```

### Container Resources
```yaml
# Recommended production limits
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.5'
    reservations:
      memory: 256M
      cpus: '0.25'
```

## 🆘 **Troubleshooting**

### Common Issues

**Container won't start:**
```bash
# Check logs
docker logs authly-app

# Check configuration
docker exec authly-app env | grep AUTHLY
```

**Database connection issues:**
```bash
# Test database connectivity
docker exec authly-app pg_isready -h postgres -p 5432 -U authly

# Check resource manager mode
docker exec authly-app python -c "
from authly.core.mode_factory import AuthlyModeFactory
print(f'Mode: {AuthlyModeFactory.detect_mode()}')
"
```

**Admin API not accessible:**
```bash
# Check admin middleware configuration
docker exec authly-app python -m authly admin status

# Verify admin API is enabled
docker exec authly-app env | grep ADMIN_API
```

### Debug Mode
```bash
# Start with debug logging
docker-compose up -d
docker-compose exec authly env LOG_LEVEL=DEBUG python -m authly serve --reload
```

## 📚 **Additional Resources**

- [Authly CLI Guide](../docs/cli-guide.md)
- [OAuth 2.1 Implementation](../docs/oauth-guide.md)
- [OIDC Implementation](../docs/oidc-guide.md)
- [Security Audit](../docs/security-audit.md)

---

**🔗 Related Commands:**
- `docker-compose logs -f authly` - Follow application logs
- `docker-compose exec postgres psql -U authly -d authly` - Access database
- `docker-compose down -v` - Stop and remove all data
- `docker system prune -a` - Clean up Docker resources