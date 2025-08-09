# Docker Standalone - Quick Start Guide

## 🚀 Quick Start

### Using Make (Recommended)

```bash
# Start everything (all services)
make standalone-full

# Show all service URLs and credentials
make standalone-info

# View logs
make standalone-logs

# Stop everything
make standalone-stop
```

### Using Scripts

```bash
# Start with all services
./scripts/start-standalone.sh --profile tools --profile monitoring --profile authz

# Show service information
./scripts/show-services.sh

# Stop services
./scripts/stop-standalone.sh
```

### Using Docker Compose Directly

```bash
# Start with specific profiles
docker compose -f docker-compose.standalone.yml \
  --profile tools \
  --profile monitoring \
  --profile authz \
  up -d

# Stop services
docker compose -f docker-compose.standalone.yml down
```

## 📋 Service URLs and Credentials

After starting, run `make standalone-info` to see all service URLs and credentials:

### Core Services
- **Authly API**: http://localhost:8000
  - Admin: `admin` / `admin` (or value of `AUTHLY_ADMIN_PASSWORD`)
  - Docs: http://localhost:8000/docs

### Database Services
- **PostgreSQL**: localhost:5432
  - Database: `authly`
  - Internal access only
  
- **pgAdmin**: http://localhost:5050
  - Login: `admin@example.com` / `authly`
  
- **Adminer**: http://localhost:8082
  - OAuth-integrated database access
  - Auto-login in development mode

### Cache Services
- **Redis/KeyDB**: localhost:6379
  - No authentication required
  
- **Redis Commander**: http://localhost:8081
  - Login: `admin` / `admin`

### Monitoring Services
- **Prometheus**: http://localhost:9090
  - No authentication required
  - Targets: http://localhost:9090/targets
  
- **Grafana**: http://localhost:3000
  - Login: `admin` / `admin`
  - Dashboard: "Authly Metrics"

### OAuth Proxy Services
- **PostgreSQL OAuth Proxy**: localhost:5433
  - Requires OAuth token with scopes: `database:read database:write`
  
- **Redis OAuth Proxy**: localhost:6380
  - Requires OAuth token with scopes: `cache:read cache:write`

## 🎯 Common Tasks

### Get an OAuth Token
```bash
curl -X POST http://localhost:8000/api/v1/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=admin&scope=openid profile"
```

### Check Service Health
```bash
curl http://localhost:8000/health
```

### View Real-time Logs
```bash
make standalone-logs
# or
docker logs authly-standalone -f
```

### Access PostgreSQL
```bash
# Via pgAdmin web interface
open http://localhost:5050

# Via command line (from inside container)
docker exec -it authly-standalone psql -U authly -d authly
```

### Access Redis/KeyDB
```bash
# Via Redis Commander web interface
open http://localhost:8081

# Via command line
docker exec -it authly-standalone keydb-cli
```

## 🔧 Configuration

### Environment Variables
```bash
# Set admin password
export AUTHLY_ADMIN_PASSWORD=mysecurepassword

# Set JWT secrets (production)
export JWT_SECRET_KEY=your-256-bit-secret-key
export JWT_REFRESH_SECRET_KEY=your-refresh-secret-key

# Start with custom configuration
make standalone-full
```

### Available Profiles
- **`tools`**: pgAdmin, Adminer, Redis Commander
- **`monitoring`**: Prometheus, Grafana
- **`authz`**: OAuth proxy servers for database and cache

### Start with Specific Profiles
```bash
# Only tools
./scripts/start-standalone.sh --profile tools

# Tools and monitoring
./scripts/start-standalone.sh --profile tools --profile monitoring

# Everything
./scripts/start-standalone.sh --profile tools --profile monitoring --profile authz
```

## 🛑 Stopping Services

### Keep Data
```bash
make standalone-stop
# or
./scripts/stop-standalone.sh
```

### Remove Everything (Including Data)
```bash
./scripts/stop-standalone.sh --volumes
# or
docker compose -f docker-compose.standalone.yml down -v
```

## 📊 Monitoring

### View Metrics in Grafana
1. Open http://localhost:3000
2. Login with `admin` / `admin`
3. Navigate to Dashboards → "Authly Metrics"

### Query Metrics in Prometheus
1. Open http://localhost:9090
2. Try queries like:
   - `up` - Service health
   - `authly_http_requests_total` - Total requests
   - `rate(authly_http_requests_total[5m])` - Request rate

## 🔍 Troubleshooting

### Check if Services are Running
```bash
make standalone-info
# Look for ✅ or ❌ next to each service
```

### View Service Logs
```bash
# All services
docker compose -f docker-compose.standalone.yml logs

# Specific service
docker logs authly-grafana
docker logs authly-prometheus
```

### Reset Everything
```bash
# Stop and remove all data
./scripts/stop-standalone.sh --volumes

# Start fresh
make standalone-full
```

## 📚 More Information

- [Full Documentation](docker-standalone.md)
- [Prometheus Queries](prometheus-queries.md)
- [API Documentation](http://localhost:8000/docs)