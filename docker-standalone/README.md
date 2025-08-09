# Authly Standalone with Management Tools

This directory contains configuration for running Authly standalone container with management and monitoring tools.

## Quick Start

```bash
# Start everything (Authly + all tools)
docker compose -f docker-compose.standalone.yml --profile tools --profile monitoring up -d

# Or start just Authly with management tools
docker compose -f docker-compose.standalone.yml --profile tools up -d

# Or start just Authly with monitoring
docker compose -f docker-compose.standalone.yml --profile monitoring up -d

# Or start just Authly standalone
docker compose -f docker-compose.standalone.yml up -d
```

## Services

### Core Service
- **Authly Standalone** (http://localhost:8000)
  - PostgreSQL on port 5432 (password: admin)
  - KeyDB/Redis on port 6379
  - API on port 8000

### Management Tools (profile: tools)
- **pgAdmin** (http://localhost:5050)
  - Email: admin@authly.local
  - Password: admin
  - Pre-configured connection to Authly PostgreSQL

- **Redis Commander** (http://localhost:8081)
  - Username: admin
  - Password: admin
  - Pre-configured connection to Authly KeyDB

### Monitoring Stack (profile: monitoring)
- **Prometheus** (http://localhost:9090)
  - Metrics collection from all services
  
- **Grafana** (http://localhost:3000)
  - Username: admin
  - Password: admin
  - Pre-configured dashboards for Authly

- **PostgreSQL Exporter** (http://localhost:9187/metrics)
  - Database metrics for Prometheus

- **Redis Exporter** (http://localhost:9121/metrics)
  - Cache metrics for Prometheus

## Configuration Files

```
docker-standalone/
├── config/
│   ├── pgadmin-servers.json      # pgAdmin server configuration
│   ├── prometheus.yml            # Prometheus scrape configuration
│   ├── grafana-datasources.yml   # Grafana data source configuration
│   └── grafana-dashboards.yml    # Grafana dashboard provisioning
├── dashboards/
│   └── authly-overview.json      # Main Authly dashboard
├── scripts/                      # Container setup scripts
└── AUTHLY_AS_AUTHZ.md           # Future: Using Authly for DB auth
```

## Usage Examples

### Connect to PostgreSQL from host
```bash
psql -h localhost -p 5432 -U authly -d authly
# Password: admin
```

### Connect to Redis from host
```bash
redis-cli -h localhost -p 6379
```

### View logs
```bash
docker compose -f docker-compose.standalone.yml logs -f authly-standalone
```

### Reset everything
```bash
docker compose -f docker-compose.standalone.yml down -v
```

## Environment Variables

Create a `.env` file to override defaults:

```env
# Authly Configuration
AUTHLY_ADMIN_PASSWORD=your-secure-password
JWT_SECRET_KEY=your-production-secret-key-at-least-256-bits
JWT_REFRESH_SECRET_KEY=your-refresh-secret-key-at-least-256-bits

# Tool Passwords (optional)
PGADMIN_PASSWORD=secure-pgadmin-password
REDIS_COMMANDER_PASSWORD=secure-redis-password
GRAFANA_PASSWORD=secure-grafana-password
```

## Accessing Services from Tools

All management tools can access the Authly services using the container name `authly-standalone`:

- PostgreSQL: `authly-standalone:5432`
- Redis: `authly-standalone:6379`
- API: `authly-standalone:8000`

## Security Notes

⚠️ **Default passwords are for development only!**

For production:
1. Change all default passwords
2. Use secrets management
3. Enable TLS/SSL
4. Restrict network access
5. Use firewall rules

## Troubleshooting

### Services not connecting
Ensure the Authly container is healthy:
```bash
docker compose -f docker-compose.standalone.yml ps
docker compose -f docker-compose.standalone.yml exec authly-standalone curl http://localhost:8000/health
```

### pgAdmin connection failed
Check PostgreSQL is listening:
```bash
docker compose -f docker-compose.standalone.yml exec authly-standalone psql -U authly -c "SELECT 1"
```

### Redis Commander not showing data
Check Redis is responding:
```bash
docker compose -f docker-compose.standalone.yml exec authly-standalone redis PING
```

## Future Enhancements

See [AUTHLY_AS_AUTHZ.md](AUTHLY_AS_AUTHZ.md) for plans to use Authly as the authorization server for PostgreSQL and Redis access.