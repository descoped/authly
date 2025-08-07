# Authly Standalone Docker Image

The `descoped/authly-standalone` image is an all-in-one container that includes Authly with embedded PostgreSQL and Redis, perfect for quick testing, development, and small deployments.

## Features

- **Zero Dependencies**: Everything needed runs in a single container
- **Minimal Size**: ~150MB total image size
- **Quick Start**: Running in seconds with no configuration
- **Developer Friendly**: Direct CLI access with `authly` command
- **Persistent Data**: Optional volume mounting for data persistence
- **Multi-Architecture**: Supports both AMD64 and ARM64

## Quick Start

### Simplest Usage - Ephemeral

```bash
# Run with default settings (data is lost when container stops)
docker run -it --rm -p 8000:8000 descoped/authly-standalone
```

### Interactive Development

```bash
# Start container and get a shell
docker run -it --rm -p 8000:8000 descoped/authly-standalone /bin/bash

# Enter Interactive Shell to access Authly Admin CLI + End-2-End Testing tools
docker exec -it $(docker ps --filter "ancestor=descoped/authly-standalone" --format "{{.ID}}") /bin/bash

# Inside the container (you'll see the welcome message with command list):
authly> authly --help                   # Main CLI
authly> authly-admin --help             # Admin shortcuts  
authly> simple-auth-flow --help         # Full test
authly> run-end-to-end-test --help      # Full tests
authly> curl http://localhost:8000/health
```

### Production-like with Persistence

```bash
# Run with persistent storage
docker run -d \
  --name authly \
  -p 8000:8000 \
  -v authly-data:/data \
  -e JWT_SECRET_KEY=your-secret-key-here \
  -e AUTHLY_ADMIN_PASSWORD=secure-password \
  descoped/authly-standalone
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | dev-secret | JWT signing key (change in production!) |
| `JWT_REFRESH_SECRET_KEY` | dev-refresh | Refresh token key (change in production!) |
| `AUTHLY_ADMIN_PASSWORD` | admin | Admin user password |
| `AUTHLY_ADMIN_USERNAME` | admin | Admin username |
| `AUTHLY_ADMIN_EMAIL` | admin@localhost | Admin email |
| `DATABASE_URL` | (auto-configured) | PostgreSQL connection string |
| `REDIS_URL` | (auto-configured) | Redis connection string |

## Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  authly:
    image: descoped/authly-standalone:latest
    container_name: authly
    ports:
      - "8000:8000"
    volumes:
      - authly_data:/data
    environment:
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      JWT_REFRESH_SECRET_KEY: ${JWT_REFRESH_SECRET_KEY}
      AUTHLY_ADMIN_PASSWORD: ${AUTHLY_ADMIN_PASSWORD}
    restart: unless-stopped

volumes:
  authly_data:
```

Then create a `.env` file:

```env
JWT_SECRET_KEY=your-production-secret-key-at-least-256-bits
JWT_REFRESH_SECRET_KEY=your-refresh-secret-key-at-least-256-bits
AUTHLY_ADMIN_PASSWORD=your-secure-admin-password
```

Run with:

```bash
docker-compose up -d
```

## Data Persistence

The container stores all data in `/data`:
- `/data/postgres` - PostgreSQL database files
- `/data/redis` - Redis persistence (if enabled)
- `/data/authly` - Application data

To persist data across container restarts, mount a volume:

```bash
docker run -v /path/to/local/storage:/data ...
```

Or use a named volume:

```bash
docker volume create authly-data
docker run -v authly-data:/data ...
```

## Using the Authly CLI

The container includes the full Authly CLI. You can use it in several ways:

### Method 1: Interactive Shell

```bash
docker run -it --rm -p 8000:8000 descoped/authly-standalone
# You'll see the welcome message and commands list automatically
authly> authly-admin login              # Login as admin/admin
authly> authly admin client create --name "My App"
```

### Method 2: Docker Exec

```bash
# Start container in background
docker run -d --name authly -p 8000:8000 descoped/authly-standalone

# Execute commands
docker exec authly authly-admin status
docker exec authly authly admin client list
docker exec authly simple-auth-flow     # Run integration tests
```

### Method 3: One-off Commands

```bash
docker run --rm descoped/authly-standalone authly --version
```

## Health Checks

The container includes health checks for all services:

```bash
# Check if container is healthy
docker ps --filter "name=authly" --format "table {{.Names}}\t{{.Status}}"

# Manual health check
curl http://localhost:8000/health
```

## Networking

### Expose Additional Ports

By default, only port 8000 (Authly API) is exposed. If you need direct access to PostgreSQL or Redis:

```bash
docker run -p 8000:8000 -p 5432:5432 -p 6379:6379 descoped/authly-standalone
```

⚠️ **Security Warning**: Only expose additional ports for development. In production, keep them internal.

### Connect from Other Containers

```yaml
version: '3.8'

services:
  authly:
    image: descoped/authly-standalone
    networks:
      - app-network

  my-app:
    image: my-app:latest
    environment:
      OAUTH_SERVER: http://authly:8000
    networks:
      - app-network

networks:
  app-network:
```

## Troubleshooting

### View Logs

```bash
# All logs
docker logs authly

# Follow logs
docker logs -f authly

# Last 100 lines
docker logs --tail 100 authly
```

### Increase Verbosity

Set `S6_VERBOSITY` for more detailed startup logs:

```bash
docker run -e S6_VERBOSITY=2 descoped/authly-standalone
```

### Container Won't Start

1. Check port 8000 is not already in use:
   ```bash
   lsof -i :8000
   ```

2. Ensure sufficient resources:
   - Minimum 512MB RAM
   - 1GB disk space

3. Check logs for errors:
   ```bash
   docker logs authly
   ```

### Reset Database

To completely reset the database:

```bash
# Stop and remove container
docker stop authly
docker rm authly

# Remove volume (WARNING: Deletes all data!)
docker volume rm authly-data

# Start fresh
docker run -d --name authly -v authly-data:/data descoped/authly-standalone
```

## Performance Tuning

### Memory Limits

```bash
docker run -m 512m descoped/authly-standalone
```

### CPU Limits

```bash
docker run --cpus="1.5" descoped/authly-standalone
```

### Optimized Settings

For production workloads, create a custom environment file:

```bash
# High-performance settings
docker run \
  -e POSTGRES_SHARED_BUFFERS=256MB \
  -e POSTGRES_MAX_CONNECTIONS=200 \
  -e REDIS_MAXMEMORY=100mb \
  descoped/authly-standalone
```

## Security Considerations

### Production Checklist

- [ ] Change default JWT secrets
- [ ] Set strong admin password
- [ ] Use TLS/HTTPS (reverse proxy recommended)
- [ ] Limit resource usage
- [ ] Regular backups
- [ ] Monitor logs
- [ ] Keep image updated

### Backup and Restore

**Backup:**

```bash
# Backup entire data directory
docker run --rm -v authly-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/authly-backup-$(date +%Y%m%d).tar.gz /data
```

**Restore:**

```bash
# Restore from backup
docker run --rm -v authly-data:/data -v $(pwd):/backup alpine \
  tar xzf /backup/authly-backup-20240101.tar.gz -C /
```

## Versions and Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `minimal` | Size-optimized version |
| `0.5.6` | Specific version |
| `0.5` | Latest patch of 0.5.x |

## Limitations

The standalone image is perfect for:
- Development and testing
- POCs and demos
- Small production deployments (<1000 users)
- CI/CD pipelines

For larger deployments, consider:
- Using separate PostgreSQL and Redis instances
- The standard `descoped/authly` image with external databases
- Kubernetes deployment with proper scaling

## Support

- **Issues**: https://github.com/descoped/authly/issues
- **Documentation**: https://github.com/descoped/authly/docs
- **Docker Hub**: https://hub.docker.com/r/descoped/authly-standalone