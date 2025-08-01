# Redis Integration Guide

This guide explains how to configure and use Redis with Authly for enhanced scalability and distributed deployments.

## Overview

Authly supports **optional Redis integration** for:
- **Distributed rate limiting** - Shared rate limits across multiple server instances
- **High-performance caching** - JWKS keys, session data, and API responses
- **Session management** - Distributed session storage for multi-instance deployments

**Key Features:**
- ✅ **Optional by design** - System works fully without Redis
- ✅ **Automatic fallback** - Memory backends when Redis unavailable
- ✅ **Configuration-driven** - Environment variables control all features
- ✅ **Zero breaking changes** - Existing deployments continue working

## Quick Start

### 1. Install Redis Support

```bash
# Add Redis dependency group
uv add --group redis authly

# Or with pip
pip install "redis>=5.2.0"
```

### 2. Basic Configuration

```bash
# Enable Redis connection
export AUTHLY_REDIS_URL="redis://localhost:6379/0"

# Enable specific features
export AUTHLY_REDIS_RATE_LIMIT="true"
export AUTHLY_REDIS_CACHE="true"
export AUTHLY_REDIS_SESSION="false"  # Optional

# Start Authly (will auto-detect Redis)
python -m authly serve
```

### 3. Verify Integration

```bash
# Check logs for Redis initialization
# You should see: "Redis integration enabled"

# Test rate limiting across instances
curl -X POST http://localhost:8000/api/v1/auth/login
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHLY_REDIS_URL` | `None` | Redis connection URL |
| `AUTHLY_REDIS_RATE_LIMIT` | `false` | Enable Redis rate limiting |
| `AUTHLY_REDIS_CACHE` | `false` | Enable Redis caching |
| `AUTHLY_REDIS_SESSION` | `false` | Enable Redis session storage |
| `AUTHLY_REDIS_POOL_SIZE` | `10` | Redis connection pool size |
| `AUTHLY_REDIS_TIMEOUT` | `5` | Connection timeout in seconds |
| `AUTHLY_REDIS_KEEPALIVE` | `true` | Enable socket keepalive |

### Redis URL Formats

```bash
# Basic Redis
AUTHLY_REDIS_URL="redis://localhost:6379/0"

# Redis with password
AUTHLY_REDIS_URL="redis://:password@localhost:6379/0"

# Redis with username and password
AUTHLY_REDIS_URL="redis://username:password@localhost:6379/0"

# Redis SSL
AUTHLY_REDIS_URL="rediss://localhost:6380/0"

# Redis Cluster
AUTHLY_REDIS_URL="redis://node1:6379,node2:6379,node3:6379/0"
```

## Deployment Scenarios

### Scenario 1: Single Instance (Memory Only)

**Best for**: Development, small applications, edge deployments

```bash
# No Redis configuration needed
python -m authly serve
```

- ✅ Simple deployment
- ✅ No external dependencies
- ❌ No shared state between restarts

### Scenario 2: Multiple Instances with Redis

**Best for**: Production, load-balanced deployments

```bash
# Shared Redis for all instances
export AUTHLY_REDIS_URL="redis://redis-server:6379/0"
export AUTHLY_REDIS_RATE_LIMIT="true"
export AUTHLY_REDIS_CACHE="true"

# Start multiple instances
python -m authly serve --port 8000 &
python -m authly serve --port 8001 &
python -m authly serve --port 8002 &
```

- ✅ Shared rate limits
- ✅ Consistent caching
- ✅ Horizontal scaling

### Scenario 3: Hybrid Deployment

**Best for**: Mixed environments, gradual migration

```bash
# Enable only specific features
export AUTHLY_REDIS_URL="redis://localhost:6379/0"
export AUTHLY_REDIS_RATE_LIMIT="true"    # Shared rate limiting
export AUTHLY_REDIS_CACHE="false"        # Memory caching
export AUTHLY_REDIS_SESSION="false"      # Database sessions
```

- ✅ Selective feature adoption
- ✅ Risk mitigation
- ✅ Performance tuning

## Docker Compose Integration

### Development Setup

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  authly:
    environment:
      AUTHLY_REDIS_URL: "redis://redis:6379/0"
      AUTHLY_REDIS_RATE_LIMIT: "true"
      AUTHLY_REDIS_CACHE: "true"
    depends_on:
      - redis

volumes:
  redis_data:
```

### Production Setup

```yaml
services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  authly:
    environment:
      AUTHLY_REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379/0"
      AUTHLY_REDIS_RATE_LIMIT: "true"
      AUTHLY_REDIS_CACHE: "true"
      AUTHLY_REDIS_POOL_SIZE: "20"
    depends_on:
      - redis
    deploy:
      replicas: 3
```

## Feature Details

### Distributed Rate Limiting

**How it works**: Uses Redis sorted sets with sliding window algorithm

```bash
# Enable distributed rate limiting
export AUTHLY_REDIS_RATE_LIMIT="true"
```

**Benefits**:
- Rate limits shared across all server instances
- More accurate than memory-based limiting
- Survives server restarts

**Use cases**:
- API rate limiting for external clients
- Brute force protection across load balancers
- Fair usage enforcement in multi-tenant scenarios

### High-Performance Caching

**How it works**: Redis cache-aside pattern with TTL expiration

```bash
# Enable Redis caching
export AUTHLY_REDIS_CACHE="true"
```

**Cached data**:
- JWKS keys (JWT verification performance)
- OAuth discovery metadata
- User profile information
- API response caching

**Benefits**:
- Reduced database load
- Faster response times
- Shared cache across instances

### Session Management

**How it works**: Redis hash storage with automatic expiration

```bash
# Enable Redis sessions
export AUTHLY_REDIS_SESSION="true"
```

**Session data**:
- OAuth authorization states
- Admin CLI sessions
- User preference caching
- Temporary authentication data

**Benefits**:
- Sessions survive server restarts
- Load balancer sticky sessions not required
- Centralized session management

## Monitoring and Troubleshooting

### Health Checks

```bash
# Check Redis connection status
curl http://localhost:8000/health

# Response includes Redis status
{
  "status": "healthy",
  "redis": {
    "available": true,
    "features": {
      "rate_limit": true,
      "cache": true,
      "session": false
    }
  }
}
```

### Log Monitoring

```bash
# Look for Redis initialization messages
tail -f /var/log/authly.log | grep -i redis

# Expected log messages:
# INFO - Redis connection initialized successfully
# INFO - Using Redis rate limiting backend
# INFO - Using Redis caching backend
# WARNING - Redis connection failed, falling back to memory
```

### Performance Metrics

Monitor these Redis metrics:
- **Connection pool usage**: Should be < 80% of pool size
- **Memory usage**: Monitor Redis memory consumption
- **Response time**: Redis operations should be < 5ms
- **Error rate**: Should be < 0.1% of requests

### Common Issues

**Issue**: "Redis dependency not available"
```bash
# Solution: Install Redis support
uv add --group redis authly
```

**Issue**: "Redis connection failed"
```bash
# Check Redis server status
redis-cli ping

# Verify connection string
echo $AUTHLY_REDIS_URL

# Check network connectivity
telnet redis-server 6379
```

**Issue**: Memory backend fallback
```bash
# Check logs for specific error
# Update Redis configuration
# Verify Redis server health
```

## Performance Considerations

### Memory Usage

- **Redis memory**: ~1-10MB per 1000 active sessions
- **Connection overhead**: ~8KB per connection
- **Cache efficiency**: Monitor hit/miss ratios

### Network Latency

- **Redis latency**: Should be < 1ms for local deployments
- **Connection pooling**: Reduces connection overhead
- **Pipeline operations**: Used for atomic rate limiting

### Scaling Guidelines

| Concurrent Users | Redis Configuration | Expected Memory |
|------------------|-------------------|-----------------|
| < 1,000 | Single instance, 10 connections | < 100MB |
| 1,000 - 10,000 | Single instance, 20 connections | 100MB - 1GB |
| 10,000 - 100,000 | Redis cluster or sentinel | 1GB - 10GB |
| > 100,000 | Redis cluster with sharding | > 10GB |

## Migration Guide

### From Memory to Redis

1. **Install Redis support**:
   ```bash
   uv add --group redis authly
   ```

2. **Start with rate limiting only**:
   ```bash
   export AUTHLY_REDIS_URL="redis://localhost:6379/0"
   export AUTHLY_REDIS_RATE_LIMIT="true"
   ```

3. **Verify operation**:
   ```bash
   # Check logs for successful Redis initialization
   # Test rate limiting behavior
   ```

4. **Enable additional features**:
   ```bash
   export AUTHLY_REDIS_CACHE="true"
   export AUTHLY_REDIS_SESSION="true"
   ```

5. **Monitor and optimize**:
   ```bash
   # Monitor Redis memory usage
   # Adjust connection pool sizes
   # Tune TTL values for cache efficiency
   ```

### Rollback Procedure

1. **Disable Redis features**:
   ```bash
   export AUTHLY_REDIS_RATE_LIMIT="false"
   export AUTHLY_REDIS_CACHE="false"
   export AUTHLY_REDIS_SESSION="false"
   ```

2. **Restart Authly**:
   ```bash
   # System automatically falls back to memory backends
   python -m authly serve
   ```

3. **Verify fallback**:
   ```bash
   # Check logs for "using memory backends" messages
   ```

## Best Practices

### Security

- ✅ Use Redis AUTH for password protection
- ✅ Enable TLS for Redis connections in production
- ✅ Restrict Redis network access with firewalls
- ✅ Regular Redis security updates
- ❌ Don't expose Redis directly to the internet

### Performance

- ✅ Monitor Redis memory usage and set limits
- ✅ Use connection pooling for efficiency
- ✅ Set appropriate TTL values for cached data
- ✅ Monitor Redis key expiration and cleanup
- ❌ Don't cache sensitive data without encryption

### Operations

- ✅ Set up Redis persistence for important data
- ✅ Configure Redis backup and recovery
- ✅ Monitor Redis health and performance metrics
- ✅ Plan for Redis maintenance windows
- ❌ Don't rely solely on Redis for critical data

## Integration Examples

### Python Client Example

```python
import asyncio
from authly.core.backend_factory import get_rate_limit_backend

async def example_rate_limiting():
    # Get backend (automatically uses Redis if configured)
    backend = await get_rate_limit_backend()
    
    # Check rate limit
    try:
        await backend.check_rate_limit("user:123", max_requests=10, window_seconds=60)
        print("Request allowed")
    except HTTPException:
        print("Rate limit exceeded")

# Run example
asyncio.run(example_rate_limiting())
```

### API Integration

```bash
# Test rate limiting with Redis
for i in {1..10}; do
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}'
  echo "Request $i"
done
```

### Monitoring Integration

```bash
# Prometheus metrics endpoint
curl http://localhost:8000/metrics | grep redis

# Example metrics:
# authly_redis_connections_active 5
# authly_redis_operations_total{operation="get"} 1234
# authly_redis_cache_hits_total 890
# authly_redis_cache_misses_total 123
```

## Support and Troubleshooting

For additional support:
- Check the [Authly documentation](../README.md)
- Review [deployment guides](./docker-deployment.md)
- Report issues on [GitHub](https://github.com/descoped/authly/issues)

## Version Compatibility

| Authly Version | Redis Version | Python Version |
|----------------|---------------|----------------|
| 0.5.1+ | 5.0+ | 3.11+ |
| Future | 6.0+ | 3.11+ |

This Redis integration maintains backward compatibility and follows Authly's principle of optional, configuration-driven scalability.