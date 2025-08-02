# Metrics Implementation Plan for Authly

## Overview

This document outlines the implementation plan for comprehensive Prometheus metrics integration in Authly. The existing `src/authly/monitoring/metrics.py` module provides a solid foundation with the `AuthlyMetrics` class and context managers, but it needs to be integrated into the application architecture.

## Current State Analysis

### Existing Components

1. **AuthlyMetrics Class** (`src/authly/monitoring/metrics.py`)
   - ✅ Comprehensive metric definitions (HTTP, OAuth, Auth, Database, Cache, Security, System)
   - ✅ Context managers (`RequestTimer`, `DatabaseTimer`)
   - ✅ Global metrics instance
   - ✅ Prometheus endpoint handler (`metrics_handler()`)
   - ✅ Prometheus client dependency already in `pyproject.toml`

2. **Infrastructure Ready**
   - ✅ Prometheus configured in Docker Compose (`docker-compose/prometheus/prometheus.yml`)
   - ✅ Grafana provisioning configured
   - ✅ Metrics endpoint configured in Prometheus scrape config (`/metrics` at port 8000)

3. **Architecture Components**
   - ✅ Resource Manager pattern for dependency management
   - ✅ Structured logging with correlation IDs
   - ✅ FastAPI middleware architecture
   - ✅ Router-based API organization

### Missing Integrations

1. **No FastAPI Router Integration**
   - Metrics endpoint handler exists but not exposed via router
   - No `/metrics` endpoint available in the application

2. **No Middleware Integration** 
   - HTTP request metrics not collected automatically
   - No integration with existing `LoggingMiddleware`

3. **No Service-Level Integration**
   - OAuth operations not instrumented
   - Database operations not instrumented
   - Authentication events not tracked

4. **No Resource Manager Integration**
   - Metrics not initialized through dependency injection
   - No integration with Redis for distributed metrics

## Implementation Plan

### Phase 1: Core Integration (Priority: High)

#### 1.1 Create Metrics Router
**File**: `src/authly/api/metrics_router.py`

```python
from fastapi import APIRouter, Depends
from authly.monitoring.metrics import metrics_handler
from authly.api.auth_dependencies import get_rate_limiter

router = APIRouter(tags=["metrics"])

@router.get("/metrics")
async def get_metrics(
    _: None = Depends(get_rate_limiter("metrics"))
):
    """Prometheus metrics endpoint."""
    return metrics_handler()
```

#### 1.2 Integrate Metrics Router into Application
**File**: `src/authly/app.py`

Add metrics router to the FastAPI application:
- Import metrics router
- Include router without prefix (standard `/metrics` path)
- Ensure it's added after security middleware

#### 1.3 Create Metrics Middleware
**File**: `src/authly/monitoring/middleware.py`

```python
class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic HTTP metrics collection."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Extract endpoint pattern from FastAPI route
        # Use RequestTimer context manager
        # Track HTTP metrics automatically
        # Integrate with existing LoggingMiddleware patterns
```

#### 1.4 Update Application Factory
**File**: `src/authly/app.py`

Add MetricsMiddleware to the middleware stack:
- Add after LoggingMiddleware (to capture all requests)
- Add before SecurityMiddleware (to measure security overhead)

### Phase 2: Service Integration (Priority: High)

#### 2.1 OAuth Service Instrumentation
**Files**: 
- `src/authly/oauth/authorization_service.py`
- `src/authly/oauth/client_service.py`
- `src/authly/tokens/service.py`

Integration points:
- Token generation timing (`track_oauth_token_request`)
- Authorization flow tracking (`track_oauth_authorization_request`)
- Client request counting (`track_client_request`)
- Active token counting (periodic updates)

#### 2.2 Authentication Service Instrumentation
**Files**:
- `src/authly/api/auth_router.py`
- `src/authly/users/service.py`

Integration points:
- Login attempt tracking (`track_login_attempt`)
- Failed login tracking with security context
- Session management (`update_active_sessions`)
- Password change operations

#### 2.3 Database Operation Instrumentation
**Files**:
- `src/authly/oauth/authorization_code_repository.py`
- `src/authly/oauth/client_repository.py`
- `src/authly/oauth/scope_repository.py`
- `src/authly/tokens/repository.py`
- `src/authly/users/repository.py`

Implementation approach:
- Use `DatabaseTimer` context manager in repository methods
- Track connection pool metrics via resource manager
- Monitor query performance per operation type

### Phase 3: Advanced Integration (Priority: Medium)

#### 3.1 Resource Manager Integration
**File**: `src/authly/core/resource_manager.py`

Add metrics initialization:
- Initialize metrics in resource manager startup
- Set application info (`set_app_info`) with version, environment
- Integrate with Redis metrics if available
- Track resource manager lifecycle events

#### 3.2 Rate Limiter Integration
**File**: `src/authly/api/rate_limiter.py`

Add rate limit metrics:
- Track rate limit hits (`track_rate_limit_hit`)
- Monitor rate limiter performance
- Different metrics for Redis vs in-memory rate limiting

#### 3.3 Security Event Tracking
**Files**:
- `src/authly/api/security_middleware.py`
- `src/authly/api/admin_middleware.py`

Integration points:
- Security header violations
- Admin access patterns
- CORS violations
- Authentication failures

### Phase 4: System Metrics (Priority: Medium)

#### 4.1 Application Lifecycle Metrics
**File**: `src/authly/main.py` or lifespan handlers

Track:
- Application startup time
- Configuration validation
- Database connection establishment
- Redis connection status

#### 4.2 Periodic System Metrics
**File**: `src/authly/monitoring/system_collector.py`

Create background task for:
- Memory usage collection
- Active connection counts
- Cache hit ratios (if Redis enabled)
- Token cleanup statistics

#### 4.3 OIDC-Specific Metrics
**Files**:
- `src/authly/oidc/userinfo.py`
- `src/authly/oidc/jwks.py`
- `src/authly/oidc/id_token.py`

Track:
- JWKS endpoint requests
- UserInfo endpoint usage
- ID token generation performance
- OIDC discovery requests

### Phase 5: Production Features (Priority: Low)

#### 5.1 Custom Metric Dashboards
**File**: `docker-compose/grafana/dashboards/authly-dashboard.json`

Create Grafana dashboard with:
- HTTP request rates and latencies
- OAuth flow success rates
- Authentication patterns
- Database performance
- Security events

#### 5.2 Alerting Rules
**File**: `docker-compose/prometheus/rules/authly-alerts.yml`

Define alerts for:
- High error rates
- Database connection issues
- Failed authentication spikes
- Token generation failures

#### 5.3 Metrics Export Configuration
Add configuration options:
- Enable/disable metrics collection
- Configure metrics resolution
- Custom metric labels
- Metric retention policies

## Technical Implementation Details

### Middleware Integration Pattern

```python
# Add to src/authly/app.py
from authly.monitoring.middleware import MetricsMiddleware

def create_app(...) -> FastAPI:
    app = FastAPI(...)
    
    # Middleware order (outer to inner):
    app.add_middleware(LoggingMiddleware)          # 1. Logging (outermost)
    app.add_middleware(MetricsMiddleware)          # 2. Metrics 
    setup_security_middleware(app)                # 3. Security
    setup_admin_middleware(app)                   # 4. Admin security
    
    # Include metrics router
    from authly.api.metrics_router import router as metrics_router
    app.include_router(metrics_router)
```

### Service Integration Pattern

```python
# Example: OAuth service instrumentation
from authly.monitoring.metrics import metrics

class AuthorizationService:
    async def create_authorization_code(self, ...):
        start_time = time.time()
        try:
            # Business logic
            result = await self._create_code(...)
            metrics.track_oauth_authorization_request(
                client_id=client_id, 
                status="success", 
                response_type="code"
            )
            return result
        except Exception as e:
            metrics.track_oauth_authorization_request(
                client_id=client_id, 
                status="error", 
                response_type="code"
            )
            raise
```

### Database Integration Pattern

```python
# Example: Repository instrumentation
from authly.monitoring.metrics import DatabaseTimer

class ClientRepository:
    async def create_client(self, client_data: dict):
        with DatabaseTimer("client_create"):
            # Database operation
            return await self._execute_query(...)
```

## Configuration Requirements

### Environment Variables

```bash
# Metrics configuration
AUTHLY_METRICS_ENABLED=true
AUTHLY_METRICS_PATH="/metrics"
AUTHLY_METRICS_INCLUDE_CLIENT_IDS=false  # For privacy
AUTHLY_METRICS_COLLECTION_INTERVAL=30
```

### Dependencies

Already satisfied:
- `prometheus-client>=0.20.0` ✅

### Security Considerations

1. **Client ID Privacy**: Mask or hash client IDs in metrics
2. **Rate Limiting**: Apply rate limiting to `/metrics` endpoint
3. **Access Control**: Consider restricting metrics endpoint access
4. **Sensitive Data**: Ensure no sensitive data in metric labels
5. **Resource Usage**: Monitor metrics collection overhead

## Testing Strategy

### Unit Tests
- Test metrics collection accuracy
- Verify context manager functionality
- Test middleware integration

### Integration Tests
- End-to-end metric collection
- Prometheus scraping verification
- Performance impact measurement

### Load Tests
- Metrics overhead under load
- Memory usage with metrics enabled
- Metric collection performance

## Migration Strategy

### Deployment Steps
1. Deploy metrics infrastructure (router, middleware)
2. Enable HTTP metrics collection
3. Gradually add service-level metrics
4. Deploy system metrics
5. Configure alerting and dashboards

### Rollback Plan
- Feature flags for metrics collection
- Graceful degradation if metrics fail
- Monitoring overhead alerts

## Success Metrics

### Technical KPIs
- < 5ms overhead per request for metrics collection
- < 50MB additional memory usage for metrics
- 99.9% uptime for `/metrics` endpoint

### Business KPIs
- Visibility into OAuth flow performance
- Authentication pattern analysis
- Database performance optimization opportunities
- Security event detection capabilities

## Resource Requirements

### Development Time
- Phase 1: 2-3 days
- Phase 2: 3-4 days  
- Phase 3: 2-3 days
- Phase 4: 2-3 days
- Phase 5: 3-4 days

### Infrastructure Impact
- ~50MB additional memory per instance
- ~5% CPU overhead for metrics collection
- Network bandwidth for Prometheus scraping

### Maintenance
- Monthly dashboard reviews
- Quarterly alert rule updates
- Metrics retention policy management

---

## Implementation Priority

**Immediate (This Sprint)**:
- Phase 1: Core Integration
- Phase 2: Service Integration (OAuth, Auth)

**Next Sprint**:
- Phase 2: Database Integration
- Phase 3: Resource Manager Integration

**Future**:
- Phase 4: System Metrics
- Phase 5: Production Features

This plan leverages the existing solid foundation while providing a clear path to comprehensive observability for the Authly authorization server.