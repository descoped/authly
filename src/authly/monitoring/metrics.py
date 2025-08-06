"""
Prometheus Metrics for Authly OAuth 2.1 Authorization Server.

This module provides comprehensive metrics collection for monitoring
the performance, usage, and health of the Authly authorization server.

Metrics Categories:
- HTTP Request Metrics: Request rates, response times, status codes
- OAuth Business Metrics: Token generation, authorization flows, client activity
- Database Metrics: Connection pool status, query performance
- Authentication Metrics: Login attempts, success rates, security events
- System Metrics: Memory usage, cache hit rates, active sessions
"""

import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)
from starlette.responses import Response


class AuthlyMetrics:
    """
    Comprehensive metrics collection for Authly authorization server.

    This class provides methods to track various aspects of the OAuth 2.1
    server performance and usage patterns.
    """

    def __init__(self, registry: CollectorRegistry | None = None):
        """Initialize metrics collectors."""
        self.registry = registry or REGISTRY

        # Application info
        self.app_info = Info("authly_application", "Application information", registry=self.registry)

        # HTTP Request Metrics
        self.http_requests_total = Counter(
            "authly_http_requests_total",
            "Total number of HTTP requests",
            ["method", "endpoint", "status_code"],
            registry=self.registry,
        )

        self.http_request_duration_seconds = Histogram(
            "authly_http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method", "endpoint"],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry,
        )

        self.http_requests_in_progress = Gauge(
            "authly_http_requests_in_progress",
            "Number of HTTP requests currently being processed",
            ["method", "endpoint"],
            registry=self.registry,
        )

        # OAuth 2.1 Business Metrics
        self.oauth_token_requests_total = Counter(
            "authly_oauth_token_requests_total",
            "Total OAuth token requests",
            ["grant_type", "client_id", "status"],
            registry=self.registry,
        )

        self.oauth_authorization_requests_total = Counter(
            "authly_oauth_authorization_requests_total",
            "Total OAuth authorization requests",
            ["client_id", "status", "response_type"],
            registry=self.registry,
        )

        self.oauth_active_tokens = Gauge(
            "authly_oauth_active_tokens", "Number of active OAuth tokens", ["token_type"], registry=self.registry
        )

        self.oauth_token_generation_duration_seconds = Histogram(
            "authly_oauth_token_generation_duration_seconds",
            "Time taken to generate OAuth tokens",
            ["token_type"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry=self.registry,
        )

        # Authentication Metrics
        self.auth_login_attempts_total = Counter(
            "authly_auth_login_attempts_total", "Total login attempts", ["status", "method"], registry=self.registry
        )

        self.auth_failed_login_attempts = Counter(
            "authly_auth_failed_login_attempts_total",
            "Total failed login attempts",
            ["reason", "username"],
            registry=self.registry,
        )

        self.auth_active_sessions = Gauge(
            "authly_auth_active_sessions", "Number of active user sessions", registry=self.registry
        )

        # Database Metrics
        self.database_connections_active = Gauge(
            "authly_database_connections_active", "Number of active database connections", registry=self.registry
        )

        self.database_connections_idle = Gauge(
            "authly_database_connections_idle", "Number of idle database connections", registry=self.registry
        )

        self.database_query_duration_seconds = Histogram(
            "authly_database_query_duration_seconds",
            "Database query execution time",
            ["operation"],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
            registry=self.registry,
        )

        self.database_queries_total = Counter(
            "authly_database_queries_total",
            "Total database queries executed",
            ["operation", "status"],
            registry=self.registry,
        )

        # Cache Metrics (Redis)
        self.cache_operations_total = Counter(
            "authly_cache_operations_total", "Total cache operations", ["operation", "status"], registry=self.registry
        )

        self.cache_hit_ratio = Gauge("authly_cache_hit_ratio", "Cache hit ratio (0-1)", registry=self.registry)

        self.cache_memory_usage_bytes = Gauge(
            "authly_cache_memory_usage_bytes", "Cache memory usage in bytes", registry=self.registry
        )

        # Client Metrics
        self.oauth_clients_total = Gauge(
            "authly_oauth_clients_total", "Total number of registered OAuth clients", registry=self.registry
        )

        self.oauth_client_requests_total = Counter(
            "authly_oauth_client_requests_total",
            "Total requests per OAuth client",
            ["client_id", "endpoint"],
            registry=self.registry,
        )

        # Security Metrics
        self.security_events_total = Counter(
            "authly_security_events_total", "Total security events", ["event_type", "severity"], registry=self.registry
        )

        self.rate_limit_hits_total = Counter(
            "authly_rate_limit_hits_total", "Total rate limit hits", ["client_id", "endpoint"], registry=self.registry
        )

        # System Metrics
        self.memory_usage_bytes = Gauge(
            "authly_memory_usage_bytes", "Memory usage in bytes", ["type"], registry=self.registry
        )

        self.uptime_seconds = Gauge("authly_uptime_seconds", "Application uptime in seconds", registry=self.registry)

    def set_app_info(self, version: str, python_version: str, environment: str):
        """Set application information."""
        self.app_info.info({"version": version, "python_version": python_version, "environment": environment})

    # HTTP Request Tracking
    def track_http_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Track HTTP request metrics."""
        self.http_requests_total.labels(method=method, endpoint=endpoint, status_code=str(status_code)).inc()

        self.http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

    def track_http_request_start(self, method: str, endpoint: str):
        """Track start of HTTP request processing."""
        self.http_requests_in_progress.labels(method=method, endpoint=endpoint).inc()

    def track_http_request_end(self, method: str, endpoint: str):
        """Track end of HTTP request processing."""
        self.http_requests_in_progress.labels(method=method, endpoint=endpoint).dec()

    # OAuth Business Metrics
    def track_oauth_token_request(self, grant_type: str, client_id: str, status: str, duration: float):
        """Track OAuth token request."""
        self.oauth_token_requests_total.labels(grant_type=grant_type, client_id=client_id, status=status).inc()

        if status == "success":
            self.oauth_token_generation_duration_seconds.labels(token_type="access_token").observe(duration)

    def track_oauth_authorization_request(self, client_id: str, status: str, response_type: str = "code"):
        """Track OAuth authorization request."""
        self.oauth_authorization_requests_total.labels(
            client_id=client_id, status=status, response_type=response_type
        ).inc()

    def update_active_tokens(self, access_tokens: int, refresh_tokens: int):
        """Update active token counts."""
        self.oauth_active_tokens.labels(token_type="access_token").set(access_tokens)
        self.oauth_active_tokens.labels(token_type="refresh_token").set(refresh_tokens)

    # Authentication Metrics
    def track_login_attempt(self, status: str, method: str = "password", username: str = None):
        """Track login attempt."""
        self.auth_login_attempts_total.labels(status=status, method=method).inc()

        if status == "failed" and username:
            # Only track failed attempts with username for security monitoring
            self.auth_failed_login_attempts.labels(
                reason="invalid_credentials",
                username=username[:10] + "***",  # Partial username for privacy
            ).inc()

    def update_active_sessions(self, count: int):
        """Update active sessions count."""
        self.auth_active_sessions.set(count)

    # Database Metrics
    def track_database_query(self, operation: str, status: str, duration: float):
        """Track database query execution."""
        self.database_queries_total.labels(operation=operation, status=status).inc()

        if status == "success":
            self.database_query_duration_seconds.labels(operation=operation).observe(duration)

    def update_database_connections(self, active: int, idle: int):
        """Update database connection pool metrics."""
        self.database_connections_active.set(active)
        self.database_connections_idle.set(idle)

    # Cache Metrics
    def track_cache_operation(self, operation: str, status: str):
        """Track cache operations."""
        self.cache_operations_total.labels(operation=operation, status=status).inc()

    def update_cache_metrics(self, hit_ratio: float, memory_usage: int):
        """Update cache performance metrics."""
        self.cache_hit_ratio.set(hit_ratio)
        self.cache_memory_usage_bytes.set(memory_usage)

    # Security Metrics
    def track_security_event(self, event_type: str, severity: str = "info"):
        """Track security events."""
        self.security_events_total.labels(event_type=event_type, severity=severity).inc()

    def track_rate_limit_hit(self, client_id: str, endpoint: str):
        """Track rate limit violations."""
        self.rate_limit_hits_total.labels(client_id=client_id, endpoint=endpoint).inc()

    # System Metrics
    def update_memory_usage(self, rss: int, vms: int):
        """Update memory usage metrics."""
        self.memory_usage_bytes.labels(type="rss").set(rss)
        self.memory_usage_bytes.labels(type="vms").set(vms)

    def update_uptime(self, seconds: float):
        """Update application uptime."""
        self.uptime_seconds.set(seconds)

    def update_client_count(self, count: int):
        """Update total OAuth clients count."""
        self.oauth_clients_total.set(count)

    def track_client_request(self, client_id: str, endpoint: str):
        """Track requests per OAuth client."""
        self.oauth_client_requests_total.labels(client_id=client_id, endpoint=endpoint).inc()

    # Extended metrics for detailed OAuth service tracking
    def track_token_operation(
        self,
        operation: str,
        status: str,
        client_id: str = "unknown",
        token_type: str = "unknown",
        duration: float = 0.0,
        is_oidc: bool = False,
        extra_data: dict | None = None,
    ):
        """
        Track token service operations with detailed context.

        Args:
            operation: The operation being performed (create_token_pair, refresh_token_pair, revoke_token)
            status: Operation status (success, error, invalid_token, etc.)
            client_id: OAuth client identifier
            token_type: Type of token (access, refresh, pair)
            duration: Operation duration in seconds
            is_oidc: Whether this is an OIDC operation
            extra_data: Additional operation-specific data
        """
        # Use existing OAuth token metrics but with extended labels
        grant_type = "unknown"
        if operation == "create_token_pair":
            grant_type = "authorization_code" if client_id != "unknown" else "password"
        elif operation == "refresh_token_pair":
            grant_type = "refresh_token"
        elif operation == "revoke_token":
            grant_type = "revocation"

        # Track via existing OAuth token request metric
        self.track_oauth_token_request(grant_type, client_id, status, duration)

        # Track OIDC operations as security events if applicable
        if is_oidc:
            self.track_security_event(f"oidc_{operation}", "info")

    def track_client_operation(
        self,
        operation: str,
        status: str,
        client_id: str = "unknown",
        client_type: str = "unknown",
        auth_method: str = "unknown",
        duration: float = 0.0,
    ):
        """
        Track client service operations.

        Args:
            operation: The operation being performed (create_client, authenticate_client)
            status: Operation status (success, error, validation_error, etc.)
            client_id: OAuth client identifier
            client_type: Type of client (public, confidential)
            auth_method: Authentication method used
            duration: Operation duration in seconds
        """
        # Track client operations as client requests
        self.track_client_request(client_id, operation)

        # Track authentication events
        if operation == "authenticate_client":
            auth_status = "success" if status == "success" else "failed"
            self.track_login_attempt(auth_status, auth_method, client_id)

        # Track security events for authentication failures
        if status in ["invalid_secret", "client_not_found", "auth_method_mismatch"]:
            self.track_security_event(f"client_{status}", "warning")

    def track_token_revocation(self, token_type: str, status: str):
        """
        Track token revocation operations.

        Args:
            token_type: Type of token being revoked (access_token, refresh_token, etc.)
            status: Revocation status (success, invalid_token, error)
        """
        # Track as a security event
        self.track_security_event(f"token_revocation_{status}", "info")

        # Also track via OAuth token request metric with revocation grant type
        self.track_oauth_token_request("revocation", "unknown", status, 0.0)

    def track_logout_event(self, user_id: str, status: str, tokens_invalidated: int = 0):
        """
        Track user logout operations.

        Args:
            user_id: User identifier (partially masked for privacy)
            status: Logout status (success, no_active_tokens, error)
            tokens_invalidated: Number of tokens invalidated during logout
        """
        # Track as a security event
        self.track_security_event(f"user_logout_{status}", "info")

        # Track as authentication event
        self.track_login_attempt("logout", "session_end", user_id[:10] + "***" if len(user_id) > 10 else user_id)

        # Update active tokens if tokens were invalidated
        if tokens_invalidated > 0:
            # This is an approximation - in real implementation you'd get actual counts
            pass

    def track_client_authentication(self, client_id: str, status: str, auth_method: str):
        """
        Track OAuth client authentication attempts.

        Args:
            client_id: OAuth client identifier
            status: Authentication status (success, authentication_failed, missing_credentials, error)
            auth_method: Authentication method used (client_secret_basic, client_secret_post, none)
        """
        # Track client authentication via client operation tracking
        self.track_client_operation("authenticate_client", status, client_id, "unknown", auth_method, 0.0)

        # Track security events for failed authentication
        if status in ["authentication_failed", "missing_credentials"]:
            self.track_security_event(f"client_auth_{status}", "warning")


# Global metrics instance
metrics = AuthlyMetrics()


# Metrics endpoint handler
def metrics_handler() -> Response:
    """
    Prometheus metrics endpoint handler.

    Returns:
        Response with Prometheus metrics in text format
    """
    return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)


# Context manager for request timing
class RequestTimer:
    """Context manager for timing HTTP requests."""

    def __init__(self, method: str, endpoint: str):
        self.method = method
        self.endpoint = endpoint
        self.start_time = None

    def __enter__(self):
        """Start timing and track request start."""
        self.start_time = time.time()
        metrics.track_http_request_start(self.method, self.endpoint)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and track request completion."""
        if self.start_time:
            duration = time.time() - self.start_time
            status_code = 500 if exc_type else 200

            metrics.track_http_request(self.method, self.endpoint, status_code, duration)

        metrics.track_http_request_end(self.method, self.endpoint)


# Database query timer
class DatabaseTimer:
    """Context manager for timing database operations."""

    def __init__(self, operation: str):
        self.operation = operation
        self.start_time = None

    def __enter__(self):
        """Start timing database operation."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and record database metrics."""
        if self.start_time:
            duration = time.time() - self.start_time
            status = "error" if exc_type else "success"

            metrics.track_database_query(self.operation, status, duration)
