"""
Logging context management with correlation IDs.

Provides thread-local storage for correlation IDs and request context
that can be included in all log messages within a request.
"""

import contextvars
import uuid
from typing import Any

# Context variables for correlation tracking
correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)

request_context_var: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("request_context", default=None)


class LoggingContext:
    """
    Context manager for setting logging context including correlation ID.

    Usage:
        with LoggingContext(correlation_id="req-123", user_id="user-456"):
            logger.info("Processing request")  # Will include correlation_id and user_id
    """

    def __init__(self, correlation_id: str | None = None, **context: Any):
        self.correlation_id = correlation_id or generate_correlation_id()
        self.context = context
        self.old_correlation_id = None
        self.old_context = None

    def __enter__(self):
        self.old_correlation_id = correlation_id_var.get()
        self.old_context = request_context_var.get()

        correlation_id_var.set(self.correlation_id)
        request_context_var.set(self.context)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        correlation_id_var.set(self.old_correlation_id)
        request_context_var.set(self.old_context)


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return f"req-{uuid.uuid4().hex[:12]}"


def get_correlation_id() -> str | None:
    """Get the current correlation ID from context."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID in context."""
    correlation_id_var.set(correlation_id)


def get_request_context() -> dict[str, Any]:
    """Get the current request context."""
    return request_context_var.get() or {}


def set_request_context(**context: Any) -> None:
    """Set values in the request context."""
    current_context = request_context_var.get() or {}
    updated_context = {**current_context, **context}
    request_context_var.set(updated_context)


def clear_request_context() -> None:
    """Clear the request context."""
    request_context_var.set({})
