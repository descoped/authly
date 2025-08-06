"""
Structured logging system for Authly.

Provides JSON-formatted logging with correlation IDs and structured fields
for better observability in production environments.
"""

from .context import LoggingContext, get_correlation_id, set_correlation_id
from .formatter import StructuredFormatter
from .helpers import (
    log_admin_action,
    log_authentication_event,
    log_database_event,
    log_oauth_event,
    log_security_event,
    set_client_context,
    set_user_context,
)
from .setup import setup_structured_logging

__all__ = [
    "LoggingContext",
    "StructuredFormatter",
    "get_correlation_id",
    "log_admin_action",
    "log_authentication_event",
    "log_database_event",
    "log_oauth_event",
    "log_security_event",
    "set_client_context",
    "set_correlation_id",
    "set_user_context",
    "setup_structured_logging",
]
