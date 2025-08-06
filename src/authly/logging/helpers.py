"""
Helper functions for structured logging in specific Authly contexts.

Provides convenient logging functions for common scenarios like OAuth flows,
user authentication, admin actions, etc.
"""

import logging
from typing import Any

from .context import set_request_context

logger = logging.getLogger(__name__)


def log_oauth_event(
    event: str,
    client_id: str | None = None,
    user_id: str | None = None,
    scope: str | None = None,
    grant_type: str | None = None,
    **extra: Any,
) -> None:
    """
    Log OAuth-related events with structured context.

    Args:
        event: The OAuth event (e.g., "authorization_requested", "token_issued")
        client_id: OAuth client identifier
        user_id: User identifier
        scope: Requested OAuth scopes
        grant_type: OAuth grant type
        **extra: Additional context fields
    """
    context = {
        "event_type": "oauth",
        "oauth_event": event,
    }

    if client_id:
        context["client_id"] = client_id
    if user_id:
        context["user_id"] = user_id
    if scope:
        context["scope"] = scope
    if grant_type:
        context["grant_type"] = grant_type

    context.update(extra)

    logger.info(f"OAuth: {event}", extra=context)


def log_authentication_event(
    event: str,
    user_id: str | None = None,
    username: str | None = None,
    success: bool | None = None,
    failure_reason: str | None = None,
    **extra: Any,
) -> None:
    """
    Log authentication events with structured context.

    Args:
        event: The auth event (e.g., "login_attempt", "login_success", "login_failed")
        user_id: User identifier
        username: Username (if different from user_id)
        success: Whether the authentication was successful
        failure_reason: Reason for authentication failure
        **extra: Additional context fields
    """
    context = {
        "event_type": "authentication",
        "auth_event": event,
    }

    if user_id:
        context["user_id"] = user_id
    if username:
        context["username"] = username
    if success is not None:
        context["success"] = success
    if failure_reason:
        context["failure_reason"] = failure_reason

    context.update(extra)

    if success is False:
        logger.warning(f"Authentication: {event}", extra=context)
    else:
        logger.info(f"Authentication: {event}", extra=context)


def log_admin_action(
    action: str,
    admin_user_id: str | None = None,
    target_user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    changes: dict[str, Any] | None = None,
    **extra: Any,
) -> None:
    """
    Log administrative actions with structured context.

    Args:
        action: The admin action (e.g., "user_created", "client_deleted")
        admin_user_id: ID of the admin performing the action
        target_user_id: ID of the user being acted upon (if applicable)
        resource_type: Type of resource (e.g., "user", "client", "scope")
        resource_id: ID of the resource being acted upon
        changes: Dictionary of changes made
        **extra: Additional context fields
    """
    context = {
        "event_type": "admin",
        "admin_action": action,
    }

    if admin_user_id:
        context["admin_user_id"] = admin_user_id
    if target_user_id:
        context["target_user_id"] = target_user_id
    if resource_type:
        context["resource_type"] = resource_type
    if resource_id:
        context["resource_id"] = resource_id
    if changes:
        context["changes"] = changes

    context.update(extra)

    logger.info(f"Admin: {action}", extra=context)


def log_security_event(
    event: str,
    severity: str = "medium",
    user_id: str | None = None,
    client_id: str | None = None,
    threat_type: str | None = None,
    details: dict[str, Any] | None = None,
    **extra: Any,
) -> None:
    """
    Log security-related events with structured context.

    Args:
        event: The security event (e.g., "rate_limit_exceeded", "invalid_token")
        severity: Event severity (low, medium, high, critical)
        user_id: User identifier (if applicable)
        client_id: Client identifier (if applicable)
        threat_type: Type of security threat
        details: Additional security details
        **extra: Additional context fields
    """
    context = {
        "event_type": "security",
        "security_event": event,
        "severity": severity,
    }

    if user_id:
        context["user_id"] = user_id
    if client_id:
        context["client_id"] = client_id
    if threat_type:
        context["threat_type"] = threat_type
    if details:
        context["details"] = details

    context.update(extra)

    # Log at appropriate level based on severity
    if severity in ("high", "critical"):
        logger.error(f"Security: {event}", extra=context)
    elif severity == "medium":
        logger.warning(f"Security: {event}", extra=context)
    else:
        logger.info(f"Security: {event}", extra=context)


def log_database_event(
    event: str,
    operation: str | None = None,
    table: str | None = None,
    duration_ms: float | None = None,
    rows_affected: int | None = None,
    error: str | None = None,
    **extra: Any,
) -> None:
    """
    Log database-related events with structured context.

    Args:
        event: The database event (e.g., "query_executed", "connection_error")
        operation: Database operation (SELECT, INSERT, UPDATE, DELETE)
        table: Database table name
        duration_ms: Query duration in milliseconds
        rows_affected: Number of rows affected
        error: Error message (if applicable)
        **extra: Additional context fields
    """
    context = {
        "event_type": "database",
        "db_event": event,
    }

    if operation:
        context["operation"] = operation
    if table:
        context["table"] = table
    if duration_ms is not None:
        context["duration_ms"] = duration_ms
    if rows_affected is not None:
        context["rows_affected"] = rows_affected
    if error:
        context["error"] = error

    context.update(extra)

    if error:
        logger.error(f"Database: {event}", extra=context)
    else:
        logger.debug(f"Database: {event}", extra=context)


def set_user_context(user_id: str, username: str | None = None, roles: list | None = None) -> None:
    """
    Set user context for all subsequent log messages in the current request.

    Args:
        user_id: User identifier
        username: Username (optional)
        roles: User roles (optional)
    """
    context = {"user_id": user_id}

    if username:
        context["username"] = username
    if roles:
        context["user_roles"] = roles

    set_request_context(**context)


def set_client_context(client_id: str, client_name: str | None = None, client_type: str | None = None) -> None:
    """
    Set OAuth client context for all subsequent log messages in the current request.

    Args:
        client_id: Client identifier
        client_name: Client name (optional)
        client_type: Client type (optional)
    """
    context = {"client_id": client_id}

    if client_name:
        context["client_name"] = client_name
    if client_type:
        context["client_type"] = client_type

    set_request_context(**context)
