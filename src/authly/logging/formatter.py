"""
Structured JSON logging formatter.

Formats log records as JSON with correlation IDs and structured fields
for better observability and parsing in log aggregation systems.
"""

import json
import logging
import traceback
from datetime import UTC, datetime
from typing import Any

from .context import get_correlation_id, get_request_context


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter that includes correlation IDs and structured context.

    Produces log records in JSON format with the following structure:
    {
        "timestamp": "2025-08-01T14:30:00.123456Z",
        "level": "INFO",
        "logger": "authly.api.oauth_router",
        "message": "Processing OAuth authorization request",
        "correlation_id": "req-abc123def456",
        "context": {
            "user_id": "user-123",
            "client_id": "client-456"
        },
        "exception": {
            "type": "ValueError",
            "message": "Invalid client_id",
            "traceback": ["line1", "line2", ...]
        }
    }
    """

    def __init__(
        self,
        service_name: str = "authly",
        service_version: str | None = None,
        include_location: bool = False,
    ):
        super().__init__()
        self.service_name = service_name
        self.service_version = service_version
        self.include_location = include_location

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        # Base log structure
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add service version if available
        if self.service_version:
            log_entry["service_version"] = self.service_version

        # Add correlation ID if available
        correlation_id = get_correlation_id()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        # Add request context if available
        context = get_request_context()
        if context:
            log_entry["context"] = context

        # Add location information if requested
        if self.include_location:
            log_entry["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add thread information for debugging
        if record.thread:
            log_entry["thread_id"] = record.thread

        if record.process:
            log_entry["process_id"] = record.process

        # Handle exceptions
        if record.exc_info and record.exc_info != (None, None, None):
            log_entry["exception"] = self._format_exception(record.exc_info)

        # Add any extra fields from the log record
        extra_fields = self._extract_extra_fields(record)
        if extra_fields:
            log_entry["extra"] = extra_fields

        return json.dumps(log_entry, ensure_ascii=False, separators=(",", ":"))

    def _format_exception(self, exc_info) -> dict[str, Any]:
        """Format exception information."""
        exc_type, exc_value, exc_traceback = exc_info

        return {
            "type": exc_type.__name__ if exc_type else None,
            "message": str(exc_value) if exc_value else None,
            "traceback": traceback.format_exception(exc_type, exc_value, exc_traceback),
        }

    def _extract_extra_fields(self, record: logging.LogRecord) -> dict[str, Any]:
        """Extract extra fields from the log record."""
        # Standard fields that should not be included in extra
        standard_fields = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "getMessage",
            "extra",
        }

        extra = {}
        for key, value in record.__dict__.items():
            if key not in standard_fields and not key.startswith("_"):
                # Only include JSON-serializable values
                try:
                    json.dumps(value)
                    extra[key] = value
                except (TypeError, ValueError):
                    extra[key] = str(value)

        return extra
