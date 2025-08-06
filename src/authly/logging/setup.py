"""
Structured logging setup and configuration.

Configures logging to use structured JSON format with correlation IDs
while maintaining compatibility with existing logging configuration.
"""

import logging
import os

from .formatter import StructuredFormatter


def setup_structured_logging(
    service_name: str = "authly",
    service_version: str | None = None,
    log_level: str | None = None,
    json_format: bool = True,
    include_location: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        service_name: Name of the service for log identification
        service_version: Version of the service (optional)
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Whether to use JSON formatting (True) or plain text (False)
        include_location: Whether to include file/line location in logs
    """
    # Determine log level from parameter or environment
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Determine format from environment if not explicitly specified
    if json_format is None:
        json_format = os.getenv("LOG_JSON", "true").lower() in ("true", "1", "yes")

    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler()

    if json_format:
        # Use structured JSON formatter
        formatter = StructuredFormatter(
            service_name=service_name,
            service_version=service_version,
            include_location=include_location,
        )
    else:
        # Use traditional text formatter for development
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    console_handler.setFormatter(formatter)

    # Configure root logger
    root_logger.setLevel(getattr(logging, log_level))
    root_logger.addHandler(console_handler)

    # Configure specific loggers
    _configure_logger_levels(log_level)

    # Log the configuration
    logger = logging.getLogger(__name__)
    logger.info(
        "Structured logging configured",
        extra={
            "service_name": service_name,
            "service_version": service_version,
            "log_level": log_level,
            "json_format": json_format,
            "include_location": include_location,
        },
    )


def _configure_logger_levels(log_level: str) -> None:
    """Configure specific logger levels."""
    # Authly application loggers
    logging.getLogger("authly").setLevel(log_level)

    # Third-party library loggers
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)

    # Database loggers (can be noisy)
    logging.getLogger("psycopg").setLevel(logging.WARNING)
    logging.getLogger("psycopg.pool").setLevel(logging.WARNING)

    # Adjust access log level based on environment
    access_log_level = os.getenv("ACCESS_LOG_LEVEL", "INFO").upper()
    logging.getLogger("uvicorn.access").setLevel(getattr(logging, access_log_level))


def get_service_version() -> str | None:
    """Get the service version from package metadata."""
    try:
        from importlib.metadata import version

        return version("authly")
    except Exception:
        return None
