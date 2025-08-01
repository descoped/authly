"""
Tests for structured logging functionality.
"""

import json
import logging
from io import StringIO
from unittest.mock import patch

import pytest

from authly.logging import (
    LoggingContext,
    StructuredFormatter,
    get_correlation_id,
    set_correlation_id,
    setup_structured_logging,
)
from authly.logging.helpers import (
    log_admin_action,
    log_authentication_event,
    log_oauth_event,
    log_security_event,
    set_client_context,
    set_user_context,
)


class TestLoggingContext:
    """Test correlation ID context management."""

    def test_correlation_id_context(self):
        """Test that correlation ID is properly set and cleared."""
        # Initially no correlation ID
        assert get_correlation_id() is None

        # Set correlation ID in context
        with LoggingContext(correlation_id="test-123"):
            assert get_correlation_id() == "test-123"

        # Should be cleared after context
        assert get_correlation_id() is None

    def test_auto_generated_correlation_id(self):
        """Test that correlation ID is auto-generated if not provided."""
        with LoggingContext() as ctx:
            correlation_id = get_correlation_id()
            assert correlation_id is not None
            assert correlation_id.startswith("req-")
            assert len(correlation_id) == 16  # "req-" + 12 hex chars

    def test_nested_context(self):
        """Test nested logging contexts."""
        with LoggingContext(correlation_id="outer"):
            assert get_correlation_id() == "outer"

            with LoggingContext(correlation_id="inner"):
                assert get_correlation_id() == "inner"

            # Should restore outer context
            assert get_correlation_id() == "outer"


class TestStructuredFormatter:
    """Test JSON logging formatter."""

    def test_basic_json_formatting(self):
        """Test basic JSON log formatting."""
        formatter = StructuredFormatter(service_name="test-service")

        # Create a log record
        logger = logging.getLogger("test.logger")
        record = logger.makeRecord(
            name="test.logger", level=logging.INFO, fn="", lno=0, msg="Test message", args=(), exc_info=None
        )

        # Format the record
        formatted = formatter.format(record)

        # Parse JSON
        log_data = json.loads(formatted)

        # Verify basic structure
        assert log_data["service"] == "test-service"
        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.logger"
        assert log_data["message"] == "Test message"
        assert "timestamp" in log_data

    def test_correlation_id_included(self):
        """Test that correlation ID is included in log output."""
        formatter = StructuredFormatter()
        logger = logging.getLogger("test")

        with LoggingContext(correlation_id="test-correlation"):
            record = logger.makeRecord(
                name="test", level=logging.INFO, fn="", lno=0, msg="Test with correlation", args=(), exc_info=None
            )

            formatted = formatter.format(record)
            log_data = json.loads(formatted)

            assert log_data["correlation_id"] == "test-correlation"

    def test_exception_formatting(self):
        """Test exception formatting in JSON logs."""
        formatter = StructuredFormatter()
        logger = logging.getLogger("test")

        try:
            raise ValueError("Test error")
        except ValueError as e:
            import sys

            exc_info = sys.exc_info()
            record = logger.makeRecord(
                name="test", level=logging.ERROR, fn="", lno=0, msg="Error occurred", args=(), exc_info=exc_info
            )

            formatted = formatter.format(record)
            log_data = json.loads(formatted)

            assert "exception" in log_data
            assert log_data["exception"]["type"] == "ValueError"
            assert log_data["exception"]["message"] == "Test error"
            assert "traceback" in log_data["exception"]

    def test_extra_fields(self):
        """Test that extra fields are included in logs."""
        formatter = StructuredFormatter()
        logger = logging.getLogger("test")

        record = logger.makeRecord(
            name="test", level=logging.INFO, fn="", lno=0, msg="Test with extra", args=(), exc_info=None
        )

        # Add extra fields
        record.user_id = "user-123"
        record.action = "test_action"

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert "extra" in log_data
        assert log_data["extra"]["user_id"] == "user-123"
        assert log_data["extra"]["action"] == "test_action"


class TestLoggingHelpers:
    """Test logging helper functions."""

    @patch("authly.logging.helpers.logger")
    def test_log_oauth_event(self, mock_logger):
        """Test OAuth event logging."""
        log_oauth_event(
            event="token_issued", client_id="client-123", user_id="user-456", grant_type="authorization_code"
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args

        assert "OAuth: token_issued" in call_args[0][0]
        assert call_args[1]["extra"]["event_type"] == "oauth"
        assert call_args[1]["extra"]["oauth_event"] == "token_issued"
        assert call_args[1]["extra"]["client_id"] == "client-123"
        assert call_args[1]["extra"]["user_id"] == "user-456"
        assert call_args[1]["extra"]["grant_type"] == "authorization_code"

    @patch("authly.logging.helpers.logger")
    def test_log_authentication_event_success(self, mock_logger):
        """Test successful authentication event logging."""
        log_authentication_event(event="login_success", user_id="user-123", username="testuser", success=True)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args

        assert "Authentication: login_success" in call_args[0][0]
        assert call_args[1]["extra"]["auth_event"] == "login_success"
        assert call_args[1]["extra"]["success"] is True

    @patch("authly.logging.helpers.logger")
    def test_log_authentication_event_failure(self, mock_logger):
        """Test failed authentication event logging."""
        log_authentication_event(
            event="login_failed", username="testuser", success=False, failure_reason="invalid_password"
        )

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args

        assert "Authentication: login_failed" in call_args[0][0]
        assert call_args[1]["extra"]["success"] is False
        assert call_args[1]["extra"]["failure_reason"] == "invalid_password"

    @patch("authly.logging.helpers.logger")
    def test_log_admin_action(self, mock_logger):
        """Test admin action logging."""
        log_admin_action(
            action="user_created",
            admin_user_id="admin-123",
            target_user_id="user-456",
            resource_type="user",
            changes={"email": "new@example.com"},
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args

        assert "Admin: user_created" in call_args[0][0]
        assert call_args[1]["extra"]["event_type"] == "admin"
        assert call_args[1]["extra"]["admin_action"] == "user_created"
        assert call_args[1]["extra"]["admin_user_id"] == "admin-123"
        assert call_args[1]["extra"]["changes"] == {"email": "new@example.com"}

    @patch("authly.logging.helpers.logger")
    def test_log_security_event_high_severity(self, mock_logger):
        """Test high severity security event logging."""
        log_security_event(event="rate_limit_exceeded", severity="high", user_id="user-123", threat_type="brute_force")

        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args

        assert "Security: rate_limit_exceeded" in call_args[0][0]
        assert call_args[1]["extra"]["severity"] == "high"
        assert call_args[1]["extra"]["threat_type"] == "brute_force"

    def test_set_user_context(self):
        """Test setting user context."""
        with LoggingContext():
            set_user_context(user_id="user-123", username="testuser", roles=["admin"])

            # Context should be available to formatter
            from authly.logging.context import get_request_context

            context = get_request_context()

            assert context["user_id"] == "user-123"
            assert context["username"] == "testuser"
            assert context["user_roles"] == ["admin"]

    def test_set_client_context(self):
        """Test setting client context."""
        with LoggingContext():
            set_client_context(client_id="client-123", client_name="Test App", client_type="public")

            from authly.logging.context import get_request_context

            context = get_request_context()

            assert context["client_id"] == "client-123"
            assert context["client_name"] == "Test App"
            assert context["client_type"] == "public"


class TestLoggingSetup:
    """Test logging setup and configuration."""

    def test_setup_structured_logging_json(self):
        """Test structured logging setup with JSON format."""
        # Capture log output
        log_capture = StringIO()

        # Setup logging
        setup_structured_logging(
            service_name="test-service", service_version="1.0.0", log_level="INFO", json_format=True
        )

        # Get the root logger and replace its handler
        root_logger = logging.getLogger()
        handler = logging.StreamHandler(log_capture)
        handler.setFormatter(StructuredFormatter(service_name="test-service"))

        # Clear existing handlers and add our test handler
        root_logger.handlers.clear()
        root_logger.addHandler(handler)

        # Log a test message
        test_logger = logging.getLogger("test")
        test_logger.info("Test message")

        # Check output
        output = log_capture.getvalue()
        assert output.strip()  # Should have output

        # Parse JSON
        log_data = json.loads(output.strip())
        assert log_data["service"] == "test-service"
        assert log_data["message"] == "Test message"

    def test_setup_structured_logging_text(self):
        """Test structured logging setup with text format."""
        # This should not raise an exception
        setup_structured_logging(service_name="test-service", log_level="DEBUG", json_format=False)

        # Verify logging still works
        logger = logging.getLogger("test")
        logger.info("Test message")  # Should not raise
