"""Deployment modes and configurations for Authly.

This module defines the supported deployment modes and their specific
configurations for the unified resource manager architecture.
"""

from enum import Enum
from typing import Any


class DeploymentMode(Enum):
    """Supported deployment modes for Authly.

    Each mode represents a different operational context with optimized
    settings for resource management and initialization.
    """

    PRODUCTION = "production"  # Multi-worker, FastAPI lifespan managed
    EMBEDDED = "embedded"  # Self-contained with testcontainer
    CLI = "cli"  # Direct database access for admin tasks
    TESTING = "testing"  # Test-specific with dependency overrides


class ModeConfiguration:
    """Mode-specific configuration and behavior settings.

    Provides optimized settings for each deployment mode including
    database pool configurations, bootstrap behavior, and lifecycle management.
    """

    @staticmethod
    def get_pool_settings(mode: DeploymentMode) -> dict[str, Any]:
        """Get database pool configuration optimized for deployment mode.

        Args:
            mode: The deployment mode to configure for

        Returns:
            Dictionary containing pool configuration parameters
        """
        if mode == DeploymentMode.PRODUCTION:
            # Production: Larger pool for multi-worker scaling
            return {
                "min_size": 5,
                "max_size": 20,
                "timeout": 30.0,
                "max_idle": 300.0,  # 5 minutes
                "reconnect_timeout": 5.0,
            }
        elif mode == DeploymentMode.EMBEDDED:
            # Embedded: Medium pool for development
            return {
                "min_size": 2,
                "max_size": 8,
                "timeout": 15.0,
                "max_idle": 180.0,  # 3 minutes
                "reconnect_timeout": 2.0,
            }
        elif mode == DeploymentMode.CLI:
            # CLI: Minimal pool for short-lived operations
            return {
                "min_size": 1,
                "max_size": 3,
                "timeout": 10.0,
                "max_idle": 60.0,  # 1 minute
                "reconnect_timeout": 1.0,
            }
        else:  # TESTING
            # Testing: Flexible pool for test parallelization
            return {
                "min_size": 1,
                "max_size": 10,
                "timeout": 5.0,
                "max_idle": 30.0,  # 30 seconds
                "reconnect_timeout": 0.5,
            }

    @staticmethod
    def should_bootstrap_admin(mode: DeploymentMode) -> bool:
        """Determine if admin system bootstrap should run in deployment mode.

        Args:
            mode: The deployment mode to check

        Returns:
            True if admin bootstrap should run, False otherwise
        """
        if mode == DeploymentMode.PRODUCTION:
            # Production: Controlled by environment variable
            import os

            return os.getenv("AUTHLY_BOOTSTRAP_ENABLED", "true").lower() == "true"
        elif mode == DeploymentMode.EMBEDDED:
            # Embedded: Always bootstrap for development convenience
            return True
        elif mode == DeploymentMode.CLI:
            # CLI: Assume existing setup, don't bootstrap
            return False
        else:  # TESTING
            # Testing: Let tests manage bootstrap explicitly
            return False

    @staticmethod
    def get_lifecycle_strategy(mode: DeploymentMode) -> str:
        """Get resource lifecycle management strategy for deployment mode.

        Args:
            mode: The deployment mode to configure

        Returns:
            String identifier for lifecycle strategy
        """
        if mode == DeploymentMode.PRODUCTION:
            return "fastapi_lifespan"  # Managed by FastAPI lifespan events
        elif mode == DeploymentMode.EMBEDDED:
            return "self_managed"  # Self-contained lifecycle
        elif mode == DeploymentMode.CLI:
            return "context_managed"  # Short-lived context managers
        else:  # TESTING
            return "fixture_managed"  # Managed by test fixtures

    @staticmethod
    def get_mode_aliases() -> dict[str, DeploymentMode]:
        """Get mapping of mode aliases to deployment modes.

        Provides user-friendly aliases for the AUTHLY_MODE environment variable.

        Returns:
            Dictionary mapping alias strings to DeploymentMode values
        """
        return {
            # Production aliases
            "production": DeploymentMode.PRODUCTION,
            "prod": DeploymentMode.PRODUCTION,
            # Embedded development aliases
            "embedded": DeploymentMode.EMBEDDED,
            "embed": DeploymentMode.EMBEDDED,
            "dev": DeploymentMode.EMBEDDED,
            "development": DeploymentMode.EMBEDDED,
            # CLI/Admin aliases
            "cli": DeploymentMode.CLI,
            "admin": DeploymentMode.CLI,
            # Testing aliases
            "testing": DeploymentMode.TESTING,
            "test": DeploymentMode.TESTING,
        }

    @staticmethod
    def validate_mode_compatibility(mode: DeploymentMode, context: str) -> None:
        """Validate that deployment mode is compatible with execution context.

        Args:
            mode: The detected deployment mode
            context: String describing the execution context

        Raises:
            RuntimeError: If mode is incompatible with context
        """
        # Context-specific validations
        if context == "fastapi_production" and mode != DeploymentMode.PRODUCTION:
            raise RuntimeError(f"FastAPI production entry point requires PRODUCTION mode, got {mode.value}")

        if context == "embedded_server" and mode != DeploymentMode.EMBEDDED:
            # Allow embedded server to force its mode
            import os

            os.environ["AUTHLY_MODE"] = DeploymentMode.EMBEDDED.value

        if (
            context == "pytest"
            and mode not in [DeploymentMode.TESTING, DeploymentMode.EMBEDDED]
            and mode != DeploymentMode.EMBEDDED
        ):
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"Tests detected {mode.value} mode, consider AUTHLY_MODE=testing for optimal test performance"
            )
