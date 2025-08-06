"""Factory for creating mode-appropriate resource managers.

This module provides the AuthlyModeFactory that simplifies bootstrap by
automatically detecting deployment mode and creating appropriately configured
resource managers.
"""

import logging
import os

from authly.config import AuthlyConfig
from authly.core.deployment_modes import DeploymentMode, ModeConfiguration
from authly.core.resource_manager import AuthlyResourceManager

logger = logging.getLogger(__name__)


class AuthlyModeFactory:
    """Factory for creating mode-appropriate resource managers.

    Simplifies bootstrap by automatically detecting deployment mode from
    environment and creating appropriately configured resource managers.

    Key features:
    - Single AUTHLY_MODE environment variable control
    - Automatic mode detection with sensible defaults
    - User-friendly mode aliases (dev, prod, test, etc.)
    - Context validation and error reporting
    """

    @staticmethod
    def detect_mode() -> DeploymentMode:
        """Auto-detect deployment mode from environment.

        Uses the AUTHLY_MODE environment variable with fallback to production.
        Supports user-friendly aliases for ease of use.

        Returns:
            DeploymentMode: The detected deployment mode

        Environment Variables:
            AUTHLY_MODE: Primary mode control variable
                - production, prod -> DeploymentMode.PRODUCTION
                - embedded, embed, dev, development -> DeploymentMode.EMBEDDED
                - cli, admin -> DeploymentMode.CLI
                - testing, test -> DeploymentMode.TESTING
        """
        # Get mode from environment with production default
        mode_env = os.getenv("AUTHLY_MODE", "production").lower().strip()

        # Get alias mapping
        aliases = ModeConfiguration.get_mode_aliases()

        # Resolve mode through aliases
        if mode_env in aliases:
            detected_mode = aliases[mode_env]
            logger.debug(f"Detected deployment mode: {detected_mode.value} (from AUTHLY_MODE={mode_env})")
            return detected_mode
        else:
            # Unknown mode - warn and default to production
            logger.warning(
                f"Unknown AUTHLY_MODE '{mode_env}', defaulting to production. Valid values: {', '.join(aliases.keys())}"
            )
            return DeploymentMode.PRODUCTION

    @staticmethod
    def create_resource_manager(
        config: AuthlyConfig | None = None, mode: DeploymentMode | None = None
    ) -> AuthlyResourceManager:
        """Create resource manager with auto-detection.

        This is the primary entry point for creating resource managers.
        Handles mode detection, configuration loading, and resource manager creation.

        Args:
            config: Application configuration (will load if not provided)
            mode: Deployment mode (will auto-detect if not provided)

        Returns:
            AuthlyResourceManager: Configured resource manager for detected mode

        Raises:
            Exception: If configuration loading fails
        """
        # Auto-detect mode if not provided
        if mode is None:
            mode = AuthlyModeFactory.detect_mode()

        # Load config if not provided
        if config is None:
            logger.debug("Loading configuration from environment providers")
            config = AuthlyModeFactory._load_config()

        # Create mode-specific resource manager
        logger.info(f"Creating resource manager for {mode.value} mode")

        if mode == DeploymentMode.PRODUCTION:
            return AuthlyResourceManager.for_production(config)
        elif mode == DeploymentMode.EMBEDDED:
            return AuthlyResourceManager.for_embedded(config)
        elif mode == DeploymentMode.CLI:
            return AuthlyResourceManager.for_cli(config)
        else:  # TESTING
            return AuthlyResourceManager.for_testing(config)

    @staticmethod
    def _load_config() -> AuthlyConfig:
        """Load configuration using standard environment providers.

        Returns:
            AuthlyConfig: Loaded application configuration

        Raises:
            Exception: If configuration loading fails
        """
        try:
            from authly.config import EnvDatabaseProvider, EnvSecretProvider

            secret_provider = EnvSecretProvider()
            database_provider = EnvDatabaseProvider()
            config = AuthlyConfig.load(secret_provider, database_provider)

            logger.debug("Configuration loaded successfully from environment providers")
            return config

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise RuntimeError("Failed to load configuration: See logs for details") from None

    @staticmethod
    def validate_context_compatibility(context: str, mode: DeploymentMode | None = None) -> DeploymentMode:
        """Validate that deployment mode is compatible with execution context.

        Args:
            context: String describing the execution context
            mode: Deployment mode to validate (will detect if not provided)

        Returns:
            DeploymentMode: Validated (and possibly corrected) deployment mode

        Raises:
            RuntimeError: If mode is incompatible and cannot be corrected
        """
        if mode is None:
            mode = AuthlyModeFactory.detect_mode()

        try:
            ModeConfiguration.validate_mode_compatibility(mode, context)
            logger.debug(f"Mode {mode.value} validated for context '{context}'")
            return mode
        except RuntimeError as e:
            logger.error(f"Mode validation failed: {e}")
            raise RuntimeError("An error occurred") from None

    @staticmethod
    def get_mode_info() -> dict:
        """Get information about current mode detection and available modes.

        Returns:
            Dictionary containing mode detection information and available options
        """
        current_mode = AuthlyModeFactory.detect_mode()
        aliases = ModeConfiguration.get_mode_aliases()

        # Group aliases by mode
        mode_groups = {}
        for alias, mode in aliases.items():
            if mode not in mode_groups:
                mode_groups[mode] = []
            mode_groups[mode].append(alias)

        return {
            "current_mode": current_mode.value,
            "env_var": os.getenv("AUTHLY_MODE", "production"),
            "available_modes": {mode.value: aliases_list for mode, aliases_list in mode_groups.items()},
            "detection_source": "AUTHLY_MODE environment variable",
        }


# Convenience functions for common mode detection scenarios


def is_production_mode() -> bool:
    """Check if running in production mode.

    Returns:
        True if current mode is production, False otherwise
    """
    return AuthlyModeFactory.detect_mode() == DeploymentMode.PRODUCTION


def is_development_mode() -> bool:
    """Check if running in development/embedded mode.

    Returns:
        True if current mode is embedded/development, False otherwise
    """
    return AuthlyModeFactory.detect_mode() == DeploymentMode.EMBEDDED


def is_cli_mode() -> bool:
    """Check if running in CLI/admin mode.

    Returns:
        True if current mode is CLI, False otherwise
    """
    return AuthlyModeFactory.detect_mode() == DeploymentMode.CLI


def is_testing_mode() -> bool:
    """Check if running in testing mode.

    Returns:
        True if current mode is testing, False otherwise
    """
    return AuthlyModeFactory.detect_mode() == DeploymentMode.TESTING
