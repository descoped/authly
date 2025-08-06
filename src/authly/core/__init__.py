"""Core infrastructure for dependency injection pattern.

This module provides the foundational infrastructure for FastAPI
dependency injection using AuthlyResourceManager.
"""

from .database import get_configuration, get_database_pool
from .dependencies import (
    get_config,
    get_database_connection,
    get_database_pool as get_database_pool_dependency,
    get_resource_manager,
)

__all__ = [
    "get_config",
    # Database lifecycle management
    "get_configuration",
    "get_database_connection",
    "get_database_pool",
    "get_database_pool_dependency",
    # FastAPI dependencies (modern)
    "get_resource_manager",
]
