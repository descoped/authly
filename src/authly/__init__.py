"""
Authly - Modern OAuth 2.1 and OpenID Connect Authentication Service

This package provides a clean, dependency-injection based authentication service
built on FastAPI and modern Python patterns.

Core Components:
- AuthlyResourceManager: Manages database connections and configuration
- FastAPI dependencies: Provide services through dependency injection
- Clean service layer: No global state or singleton patterns

Usage:
```python
from authly.core.resource_manager import AuthlyResourceManager
from authly.core.dependencies import create_resource_manager_provider, get_resource_manager

# Initialize resource manager
resource_manager = AuthlyResourceManager(config)

# Use with FastAPI (in lifespan context)
provider = create_resource_manager_provider(resource_manager)
app.dependency_overrides[get_resource_manager] = provider
```
"""

# Clean exports - only essential types for external use
from authly.config.config import AuthlyConfig
from authly.core.resource_manager import AuthlyResourceManager

__all__ = [
    "AuthlyConfig",
    "AuthlyResourceManager",
    "__version__",
]

# Import version dynamically
from authly._version import __version__
