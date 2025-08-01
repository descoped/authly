"""Version management for Authly."""

import os
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def get_version() -> str:
    """
    Get the version of Authly.

    Tries multiple methods in order of preference:
    1. Installed package metadata (importlib.metadata)
    2. pyproject.toml file (for development)
    3. Fallback to a default version

    Returns:
        Version string
    """
    # Try to get version from installed package metadata
    try:
        return version("authly")
    except PackageNotFoundError:
        pass

    # Try to read from pyproject.toml (development mode)
    try:
        # Look for pyproject.toml in the project root
        current_file = Path(__file__)
        # Go up from src/authly/_version.py to find pyproject.toml
        for parent in current_file.parents:
            pyproject_path = parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    data = tomllib.load(f)
                    return data["project"]["version"]
    except (FileNotFoundError, KeyError, tomllib.TOMLDecodeError):
        pass

    # Try environment variable (for Docker builds)
    if version_env := os.getenv("AUTHLY_VERSION"):
        return version_env

    # Fallback version
    return "0.0.0-dev"


# Cache the version for performance
__version__ = get_version()
