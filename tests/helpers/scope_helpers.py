"""Helper functions for managing OAuth scopes in tests."""

from contextlib import suppress
from uuid import uuid4

from authly.oauth.scope_repository import ScopeRepository


async def ensure_scope_exists(scope_repo: ScopeRepository, scope_name: str, description: str = None) -> None:
    """
    Ensure a scope exists, creating it if necessary.

    This helper handles the duplicate key error gracefully,
    making tests more resilient to parallel execution and reruns.
    """
    with suppress(Exception):
        # Scope already exists, that's fine
        await scope_repo.create_scope(
            {
                "scope_name": scope_name,
                "description": description or f"{scope_name} access",
                "is_default": False,
                "is_active": True,
            }
        )


async def create_unique_scope(scope_repo: ScopeRepository, base_name: str, description: str = None) -> str:
    """
    Create a unique scope with a random suffix.

    This ensures no conflicts between test runs.
    """
    unique_name = f"{base_name}_{uuid4().hex[:8]}"
    await scope_repo.create_scope(
        {
            "scope_name": unique_name,
            "description": description or f"{base_name} access",
            "is_default": False,
            "is_active": True,
        }
    )
    return unique_name
