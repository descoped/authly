#!/usr/bin/env python3
"""
Add database and cache scopes for OAuth proxy authentication.
This script adds the necessary scopes for the database proxy proof-of-concept.
"""

import asyncio
import sys
from pathlib import Path
from uuid import uuid4

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authly.core.database import get_configuration, get_database
from authly.oauth.scope_repository import ScopeRepository


async def add_database_scopes():
    """Add database and cache scopes to Authly."""

    print("Loading configuration...")
    async with get_configuration() as config, get_database(config) as database:
        print("Initializing database connection...")
        # Get connection from the database instance
        async with database.connection() as conn:
            # Create scope repository
            scope_repo = ScopeRepository(conn)

            # Define scopes to add
            scopes = [
                {
                    "id": uuid4(),
                    "scope_name": "database:read",
                    "description": "Read access to database (SELECT queries)",
                    "is_default": False,
                    "is_active": True,
                },
                {
                    "id": uuid4(),
                    "scope_name": "database:write",
                    "description": "Write access to database (INSERT, UPDATE, DELETE)",
                    "is_default": False,
                    "is_active": True,
                },
                {
                    "id": uuid4(),
                    "scope_name": "cache:read",
                    "description": "Read access to cache/Redis (GET operations)",
                    "is_default": False,
                    "is_active": True,
                },
                {
                    "id": uuid4(),
                    "scope_name": "cache:write",
                    "description": "Write access to cache/Redis (SET, DEL operations)",
                    "is_default": False,
                    "is_active": True,
                },
            ]

            # Add each scope
            for scope_data in scopes:
                try:
                    # Check if scope already exists
                    existing = await scope_repo.get_by_scope_name(scope_data["scope_name"])
                    if existing:
                        print(f"✓ Scope '{scope_data['scope_name']}' already exists")
                    else:
                        # Create new scope
                        new_scope = await scope_repo.create_scope(scope_data)
                        print(f"✅ Created scope '{new_scope.scope_name}' with ID {new_scope.id}")
                except Exception as e:
                    print(f"❌ Error creating scope '{scope_data['scope_name']}': {e}")

            print("\n✅ Database scopes setup complete!")


if __name__ == "__main__":
    asyncio.run(add_database_scopes())
