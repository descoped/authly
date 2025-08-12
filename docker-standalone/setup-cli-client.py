#!/usr/bin/env python
"""
Setup script to create the authly-cli OAuth client.

This script registers the special OAuth client used by the Authly CLI
for OAuth 2.0 Authorization Code Flow with PKCE authentication.

Usage:
    python scripts/setup-cli-client.py

Environment Variables:
    AUTHLY_CLI_CALLBACK_PORT: Port for OAuth callback (default: 8899)
    AUTHLY_CLI_REDIRECT_URIS: Additional redirect URIs (comma-separated)
    DATABASE_URL: PostgreSQL connection string
"""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from authly.core import PGDatabase
from authly.oauth.models import OAuthClientCreateRequest, OAuthClientModel
from authly.oauth.repository import OAuthClientRepository


async def create_cli_client():
    """Create the OAuth client for CLI authentication."""

    # Get database URL from environment
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("❌ DATABASE_URL environment variable is required")
        sys.exit(1)

    # Initialize database connection
    database = PGDatabase(database_url)
    await database.init()

    try:
        async with database.connection() as conn:
            # Initialize repository
            client_repo = OAuthClientRepository(conn)

            # Check if client already exists
            existing_client = await client_repo.get_by_client_id("authly-cli")
            if existing_client:
                print("[INFO] CLI OAuth client 'authly-cli' already exists")

                # Update redirect URIs if needed
                callback_port = int(os.getenv("AUTHLY_CLI_CALLBACK_PORT", "8899"))
                redirect_uris = [
                    f"http://localhost:{callback_port}/callback",
                    f"http://127.0.0.1:{callback_port}/callback",
                ]

                # Add any additional redirect URIs from environment
                extra_uris = os.getenv("AUTHLY_CLI_REDIRECT_URIS", "")
                if extra_uris:
                    redirect_uris.extend(extra_uris.split(","))

                # Check if URIs need updating
                existing_uris = set(existing_client.redirect_uris or [])
                new_uris = set(redirect_uris)

                if existing_uris != new_uris:
                    print(f"   Updating redirect URIs from {existing_uris} to {new_uris}")
                    existing_client.redirect_uris = list(new_uris)
                    await client_repo.update(existing_client)
                    print("✅ CLI OAuth client redirect URIs updated")
                else:
                    print("   Redirect URIs are up to date")

                return existing_client

            # Default callback port - can be overridden via env var
            callback_port = int(os.getenv("AUTHLY_CLI_CALLBACK_PORT", "8899"))

            # Build redirect URIs - primary port plus any extras from env
            redirect_uris = [
                f"http://localhost:{callback_port}/callback",
                f"http://127.0.0.1:{callback_port}/callback",  # Alternative localhost
            ]

            # Add any additional redirect URIs from environment
            # Format: AUTHLY_CLI_REDIRECT_URIS="http://localhost:9000/callback,http://localhost:9001/callback"
            extra_uris = os.getenv("AUTHLY_CLI_REDIRECT_URIS", "")
            if extra_uris:
                redirect_uris.extend(extra_uris.split(","))

            print(f"Creating CLI OAuth client with redirect URIs: {redirect_uris}")

            # Create client data
            client_data = OAuthClientCreateRequest(
                client_id="authly-cli",
                client_name="Authly CLI",
                client_type="public",  # Public client (no secret)
                redirect_uris=redirect_uris,
                allowed_scopes=[
                    "admin:clients:read",
                    "admin:clients:write",
                    "admin:scopes:read",
                    "admin:scopes:write",
                    "admin:users:read",
                    "admin:system:read",
                    "openid",
                    "profile",
                    "email",
                ],
                grant_types=["authorization_code"],  # Only auth code flow
                response_types=["code"],
                require_pkce=True,  # OAuth 2.1 mandatory PKCE
            )

            # Create the client
            client_model = OAuthClientModel.from_create_request(client_data)
            created_client = await client_repo.create(client_model)

            print("✅ CLI OAuth client created successfully")
            print(f"   Client ID: {created_client.client_id}")
            print(f"   Client Type: {created_client.client_type}")
            print(f"   Redirect URIs: {created_client.redirect_uris}")
            print(f"   Allowed Scopes: {created_client.allowed_scopes}")

            return created_client

    finally:
        await database.close()


async def main():
    """Main entry point."""
    try:
        await create_cli_client()
        print("\n✅ Setup complete - CLI OAuth client is ready")
        print("   You can now use 'authly admin auth login' to authenticate")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
