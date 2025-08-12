#!/usr/bin/env python3
"""
Create OAuth clients directly in the database for testing.
This creates a confidential admin client with client_credentials grant
and a public test client for OAuth 2.1 compliance testing.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add authly to path
sys.path.insert(0, "/app")

from authly.config import AuthlyConfig
from authly.database.connection import get_connection
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, GrantType
from authly.oauth.scope_repository import ScopeRepository


async def create_clients():
    """Create OAuth clients for testing."""

    # Initialize repositories
    config = AuthlyConfig()
    conn = await get_connection(config)
    client_repo = ClientRepository(conn)
    ScopeRepository(conn)

    print("🔧 Creating OAuth Clients...")
    print("━" * 50)

    try:
        # Create admin client with client_credentials grant
        admin_client = await client_repo.create_client(
            client_name="Admin API Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["http://localhost:8080/admin"],
            grant_types=[GrantType.CLIENT_CREDENTIALS],
            scope="admin:clients:read admin:clients:write admin:users:read admin:users:write",
            require_pkce=False,  # Not needed for client_credentials
        )

        print("✅ Created Admin Client:")
        print(f"   Client ID:     {admin_client.client_id}")
        print(f"   Client Secret: {admin_client.client_secret}")
        print(f"   Type:          {admin_client.client_type}")
        print(f"   Grant Types:   {', '.join(str(g) for g in admin_client.grant_types)}")
        print()

        # Save admin config
        admin_config = {
            "admin_client_id": admin_client.client_id,
            "admin_client_secret": admin_client.client_secret,
            "client_type": admin_client.client_type.value,
            "grant_types": [g.value for g in admin_client.grant_types],
            "scope": admin_client.scope,
        }

        Path("/app/tester-data").mkdir(exist_ok=True)
        with open("/app/tester-data/admin-config.json", "w") as f:
            json.dump(admin_config, f, indent=2)
        print("📝 Admin config saved to /app/tester-data/admin-config.json")

        # Create test client for OAuth 2.1 compliance
        test_client = await client_repo.create_client(
            client_name="Compliance Test Client",
            client_type=ClientType.PUBLIC,
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
            scope="openid profile email",
            require_pkce=True,  # OAuth 2.1 requirement
        )

        print()
        print("✅ Created Test Client:")
        print(f"   Client ID:     {test_client.client_id}")
        print(f"   Type:          {test_client.client_type}")
        print(f"   Grant Types:   {', '.join(str(g) for g in test_client.grant_types)}")
        print(f"   PKCE Required: {test_client.require_pkce}")

        # Save test config
        test_config = {
            "client_id": test_client.client_id,
            "client_name": test_client.client_name,
            "client_type": test_client.client_type.value,
            "redirect_uris": test_client.redirect_uris,
            "grant_types": [g.value for g in test_client.grant_types],
            "scope": test_client.scope,
            "require_pkce": test_client.require_pkce,
        }

        with open("/app/tester-data/test-config.json", "w") as f:
            json.dump(test_config, f, indent=2)
        print("📝 Test config saved to /app/tester-data/test-config.json")

        print()
        print("✅ Setup complete! The compliance tester can now:")
        print("   1. Use client_credentials to get admin access tokens")
        print("   2. Use the admin API to manage clients dynamically")
        print("   3. Run OAuth 2.1 compliance tests")

    except Exception as e:
        print(f"❌ Error creating clients: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(create_clients())
