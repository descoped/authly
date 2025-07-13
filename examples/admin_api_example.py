"""
Example usage of the Admin API Client.

This script demonstrates how to use the AdminAPIClient for various
administrative operations through the HTTP API.
"""

import asyncio
import logging
from pathlib import Path

from authly.admin.api_client import AdminAPIClient
from authly.oauth.models import ClientType, OAuthClientCreateRequest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def main():
    """Demonstrate Admin API Client usage."""
    
    # Initialize the client
    # In production, use the actual API URL
    api_url = "http://localhost:8000"
    
    async with AdminAPIClient(base_url=api_url) as client:
        print(f"Admin API Client initialized for {api_url}")
        
        # Check health (no authentication required)
        try:
            health = await client.get_health()
            print(f"Health check: {health}")
        except Exception as e:
            print(f"Health check failed: {e}")
            return
        
        # Login
        print("\n--- Authentication ---")
        try:
            # In production, use secure credential input
            username = input("Admin username: ")
            password = input("Admin password: ")
            
            token_info = await client.login(
                username=username,
                password=password,
                scope="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write"
            )
            
            print(f"Successfully logged in!")
            print(f"Token expires at: {token_info.expires_at}")
            print(f"Scopes: {token_info.scope}")
        except Exception as e:
            print(f"Login failed: {e}")
            return
        
        # Get system status
        print("\n--- System Status ---")
        try:
            status = await client.get_status()
            print(f"System status: {status}")
        except Exception as e:
            print(f"Failed to get status: {e}")
        
        # List OAuth clients
        print("\n--- OAuth Clients ---")
        try:
            clients = await client.list_clients(active_only=True, limit=5)
            print(f"Found {len(clients)} active clients:")
            for c in clients:
                print(f"  - {c.client_name} ({c.client_id}): {c.client_type}")
        except Exception as e:
            print(f"Failed to list clients: {e}")
        
        # Create a new client
        print("\n--- Create New Client ---")
        try:
            create_new = input("Create a new test client? (y/n): ").lower() == 'y'
            
            if create_new:
                request = OAuthClientCreateRequest(
                    client_name="API Test Client",
                    client_type=ClientType.CONFIDENTIAL,
                    redirect_uris=["http://localhost:3000/callback"],
                    description="Test client created via API"
                )
                
                client, secret = await client.create_client(request)
                print(f"Created client: {client.client_name} ({client.client_id})")
                if secret:
                    print(f"Client secret: {secret}")
                    print("⚠️  Save this secret securely - it cannot be retrieved later!")
        except Exception as e:
            print(f"Failed to create client: {e}")
        
        # List OAuth scopes
        print("\n--- OAuth Scopes ---")
        try:
            scopes = await client.list_scopes(active_only=True)
            print(f"Found {len(scopes)} active scopes:")
            for s in scopes:
                default = " (default)" if s.is_default else ""
                print(f"  - {s.name}: {s.description}{default}")
        except Exception as e:
            print(f"Failed to list scopes: {e}")
        
        # Get default scopes
        print("\n--- Default Scopes ---")
        try:
            defaults = await client.get_default_scopes()
            print(f"Default scopes: {', '.join(s.name for s in defaults)}")
        except Exception as e:
            print(f"Failed to get default scopes: {e}")
        
        # Demonstrate token refresh
        print("\n--- Token Management ---")
        if client._token_info and client._token_info.refresh_token:
            try:
                print("Refreshing token...")
                new_token = await client.refresh_token()
                print(f"Token refreshed! New expiration: {new_token.expires_at}")
            except Exception as e:
                print(f"Failed to refresh token: {e}")
        
        # Logout
        print("\n--- Logout ---")
        try:
            await client.logout()
            print("Successfully logged out and revoked tokens")
        except Exception as e:
            print(f"Logout failed: {e}")
        
        # Verify we're logged out
        print(f"Is authenticated: {client.is_authenticated}")


if __name__ == "__main__":
    asyncio.run(main())