# Admin API Client Documentation

The `AdminAPIClient` provides a Python HTTP client for interacting with the Authly Admin API. It handles authentication, token management, and provides convenient methods for all admin operations.

## Installation

The Admin API Client is included with Authly when you install with admin extras:

```bash
pip install authly[admin]
```

## Basic Usage

```python
from authly.admin.api_client import AdminAPIClient

# Initialize the client
async with AdminAPIClient(base_url="http://localhost:8000") as client:
    # Login with admin credentials
    await client.login(username="admin", password="your-password")
    
    # Perform admin operations
    clients = await client.list_clients()
    
    # Logout when done
    await client.logout()
```

## Authentication

The Admin API Client uses the OAuth 2.1 Resource Owner Password Credentials flow for authentication:

```python
# Login with specific scopes
token_info = await client.login(
    username="admin",
    password="secure-password",
    scope="admin:clients:read admin:clients:write"
)

# Check authentication status
if client.is_authenticated:
    print("Successfully authenticated")

# Token information
print(f"Token expires at: {token_info.expires_at}")
print(f"Granted scopes: {token_info.scope}")
```

## Token Management

Tokens are automatically stored securely in `~/.authly/tokens.json` with restricted permissions (600):

```python
# Tokens are automatically loaded on client initialization
client = AdminAPIClient(base_url="http://localhost:8000")

# Manually refresh token
if client.is_authenticated:
    new_token = await client.refresh_token()

# Tokens are automatically refreshed when needed
await client.ensure_authenticated()
```

## OAuth Client Management

### List Clients

```python
# List all active clients
clients = await client.list_clients(active_only=True, limit=100, offset=0)

for client in clients:
    print(f"{client.client_name} ({client.client_id}): {client.client_type}")
```

### Create Client

```python
from authly.oauth.models import OAuthClientCreateRequest, ClientType

request = OAuthClientCreateRequest(
    client_name="My Application",
    client_type=ClientType.CONFIDENTIAL,
    redirect_uris=["https://myapp.com/callback"],
    description="Production application"
)

client, client_secret = await client.create_client(request)

# Save the client_secret securely - it cannot be retrieved later!
if client_secret:
    print(f"Client Secret: {client_secret}")
```

### Get Client

```python
client = await client.get_client("client_id_here")
print(f"Client: {client.client_name}")
print(f"Redirect URIs: {client.redirect_uris}")
```

### Update Client

```python
updated_client = await client.update_client(
    "client_id_here",
    {
        "description": "Updated description",
        "redirect_uris": ["https://newapp.com/callback"],
        "is_active": True
    }
)
```

### Regenerate Client Secret

```python
# Only for confidential clients
credentials = await client.regenerate_client_secret("client_id_here")
print(f"New Client Secret: {credentials.client_secret}")
```

### Delete Client

```python
# Soft delete (deactivates the client)
result = await client.delete_client("client_id_here")
print(result["message"])
```

## OAuth Scope Management

### List Scopes

```python
# List all active scopes
scopes = await client.list_scopes(active_only=True)

for scope in scopes:
    default = " (default)" if scope.is_default else ""
    print(f"{scope.name}: {scope.description}{default}")
```

### Create Scope

```python
new_scope = await client.create_scope(
    name="custom:read",
    description="Read access to custom resources",
    is_default=False
)
```

### Get Default Scopes

```python
default_scopes = await client.get_default_scopes()
print(f"Default scopes: {[s.name for s in default_scopes]}")
```

### Update Scope

```python
updated_scope = await client.update_scope(
    "custom:read",
    description="Updated description",
    is_default=True,
    is_active=True
)
```

### Delete Scope

```python
# Soft delete (deactivates the scope)
result = await client.delete_scope("custom:read")
```

## System Administration

### Health Check

```python
# No authentication required
health = await client.get_health()
print(f"Admin API Status: {health['status']}")
```

### System Status

```python
# Requires authentication
status = await client.get_status()
print(f"Database Connected: {status['database']['connected']}")
print(f"Total Clients: {status['clients']['total']}")
print(f"Total Scopes: {status['scopes']['total']}")
```

### List Users

```python
# List admin users
users = await client.list_users(admin_only=True)
```

## Error Handling

The client raises appropriate exceptions for different error scenarios:

```python
from httpx import HTTPStatusError

try:
    await client.login("admin", "wrong-password")
except HTTPStatusError as e:
    if e.response.status_code == 401:
        print("Invalid credentials")
    else:
        print(f"HTTP Error: {e}")

try:
    await client.get_status()
except ValueError as e:
    print(f"Not authenticated: {e}")
```

## Advanced Usage

### Custom Token Storage

```python
from pathlib import Path

# Use custom token file location
client = AdminAPIClient(
    base_url="http://localhost:8000",
    token_file=Path("/secure/location/tokens.json")
)
```

### Custom HTTP Settings

```python
# Configure timeout and SSL verification
client = AdminAPIClient(
    base_url="https://api.example.com",
    timeout=60.0,  # 60 second timeout
    verify_ssl=True
)
```

### Context Manager

The client supports async context manager for automatic cleanup:

```python
async with AdminAPIClient(base_url="http://localhost:8000") as client:
    await client.login("admin", "password")
    # Perform operations
    # Client is automatically closed on exit
```

## Complete Example

```python
import asyncio
from authly.admin.api_client import AdminAPIClient
from authly.oauth.models import OAuthClientCreateRequest, ClientType

async def manage_oauth_clients():
    """Example of complete OAuth client management workflow."""
    
    async with AdminAPIClient(base_url="http://localhost:8000") as client:
        # Authenticate
        try:
            await client.login(
                username="admin",
                password="secure-password",
                scope="admin:clients:read admin:clients:write"
            )
        except Exception as e:
            print(f"Authentication failed: {e}")
            return
        
        # Create a new OAuth client
        request = OAuthClientCreateRequest(
            client_name="Example App",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://example.com/callback"],
            description="Example OAuth client"
        )
        
        client_obj, secret = await client.create_client(request)
        print(f"Created client: {client_obj.client_id}")
        if secret:
            print(f"Client secret: {secret}")
        
        # List all clients
        all_clients = await client.list_clients()
        print(f"\nTotal clients: {len(all_clients)}")
        
        # Update the client
        updated = await client.update_client(
            client_obj.client_id,
            {"description": "Updated example client"}
        )
        print(f"\nUpdated client description: {updated.description}")
        
        # Clean up - delete the client
        await client.delete_client(client_obj.client_id)
        print(f"\nDeleted client: {client_obj.client_id}")
        
        # Logout
        await client.logout()
        print("\nLogged out successfully")

if __name__ == "__main__":
    asyncio.run(manage_oauth_clients())
```

## Security Considerations

1. **Token Storage**: Tokens are stored in `~/.authly/tokens.json` with 600 permissions (read/write for owner only)
2. **HTTPS**: Always use HTTPS in production to protect credentials and tokens
3. **Token Expiration**: The client automatically checks token expiration and can refresh tokens
4. **Logout**: Always logout when done to revoke tokens on the server
5. **Credential Security**: Never hardcode credentials - use environment variables or secure vaults

## API Reference

For complete API documentation, see the [Admin API Reference](/docs/admin-api-reference.md).