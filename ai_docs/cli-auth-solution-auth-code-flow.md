# Authly CLI Authentication Solution - Authorization Code Flow with Local Callback

## Executive Summary
Based on your requirements and existing infrastructure:
1. **Introspection endpoint** exists but requires an existing valid token (chicken-egg problem for initial auth)
2. **S6-overlay** in standalone container supports running multiple services
3. **Authorization Code Flow with Local Callback** is the recommended OAuth 2.1 compliant solution

## Analysis of Introspection Endpoint for M2M

The `/api/v1/oauth/introspect` endpoint exists and can validate tokens, but:
- **Problem**: It requires a valid token to introspect another token
- **Use Case**: It's for resource servers to validate tokens, not for initial authentication
- **Conclusion**: Cannot solve the initial CLI authentication problem

```python
# Introspection requires an existing token to check another token
POST /api/v1/oauth/introspect
Form Data:
  token: <token_to_check>
  token_type_hint: access_token

# Returns token metadata if valid, but doesn't create new tokens
```

## Recommended Solution: Authorization Code Flow with Local Callback

### Why This Is The Best Option
1. **OAuth 2.1 Primary Grant Type** - The most secure and compliant
2. **Works with S6-overlay** - Can run callback server alongside other services
3. **Industry Standard** - Used by Google Cloud CLI, AWS CLI with SSO
4. **Existing Infrastructure** - Uses current OAuth endpoints, no new backend code needed
5. **Security** - PKCE protection, no password handling in CLI

### Implementation Plan

## Phase 1: Update CLI Client (api_client.py)

```python
# src/authly/admin/api_client.py

import asyncio
import base64
import hashlib
import secrets
import webbrowser
from urllib.parse import urlencode, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import socket

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handler for OAuth callback with authorization code."""
    
    def do_GET(self):
        """Handle callback with authorization code."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'code' in params:
            self.server.auth_code = params['code'][0]
            self.server.state = params.get('state', [None])[0]
            
            # Send success response to browser
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html>
                <head><title>Authentication Successful</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>✅ Authentication Successful</h1>
                    <p>You can now close this window and return to the CLI.</p>
                    <script>window.setTimeout(function(){window.close();}, 3000);</script>
                </body>
                </html>
            ''')
        elif 'error' in params:
            self.server.error = params['error'][0]
            self.server.error_description = params.get('error_description', [''])[0]
            
            # Send error response to browser
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'''
                <html>
                <head><title>Authentication Failed</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>❌ Authentication Failed</h1>
                    <p>Error: {params['error'][0]}</p>
                    <p>{params.get('error_description', [''])[0]}</p>
                    <p>Please return to the CLI and try again.</p>
                </body>
                </html>
            '''.encode())
    
    def log_message(self, format, *args):
        """Suppress request logging."""
        pass


class AdminAPIClient:
    # ... existing code ...
    
    def _get_callback_port(self) -> int:
        """Get the callback port for OAuth flow."""
        # Use configured port from environment or default to 8899
        port = int(os.getenv("AUTHLY_CLI_CALLBACK_PORT", "8899"))
        
        # Verify port is available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except OSError:
                raise RuntimeError(
                    f"Port {port} is not available. "
                    f"Set AUTHLY_CLI_CALLBACK_PORT to use a different port."
                )
    
    def _generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        # Code verifier: 43-128 characters, URL-safe
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Code challenge: SHA256 hash of verifier, base64url encoded
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    async def login_oauth_flow(self, scope: str | None = None) -> TokenInfo:
        """
        Authenticate using OAuth 2.0 Authorization Code Flow with PKCE.
        
        This is OAuth 2.1 compliant and replaces the deprecated password grant.
        
        Args:
            scope: Optional OAuth scopes to request
            
        Returns:
            Token information
        """
        # Get configured callback port
        callback_port = self._get_callback_port()
        redirect_uri = f"http://localhost:{callback_port}/callback"
        
        # Generate PKCE pair
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Generate state for CSRF protection
        state = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('utf-8').rstrip('=')
        
        # We need a special CLI client that's registered with this redirect URI
        client_id = "authly-cli"  # This needs to be pre-registered
        
        # Build authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': state,
        }
        if scope:
            auth_params['scope'] = scope
        
        auth_url = f"{self.base_url}/oauth/authorize?{urlencode(auth_params)}"
        
        # Start callback server in background thread
        server = HTTPServer(('localhost', callback_port), OAuthCallbackHandler)
        server.auth_code = None
        server.error = None
        server.state = None
        server.timeout = 120  # 2 minute timeout
        
        def run_server():
            server.handle_request()  # Handle single request then stop
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Open browser for user authentication
        print(f"Opening browser for authentication...")
        print(f"If browser doesn't open, visit: {auth_url}")
        webbrowser.open(auth_url)
        
        # Wait for callback (with timeout)
        server_thread.join(timeout=120)
        
        if server.error:
            raise AdminAPIError(
                f"OAuth authentication failed: {server.error} - {server.error_description}",
                status_code=400
            )
        
        if not server.auth_code:
            raise AdminAPIError("Authentication timeout - no authorization code received", status_code=408)
        
        if server.state != state:
            raise AdminAPIError("State mismatch - possible CSRF attack", status_code=400)
        
        # Exchange authorization code for tokens
        token_data = {
            'grant_type': 'authorization_code',
            'code': server.auth_code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'code_verifier': code_verifier,
        }
        
        response = await self._request(
            "POST", 
            "/api/v1/oauth/token", 
            form_data=token_data, 
            authenticated=False
        )
        
        token_response = response.json()
        
        # Calculate expiration time
        expires_in = token_response.get("expires_in", 3600)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        
        self._token_info = TokenInfo(
            access_token=token_response["access_token"],
            refresh_token=token_response.get("refresh_token"),
            expires_at=expires_at,
            token_type=token_response.get("token_type", "Bearer"),
            scope=token_response.get("scope"),
        )
        
        self._save_tokens()
        logger.info("Successfully authenticated via OAuth flow")
        
        return self._token_info
    
    async def login(self, username: str | None = None, password: str | None = None, scope: str | None = None) -> TokenInfo:
        """
        Updated login method that uses OAuth flow.
        
        Username/password parameters are deprecated and will trigger OAuth flow.
        """
        if username or password:
            logger.warning("Password authentication is deprecated. Using OAuth flow instead.")
        
        return await self.login_oauth_flow(scope)
```

## Phase 2: Update CLI Commands (auth_commands.py)

```python
# src/authly/admin/auth_commands.py

@auth_group.command()
@click.option(
    "--scope", "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request (space-separated)",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
@click.option("--browser/--no-browser", default=True, help="Open browser automatically for authentication")
def login(scope: str, api_url: str | None, browser: bool):
    """
    Login to the Authly Admin API using OAuth 2.0.
    
    Uses secure OAuth 2.0 Authorization Code Flow with PKCE.
    A browser window will open for authentication.
    
    Examples:
        # Standard login (opens browser)
        $ authly auth login
        Opening browser for authentication...
        ✅ Successfully authenticated
        
        # Login without auto-opening browser
        $ authly auth login --no-browser
        Please visit: http://localhost:8000/oauth/authorize?...
        Waiting for authentication...
        
        # Login with specific scopes
        $ authly auth login --scope "admin:clients:read admin:users:read"
    """
    async def run_login():
        base_url = api_url or get_api_url()
        
        async with AdminAPIClient(base_url=base_url) as client:
            try:
                if not browser:
                    # Disable auto-browser opening
                    import webbrowser
                    webbrowser.open = lambda url: print(f"Please visit: {url}")
                
                click.echo("Starting OAuth authentication flow...")
                token_info = await client.login_oauth_flow(scope=scope)
                
                click.echo("✅ Successfully authenticated")
                click.echo(f"   API URL: {base_url}")
                click.echo(f"   Token expires: {token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                click.echo(f"   Granted scopes: {token_info.scope}")
                
                # Test the connection
                try:
                    status = await client.get_status()
                    click.echo(f"   Database connected: {status.get('database', {}).get('connected', 'unknown')}")
                except Exception as e:
                    click.echo(f"   ⚠️  Warning: Could not verify API connection: {e}")
                    
            except Exception as e:
                click.echo(f"❌ Authentication failed: {e}")
                raise click.ClickException(f"Authentication failed: {e}") from e
    
    asyncio.run(run_login())
```

## Phase 3: Pre-register CLI OAuth Client

We need to create a special OAuth client for the CLI with configurable redirect URIs:

```python
# Script to create CLI OAuth client (run once during setup)
# docker-standalone/setup-cli-client.py

import os
import asyncio
from authly.oauth.repository import OAuthClientRepository
from authly.oauth.models import OAuthClientCreateRequest

async def create_cli_client():
    """Create the OAuth client for CLI authentication."""
    
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
            "admin:system:read"
        ],
        grant_types=["authorization_code"],  # Only auth code flow
        response_types=["code"],
    )
    
    # Create client in database
    # ... implementation ...
```

## Phase 4: Container Support and Environment Configuration

### Environment Variables

Configure the CLI OAuth client via environment variables:

```bash
# Default callback port for OAuth flow (default: 8899)
AUTHLY_CLI_CALLBACK_PORT=8899

# Additional redirect URIs (comma-separated)
# Useful for Docker containers or special network configurations
AUTHLY_CLI_REDIRECT_URIS="http://localhost:9000/callback,http://host.docker.internal:8899/callback"
```

### Dockerfile.standalone Updates

```dockerfile
# Add to Dockerfile.standalone
ENV AUTHLY_CLI_CALLBACK_PORT=8899
ENV AUTHLY_CLI_REDIRECT_URIS=""

# Document in container
LABEL cli.oauth.port="8899" \
      cli.oauth.configurable="AUTHLY_CLI_CALLBACK_PORT,AUTHLY_CLI_REDIRECT_URIS"
```

### S6-overlay Service

For the standalone container with s6-overlay, add a service to handle CLI auth:

```bash
# /etc/s6-overlay/s6-rc.d/authly-cli-client/run
#!/usr/bin/with-contenv bash

# Wait for Authly to be ready
sleep 10

# Create CLI OAuth client if it doesn't exist
# Uses AUTHLY_CLI_CALLBACK_PORT and AUTHLY_CLI_REDIRECT_URIS from env
python /docker-standalone/setup-cli-client.py

# Keep service "running" 
exec sleep infinity
```

## Implementation Steps

1. **Immediate Fix** (Phase 1-2):
   - Update `api_client.py` with OAuth flow method
   - Update `auth_commands.py` to use new flow
   - Test with existing OAuth infrastructure

2. **Setup Requirements** (Phase 3):
   - Create and register `authly-cli` OAuth client
   - Configure with localhost redirect URIs
   - Set as public client (no secret required)

3. **Testing**:
   - Test auth flow in development
   - Test in Docker standalone container
   - Verify PKCE validation works correctly

4. **Documentation**:
   - Update CLI documentation
   - Add migration guide for users
   - Document the OAuth flow

## Benefits of This Approach

1. **Full OAuth 2.1 Compliance** - Uses the primary authorization code grant with PKCE
2. **Security** - No passwords in CLI, supports MFA/SSO if configured
3. **Standard Pattern** - Similar to Google Cloud CLI, follows industry best practices
4. **No Backend Changes** - Uses existing OAuth endpoints
5. **Works with S6-overlay** - Compatible with standalone container architecture

## Migration Path

For existing users:
1. Announce deprecation of password-based CLI auth
2. Provide clear upgrade instructions
3. Auto-detect old login attempts and guide to new flow
4. Keep error messages helpful and informative

## Security Considerations

1. **PKCE Required** - Protects against authorization code interception
2. **State Parameter** - CSRF protection
3. **Local Callback Only** - Restricts to localhost ports
4. **Public Client** - No client secret needed or stored
5. **Token Storage** - Same secure storage as before (~/.authly/tokens.json)

## Alternative: Fallback to Password for Admin Only

If you need a quick temporary fix while implementing OAuth flow:

```python
# Add special admin-only endpoint (NOT OAuth)
@router.post("/api/v1/admin/auth/token")
async def admin_auth_token(
    username: str = Form(),
    password: str = Form(),
    # Restrict to admin users only
):
    """Admin-only authentication endpoint for CLI backward compatibility."""
    if username != "admin":
        raise HTTPException(403, "This endpoint is restricted to admin user")
    
    # Verify admin password
    # Return special admin token (not OAuth token)
    # This is a stopgap measure only
```

## Recommendation

Implement the **Authorization Code Flow with Local Callback** as it:
- Provides full OAuth 2.1 compliance
- Works with your existing infrastructure
- Follows industry best practices
- Maintains security while fixing the CLI

The implementation can be done in phases, with the OAuth flow being the primary solution and any temporary fixes clearly marked as deprecated.