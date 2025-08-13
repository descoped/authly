"""
Authentication commands for Authly Admin CLI.

This module provides login, logout, and whoami commands for admin authentication
using the AdminAPIClient.
"""

import asyncio
import os

import click

from authly.admin.api_client import AdminAPIClient


def get_api_url() -> str:
    """Get the API URL from environment or use default."""
    return os.getenv("AUTHLY_API_URL", "http://localhost:8000")


def get_api_client() -> AdminAPIClient:
    """Create an AdminAPIClient instance."""
    api_url = get_api_url()
    return AdminAPIClient(base_url=api_url)


@click.group()
def auth_group():
    """
    Authentication commands for admin access.

    \b
    Manage authentication with the Authly Admin API.
    These commands handle login, logout, token management,
    and authentication status.

    \b
    Common Commands:
      authly auth login       Authenticate with admin credentials
      authly auth logout      Revoke and clear tokens
      authly auth whoami      Show current authentication status
      authly auth refresh     Refresh access token

    \b
    Note: Most admin operations require authentication.
    Use 'authly auth login' first.
    """
    pass


@auth_group.command()
@click.option(
    "--scope",
    "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request (space-separated)",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
@click.option("--browser/--no-browser", default=True, help="Open browser automatically for authentication")
@click.option("--show-token", is_flag=True, help="Display the access token (use with caution)")
def login(scope: str, api_url: str | None, browser: bool, show_token: bool):
    """
    Login to the Authly Admin API using OAuth 2.0.

    \b
    Uses secure OAuth 2.0 Authorization Code Flow with PKCE.
    A browser window will open for authentication.
    Tokens are saved to ~/.authly/tokens.json.

    \b
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

      # Login to custom API endpoint
      $ authly auth login --api-url https://auth.example.com

    \b
    Available Scopes:
      admin:clients:read     Read OAuth clients
      admin:clients:write    Create/update/delete OAuth clients
      admin:scopes:read      Read OAuth scopes
      admin:scopes:write     Create/update/delete OAuth scopes
      admin:users:read       Read user accounts
      admin:system:read      Read system configuration

    \b
    Security Notes:
      - Uses OAuth 2.0 Authorization Code Flow with PKCE
      - No passwords handled by CLI
      - Tokens expire after 60 minutes by default
      - Use 'authly auth refresh' to renew tokens
    """

    async def run_login():
        # Get API URL
        base_url = api_url or get_api_url()

        async with AdminAPIClient(base_url=base_url) as client:
            try:
                click.echo("Starting OAuth authentication flow...")

                # Attempt OAuth login
                token_info = await client.login_oauth_flow(scope=scope, auto_open_browser=browser)

                click.echo("✅ Successfully authenticated")
                click.echo(f"   API URL: {base_url}")
                click.echo(f"   Token expires: {token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                click.echo(f"   Granted scopes: {token_info.scope}")

                # Show token if requested
                if show_token:
                    click.echo(f"   Access token: {token_info.access_token}")
                    if token_info.refresh_token:
                        click.echo(f"   Refresh token: {token_info.refresh_token}")

                # Test the connection
                try:
                    api_status = await client.get_status()
                    click.echo(f"   Database connected: {api_status.get('database', {}).get('connected', 'unknown')}")
                except Exception as conn_error:
                    click.echo(f"   ⚠️  Warning: Could not verify API connection: {conn_error}")

            except Exception as login_error:
                click.echo(f"❌ Login failed: {login_error}")
                raise click.ClickException(f"Authentication failed: {login_error}") from login_error

    asyncio.run(run_login())


@auth_group.command()
def logout():
    """
    Logout from the Authly Admin API.

    \b
    Revokes stored tokens on the server and clears local authentication.
    This ensures tokens cannot be reused even if compromised.

    \b
    Examples:
      # Logout and revoke tokens
      $ authly auth logout
      ✅ Successfully logged out
         Tokens have been revoked and cleared

      # Logout is safe to run multiple times
      $ authly auth logout
      i  Already logged out

    \b
    Notes:
      - Tokens are revoked on the server
      - Local token file is deleted
      - Safe to run even if not logged in
    """

    async def run_logout():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            try:
                if client.is_authenticated:
                    await client.logout()
                    click.echo("✅ Successfully logged out")
                    click.echo("   Tokens have been revoked and cleared")
                else:
                    click.echo("i  Already logged out")
            except Exception as logout_error:
                click.echo(f"⚠️  Logout warning: {logout_error}")
                # Still clear tokens locally even if server logout fails
                client._clear_tokens()
                click.echo("   Local tokens cleared")

    asyncio.run(run_logout())


@auth_group.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def whoami(verbose: bool):
    """
    Show current authentication status.

    \b
    Displays authentication status and system information.
    Use --verbose to see token details and expiration.

    \b
    Examples:
      # Check if authenticated
      $ authly auth whoami
      ✅ Authenticated
         API URL: http://localhost:8000
         Database connected: true
         Total OAuth clients: 5
         Total OAuth scopes: 3

      # Show detailed token information
      $ authly auth whoami --verbose
      ✅ Authenticated
         API URL: http://localhost:8000
         Token type: Bearer
         Token expires: 2024-01-20 15:30:00 UTC
         Granted scopes: admin:clients:read admin:clients:write ...
         Token file: /Users/admin/.authly/tokens.json
         Database connected: true

      # When not authenticated
      $ authly auth whoami
      ❌ Not authenticated
         Use 'authly auth login' to authenticate

    \b
    Exit Codes:
      0  Authenticated and verified
      1  Not authenticated or token expired
    """

    async def run_whoami():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            if not client.is_authenticated:
                click.echo("❌ Not authenticated")
                click.echo("   Use 'authly admin auth login' to authenticate")
                return

            try:
                # Get system status to verify authentication
                system_status = await client.get_status()

                click.echo("✅ Authenticated")
                click.echo(f"   API URL: {get_api_url()}")

                if verbose and client._token_info:
                    click.echo(f"   Token type: {client._token_info.token_type}")
                    click.echo(f"   Token expires: {client._token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    click.echo(f"   Granted scopes: {client._token_info.scope}")

                    # Show token file location
                    click.echo(f"   Token file: {client.token_file}")

                # Show some system info
                db_info = system_status.get("database", {})
                click.echo(f"   Database connected: {db_info.get('connected', 'unknown')}")

                clients_info = system_status.get("clients", {})
                if clients_info:
                    click.echo(f"   Total OAuth clients: {clients_info.get('total', 'unknown')}")

                scopes_info = system_status.get("scopes", {})
                if scopes_info:
                    click.echo(f"   Total OAuth scopes: {scopes_info.get('total', 'unknown')}")

            except Exception as auth_error:
                click.echo(f"❌ Authentication verification failed: {auth_error}")
                click.echo("   Your token may have expired. Try logging in again.")
                raise click.ClickException(f"Authentication verification failed: {auth_error}") from auth_error

    asyncio.run(run_whoami())


@auth_group.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def status(verbose: bool):
    """
    Show authentication and API status.

    \b
    Comprehensive status check including API health,
    authentication status, and system statistics.

    \b
    Examples:
      # Check overall status
      $ authly auth status
      ✅ API Health: OK
         API URL: http://localhost:8000
      ✅ Authentication: Logged in
         Database: Connected
         OAuth clients: 5
         OAuth scopes: 3

      # Verbose status with token details
      $ authly auth status --verbose
      ✅ API Health: OK
         API URL: http://localhost:8000
      ✅ Authentication: Logged in
         Token expires: 2024-01-20 15:30:00 UTC
         Granted scopes: admin:clients:read admin:clients:write ...
         Database: Connected
         OAuth clients: 5
         OAuth scopes: 3

    \b
    Difference from 'whoami':
      - Shows API health status first
      - More detailed system information
      - Better for troubleshooting connections
    """

    async def run_auth_status():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            api_url = get_api_url()

            # Check API health first
            try:
                health = await client.get_health()
                click.echo(f"✅ API Health: {health.get('status', 'unknown')}")
                click.echo(f"   API URL: {api_url}")
            except Exception as health_error:
                click.echo(f"❌ API Health: Failed to connect to {api_url}")
                click.echo(f"   Error: {health_error}")
                return

            # Check authentication status
            if not client.is_authenticated:
                click.echo("❌ Authentication: Not logged in")
                click.echo("   Use 'authly admin auth login' to authenticate")
                return

            try:
                # Get detailed status
                status_info = await client.get_status()

                click.echo("✅ Authentication: Logged in")

                if verbose and client._token_info:
                    click.echo(f"   Token expires: {client._token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    click.echo(f"   Granted scopes: {client._token_info.scope}")

                # Show system status
                db_info = status_info.get("database", {})
                click.echo(f"   Database: {'Connected' if db_info.get('connected') else 'Disconnected'}")

                clients_info = status_info.get("clients", {})
                scopes_info = status_info.get("scopes", {})

                if clients_info and scopes_info:
                    click.echo(f"   OAuth clients: {clients_info.get('total', 0)}")
                    click.echo(f"   OAuth scopes: {scopes_info.get('total', 0)}")

            except Exception as status_error:
                click.echo("⚠️  Authentication: Token may be expired")
                click.echo(f"   Error: {status_error}")
                click.echo("   Try logging in again with 'authly-admin auth login'")

    asyncio.run(run_auth_status())


@auth_group.command()
def info():
    """
    Show Authly configuration and internal information.

    \b
    Displays:
      - Configuration paths
      - Token storage location
      - API endpoints
      - Environment settings
      - Version information

    \b
    Examples:
      $ authly auth info
      Authly Configuration Information
      ==================================================
      Configuration directory: /home/user/.authly
      Token file: /home/user/.authly/tokens.json
      API URL: http://localhost:8000
      Environment: development
      Version: 0.5.8
    """
    from pathlib import Path

    async def run_info():
        # Get home directory and .authly location
        home_dir = Path.home()
        authly_dir = home_dir / ".authly"
        token_file = authly_dir / "tokens.json"

        click.echo("Authly Configuration Information")
        click.echo("=" * 50)
        click.echo(f"Configuration directory: {authly_dir}")
        click.echo(f"Token file: {token_file}")
        click.echo(f"Token file exists: {token_file.exists()}")

        # API configuration
        api_url = get_api_url()
        click.echo("\nAPI Configuration:")
        click.echo(f"  API URL: {api_url}")
        click.echo(f"  Admin API enabled: {os.getenv('AUTHLY_ADMIN_API_ENABLED', 'true')}")

        # Environment info
        click.echo("\nEnvironment:")
        click.echo(f"  AUTHLY_MODE: {os.getenv('AUTHLY_MODE', 'not set')}")
        click.echo(f"  DATABASE_URL: {'set' if os.getenv('DATABASE_URL') else 'not set'}")
        click.echo(f"  JWT_SECRET_KEY: {'set' if os.getenv('JWT_SECRET_KEY') else 'not set'}")
        click.echo(f"  JWT_REFRESH_SECRET_KEY: {'set' if os.getenv('JWT_REFRESH_SECRET_KEY') else 'not set'}")

        # Version info
        try:
            from importlib.metadata import version as get_version

            authly_version = get_version("authly")
        except Exception:
            authly_version = "unknown"
        click.echo("\nVersion Information:")
        click.echo(f"  Authly version: {authly_version}")

        # Check authentication status
        async with AdminAPIClient(base_url=api_url) as client:
            click.echo("\nAuthentication Status:")
            if client.is_authenticated:
                click.echo("  Status: Authenticated")
                if client._token_info:
                    click.echo(f"  Token expires: {client._token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                click.echo("  Status: Not authenticated")

    asyncio.run(run_info())


@auth_group.command()
def refresh():
    """
    Refresh authentication tokens.

    \b
    Uses the stored refresh token to obtain a new access token.
    This extends your session without re-entering credentials.

    \b
    Examples:
      # Refresh expired or expiring token
      $ authly auth refresh
      ✅ Token refreshed successfully
         New expiration: 2024-01-20 16:30:00 UTC
         Token verified - authentication active

      # When refresh token is missing
      $ authly auth refresh
      ❌ No refresh token available
         Use 'authly auth login' to authenticate

      # When refresh token is expired
      $ authly auth refresh
      ❌ Token refresh failed: Refresh token expired
         Use 'authly auth login' to authenticate

    \b
    Notes:
      - Access tokens expire after 60 minutes
      - Refresh tokens expire after 7 days
      - Run this before your access token expires
      - Automatic refresh not yet implemented
    """

    async def run_refresh():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            if not client._token_info:
                click.echo("❌ No stored tokens found")
                click.echo("   Use 'authly admin auth login' to authenticate")
                return

            if not client._token_info.refresh_token:
                click.echo("❌ No refresh token available")
                click.echo("   Use 'authly admin auth login' to authenticate")
                return

            try:
                new_token = await client.refresh_token()
                click.echo("✅ Token refreshed successfully")
                click.echo(f"   New expiration: {new_token.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")

                # Verify the new token works
                try:
                    await client.get_status()
                    click.echo("   Token verified - authentication active")
                except Exception as verify_error:
                    click.echo(f"   ⚠️  Warning: Could not verify new token: {verify_error}")

            except Exception as refresh_error:
                click.echo(f"❌ Token refresh failed: {refresh_error}")
                click.echo("   Use 'authly admin auth login' to authenticate")
                raise click.ClickException(f"Token refresh failed: {refresh_error}") from refresh_error

    asyncio.run(run_refresh())
