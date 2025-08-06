"""
Authentication commands for Authly Admin CLI.

This module provides login, logout, and whoami commands for admin authentication
using the AdminAPIClient.
"""

import asyncio
import os
from getpass import getpass

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
    """Authentication commands for admin access."""
    pass


@auth_group.command()
@click.option("--username", "-u", prompt=True, help="Admin username")
@click.option("--password", "-p", help="Admin password (will prompt if not provided)")
@click.option(
    "--scope",
    "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
def login(username: str, password: str | None, scope: str, api_url: str | None):
    """
    Login to the Authly Admin API.

    Authenticates with the admin API and stores tokens securely for subsequent commands.

    Examples:
        authly-admin auth login -u admin
        authly-admin auth login --username admin --scope "admin:clients:read"
    """

    async def run_login():
        # Get API URL
        base_url = api_url or get_api_url()

        # Get password if not provided
        password_input = password if password else getpass("Password: ")

        async with AdminAPIClient(base_url=base_url) as client:
            try:
                # Attempt login
                token_info = await client.login(username=username, password=password_input, scope=scope)

                click.echo(f"✅ Successfully logged in as {username}")
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
                click.echo(f"❌ Login failed: {e}")
                raise click.ClickException(f"Authentication failed: {e}") from e

    asyncio.run(run_login())


@auth_group.command()
def logout():
    """
    Logout from the Authly Admin API.

    Revokes stored tokens and clears local authentication.

    Examples:
        authly-admin auth logout
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
            except Exception as e:
                click.echo(f"⚠️  Logout warning: {e}")
                # Still clear tokens locally even if server logout fails
                client._clear_tokens()
                click.echo("   Local tokens cleared")

    asyncio.run(run_logout())


@auth_group.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def whoami(verbose: bool):
    """
    Show current authentication status.

    Displays information about the currently logged-in admin user.

    Examples:
        authly-admin auth whoami
        authly-admin auth whoami --verbose
    """

    async def run_whoami():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            if not client.is_authenticated:
                click.echo("❌ Not authenticated")
                click.echo("   Use 'authly-admin auth login' to authenticate")
                return

            try:
                # Get system status to verify authentication
                status = await client.get_status()

                click.echo("✅ Authenticated")
                click.echo(f"   API URL: {get_api_url()}")

                if verbose and client._token_info:
                    click.echo(f"   Token type: {client._token_info.token_type}")
                    click.echo(f"   Token expires: {client._token_info.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    click.echo(f"   Granted scopes: {client._token_info.scope}")

                    # Show token file location
                    click.echo(f"   Token file: {client.token_file}")

                # Show some system info
                db_info = status.get("database", {})
                click.echo(f"   Database connected: {db_info.get('connected', 'unknown')}")

                clients_info = status.get("clients", {})
                if clients_info:
                    click.echo(f"   Total OAuth clients: {clients_info.get('total', 'unknown')}")

                scopes_info = status.get("scopes", {})
                if scopes_info:
                    click.echo(f"   Total OAuth scopes: {scopes_info.get('total', 'unknown')}")

            except Exception as e:
                click.echo(f"❌ Authentication verification failed: {e}")
                click.echo("   Your token may have expired. Try logging in again.")
                raise click.ClickException(f"Authentication verification failed: {e}") from e

    asyncio.run(run_whoami())


@auth_group.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def status(verbose: bool):
    """
    Show authentication and API status.

    Alias for whoami command with additional API health information.

    Examples:
        authly-admin auth status
        authly-admin auth status --verbose
    """

    async def run_auth_status():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            api_url = get_api_url()

            # Check API health first
            try:
                health = await client.get_health()
                click.echo(f"✅ API Health: {health.get('status', 'unknown')}")
                click.echo(f"   API URL: {api_url}")
            except Exception as e:
                click.echo(f"❌ API Health: Failed to connect to {api_url}")
                click.echo(f"   Error: {e}")
                return

            # Check authentication status
            if not client.is_authenticated:
                click.echo("❌ Authentication: Not logged in")
                click.echo("   Use 'authly-admin auth login' to authenticate")
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

            except Exception as e:
                click.echo("⚠️  Authentication: Token may be expired")
                click.echo(f"   Error: {e}")
                click.echo("   Try logging in again with 'authly-admin auth login'")

    asyncio.run(run_auth_status())


@auth_group.command()
def refresh():
    """
    Refresh authentication tokens.

    Attempts to refresh the access token using the stored refresh token.

    Examples:
        authly-admin auth refresh
    """

    async def run_refresh():
        async with AdminAPIClient(base_url=get_api_url()) as client:
            if not client._token_info:
                click.echo("❌ No stored tokens found")
                click.echo("   Use 'authly-admin auth login' to authenticate")
                return

            if not client._token_info.refresh_token:
                click.echo("❌ No refresh token available")
                click.echo("   Use 'authly-admin auth login' to authenticate")
                return

            try:
                new_token = await client.refresh_token()
                click.echo("✅ Token refreshed successfully")
                click.echo(f"   New expiration: {new_token.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")

                # Verify the new token works
                try:
                    await client.get_status()
                    click.echo("   Token verified - authentication active")
                except Exception as e:
                    click.echo(f"   ⚠️  Warning: Could not verify new token: {e}")

            except Exception as e:
                click.echo(f"❌ Token refresh failed: {e}")
                click.echo("   Use 'authly-admin auth login' to authenticate")
                raise click.ClickException(f"Token refresh failed: {e}") from e

    asyncio.run(run_refresh())


# Add aliases for convenience
@click.command()
@click.option("--username", "-u", prompt=True, help="Admin username")
@click.option("--password", "-p", help="Admin password (will prompt if not provided)")
@click.option(
    "--scope",
    "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
def login_alias(username: str, password: str | None, scope: str, api_url: str | None):
    """Alias for 'auth login' command."""
    # Create a context to pass to the login command
    ctx = click.Context(login)
    ctx.params = {"username": username, "password": password, "scope": scope, "api_url": api_url}
    ctx.invoke(login, username=username, password=password, scope=scope, api_url=api_url)


@click.command()
def logout_alias():
    """Alias for 'auth logout' command."""
    ctx = click.Context(logout)
    ctx.invoke(logout)


@click.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def whoami_alias(verbose: bool):
    """Alias for 'auth whoami' command."""
    ctx = click.Context(whoami)
    ctx.invoke(whoami, verbose=verbose)
