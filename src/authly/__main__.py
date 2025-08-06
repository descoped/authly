#!/usr/bin/env python3
"""
Unified entry point for Authly authentication service.

This module provides a single command-line interface for all Authly operations:
- Web service mode (default)
- Embedded development mode
- Admin CLI mode
- Library mode (programmatic usage)

Usage:
    python -m authly                    # Default: web service mode
    python -m authly serve              # Explicit web service mode
    python -m authly serve --embedded   # Embedded development mode
    python -m authly admin status       # Admin CLI operations
"""

import asyncio
import logging
import sys

import click
import uvicorn

from authly.app import create_production_app
from authly.main import lifespan, setup_logging

logger = logging.getLogger(__name__)


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """
    Authly Authentication Service - Unified Entry Point

    A production-ready OAuth 2.1 authorization server with comprehensive
    admin capabilities and embedded development support.
    """
    if version:
        try:
            from importlib.metadata import version as get_version

            authly_version = get_version("authly")
        except Exception:
            authly_version = "unknown"
        click.echo(f"Authly Authentication Service v{authly_version}")
        return

    # If no subcommand is provided, default to serve mode
    if ctx.invoked_subcommand is None:
        ctx.invoke(serve)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--workers", default=1, type=int, help="Number of worker processes")
@click.option("--embedded", is_flag=True, help="Run with embedded PostgreSQL container")
@click.option("--seed", is_flag=True, help="Seed test data (only with --embedded)")
@click.option("--log-level", default="info", help="Logging level")
@click.option("--access-log/--no-access-log", default=True, help="Enable/disable access logging")
def serve(host: str, port: int, workers: int, embedded: bool, seed: bool, log_level: str, access_log: bool) -> None:
    """
    Start the Authly web service.

    This command runs the FastAPI application with uvicorn server.
    Use --embedded for development with PostgreSQL container.
    """
    setup_logging()

    if embedded:
        # Use embedded development mode
        click.echo("🚀 Starting Authly in embedded development mode...")
        _run_embedded_mode(host, port, seed)
    else:
        # Use production mode
        click.echo(f"🚀 Starting Authly web service on {host}:{port}")
        _run_production_mode(host, port, workers, log_level, access_log)


@cli.group()
def admin() -> None:
    """
    Administrative operations for Authly.

    Manage OAuth clients, scopes, users, and system configuration.
    """
    pass


@admin.command()
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]), help="Output format")
def status(output_format: str) -> None:
    """Show system status and configuration."""
    # Import here to avoid circular imports
    # Import and call admin status command
    from authly.admin.cli import status as admin_status

    # Call the admin command directly (it doesn't use format parameter)
    admin_status()


@admin.group()
def client() -> None:
    """Manage OAuth clients."""
    pass


@client.command("list")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def list_clients(output_format: str) -> None:
    """List all OAuth clients."""
    # Import and call admin list clients command
    from authly.admin.client_commands import list_clients as admin_list_clients

    ctx = click.Context(admin_list_clients)
    ctx.obj = {}  # Initialize context object

    # Call the admin command with proper parameters
    ctx.invoke(admin_list_clients, limit=100, offset=0, output=output_format, show_inactive=False)


@client.command("create")
@click.option("--name", required=True, help="Client name")
@click.option("--client-type", type=click.Choice(["public", "confidential"]), default="public", help="Client type")
@click.option("--redirect-uri", multiple=True, help="Redirect URI (can be specified multiple times)")
@click.option("--scope", multiple=True, help="Allowed scopes (can be specified multiple times)")
@click.option("--description", help="Client description")
def create_client(name: str, client_type: str, redirect_uri: tuple, scope: tuple, description: str | None) -> None:
    """Create a new OAuth client."""
    # Import admin command
    from authly.admin.client_commands import create_client as admin_create_client

    # Validate that at least one redirect URI is provided for create
    if not redirect_uri:
        click.echo("❌ Error: At least one redirect URI is required", err=True)
        return

    # Create a proper context and invoke the admin command
    ctx = click.Context(admin_create_client)
    ctx.obj = {}  # Initialize context object

    # Map scope tuple to space-separated string if provided
    scope_str = " ".join(scope) if scope else None

    # Call the admin command with proper parameter mapping
    ctx.invoke(
        admin_create_client,
        name=name,
        client_type=client_type,
        redirect_uris=redirect_uri,  # Note: admin expects 'redirect_uris'
        scope=scope_str,
        client_uri=None,
        logo_uri=None,
        tos_uri=None,
        policy_uri=None,
        auth_method=None,  # Will use default based on client_type
        no_pkce=False,  # Enable PKCE by default
        output="table",
    )


@admin.group()
def auth() -> None:
    """Authentication commands for admin access."""
    pass


@auth.command()
@click.option("--username", "-u", prompt=True, help="Admin username")
@click.option("--password", "-p", help="Admin password (will prompt if not provided)")
@click.option(
    "--scope",
    "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
def login(username: str, password: str | None, scope: str, api_url: str | None) -> None:
    """Login to the Authly Admin API."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import login as admin_login

    ctx = click.Context(admin_login)
    ctx.params = {"username": username, "password": password, "scope": scope, "api_url": api_url}

    # Run the admin command
    admin_login.callback(username, password, scope, api_url)


@auth.command()
def logout() -> None:
    """Logout from the Authly Admin API."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import logout as admin_logout

    # Run the admin command
    admin_logout.callback()


@auth.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def whoami(verbose: bool) -> None:
    """Show current authentication status."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import whoami as admin_whoami

    ctx = click.Context(admin_whoami)
    ctx.params = {"verbose": verbose}

    # Run the admin command
    admin_whoami.callback(verbose)


@auth.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def auth_status(verbose: bool) -> None:
    """Show authentication and API status."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import status as admin_auth_status

    # Run the admin command
    admin_auth_status.callback(verbose)


@auth.command()
def refresh() -> None:
    """Refresh authentication tokens."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import refresh as admin_refresh

    # Run the admin command
    admin_refresh.callback()


# Add convenient aliases for common auth commands
@admin.command()
@click.option("--username", "-u", prompt=True, help="Admin username")
@click.option("--password", "-p", help="Admin password (will prompt if not provided)")
@click.option(
    "--scope",
    "-s",
    default="admin:clients:read admin:clients:write admin:scopes:read admin:scopes:write admin:users:read admin:system:read",
    help="OAuth scopes to request",
)
@click.option("--api-url", help="API URL (default: http://localhost:8000 or AUTHLY_API_URL env var)")
def admin_login(username: str, password: str | None, scope: str, api_url: str | None) -> None:
    """Login to the Authly Admin API (alias for 'auth login')."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import login as admin_login_cmd

    # Run the admin command
    admin_login_cmd.callback(username, password, scope, api_url)


@admin.command()
def admin_logout() -> None:
    """Logout from the Authly Admin API (alias for 'auth logout')."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import logout as admin_logout_cmd

    # Run the admin command
    admin_logout_cmd.callback()


@admin.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def admin_whoami(verbose: bool) -> None:
    """Show current authentication status (alias for 'auth whoami')."""
    # Create a mock context for the admin command
    from authly.admin.auth_commands import whoami as admin_whoami_cmd

    # Run the admin command
    admin_whoami_cmd.callback(verbose)


@admin.group()
def scope() -> None:
    """Manage OAuth scopes."""
    pass


@scope.command("list")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def list_scopes(output_format: str) -> None:
    """List all OAuth scopes."""
    # Import and call admin scope list command
    from authly.admin.scope_commands import list_scopes as admin_list_scopes

    ctx = click.Context(admin_list_scopes)
    ctx.obj = {}  # Initialize context object

    # Call the admin command with proper parameters
    ctx.invoke(admin_list_scopes, limit=100, offset=0, output=output_format, show_inactive=False, default_only=False)


@scope.command("create")
@click.option("--name", required=True, help="Scope name")
@click.option("--description", required=True, help="Scope description")
def create_scope(name: str, description: str) -> None:
    """Create a new OAuth scope."""
    # Import and call admin scope create command
    from authly.admin.scope_commands import create_scope as admin_create_scope

    # Create a proper context and invoke the admin command
    ctx = click.Context(admin_create_scope)
    ctx.obj = {}  # Initialize context object

    # Call the admin command with proper parameter mapping
    ctx.invoke(
        admin_create_scope,
        name=name,
        description=description,
        is_default=False,  # Default to not a default scope
        output="table",  # Use table output format
    )


def _run_production_mode(host: str, port: int, workers: int, log_level: str, access_log: bool) -> None:
    """Run Authly in production mode with the fixed main.py."""
    app = create_production_app(lifespan=lifespan)

    # Create uvicorn configuration
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=workers if workers > 1 else None,
        log_level=log_level.lower(),
        access_log=access_log,
    )

    server = uvicorn.Server(config)

    # Run the server
    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


def _run_embedded_mode(host: str, port: int, seed: bool) -> None:
    """Run Authly in embedded development mode."""
    try:
        # Import embedded server functionality
        from authly.embedded import run_embedded_server

        # Run embedded server with PostgreSQL container
        asyncio.run(run_embedded_server(host, port, seed))
    except ImportError:
        # Fallback to inline embedded implementation
        click.echo("⚠️  Embedded mode not fully implemented yet")
        click.echo("💡 For now, use: python examples/authly-embedded.py")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Embedded server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
