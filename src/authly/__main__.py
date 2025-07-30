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
import os
import sys
from typing import Optional

import click
import uvicorn
from fastapi import FastAPI

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
        click.echo("Authly Authentication Service v0.1.5")
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
    # Create a mock context for the admin command
    import click

    from authly.admin.cli import status as admin_status

    ctx = click.Context(admin_status)
    ctx.params = {"format": output_format}

    # Run the admin status command
    asyncio.run(admin_status.callback(output_format))


@admin.group()
def client() -> None:
    """Manage OAuth clients."""
    pass


@client.command("list")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def list_clients(output_format: str) -> None:
    """List all OAuth clients."""
    # Create a mock context for the admin command
    import click

    from authly.admin.client_commands import list_clients as admin_list_clients

    ctx = click.Context(admin_list_clients)
    ctx.params = {"format": output_format}

    # Run the admin command
    asyncio.run(admin_list_clients.callback(output_format))


@client.command("create")
@click.option("--name", required=True, help="Client name")
@click.option("--client-type", type=click.Choice(["public", "confidential"]), default="public", help="Client type")
@click.option("--redirect-uri", multiple=True, help="Redirect URI (can be specified multiple times)")
@click.option("--scope", multiple=True, help="Allowed scopes (can be specified multiple times)")
@click.option("--description", help="Client description")
def create_client(name: str, client_type: str, redirect_uri: tuple, scope: tuple, description: Optional[str]) -> None:
    """Create a new OAuth client."""
    # Create a mock context for the admin command
    import click

    from authly.admin.client_commands import create_client as admin_create_client

    ctx = click.Context(admin_create_client)
    ctx.params = {
        "name": name,
        "client_type": client_type,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "description": description,
    }

    # Run the admin command
    asyncio.run(admin_create_client.callback(name, client_type, redirect_uri, scope, description))


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
def login(username: str, password: Optional[str], scope: str, api_url: Optional[str]) -> None:
    """Login to the Authly Admin API."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import login as admin_login

    ctx = click.Context(admin_login)
    ctx.params = {"username": username, "password": password, "scope": scope, "api_url": api_url}

    # Run the admin command
    asyncio.run(admin_login.callback(username, password, scope, api_url))


@auth.command()
def logout() -> None:
    """Logout from the Authly Admin API."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import logout as admin_logout

    ctx = click.Context(admin_logout)

    # Run the admin command
    asyncio.run(admin_logout.callback())


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
    asyncio.run(admin_whoami.callback(verbose))


@auth.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def status(verbose: bool) -> None:
    """Show authentication and API status."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import status as admin_auth_status

    ctx = click.Context(admin_auth_status)
    ctx.params = {"verbose": verbose}

    # Run the admin command
    asyncio.run(admin_auth_status.callback(verbose))


@auth.command()
def refresh() -> None:
    """Refresh authentication tokens."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import refresh as admin_refresh

    ctx = click.Context(admin_refresh)

    # Run the admin command
    asyncio.run(admin_refresh.callback())


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
def login(username: str, password: Optional[str], scope: str, api_url: Optional[str]) -> None:
    """Login to the Authly Admin API (alias for 'auth login')."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import login as admin_login

    ctx = click.Context(admin_login)
    ctx.params = {"username": username, "password": password, "scope": scope, "api_url": api_url}

    # Run the admin command
    admin_login.callback(username, password, scope, api_url)


@admin.command()
def logout() -> None:
    """Logout from the Authly Admin API (alias for 'auth logout')."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import logout as admin_logout

    ctx = click.Context(admin_logout)

    # Run the admin command
    admin_logout.callback()


@admin.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed token information")
def whoami(verbose: bool) -> None:
    """Show current authentication status (alias for 'auth whoami')."""
    # Create a mock context for the admin command
    import click

    from authly.admin.auth_commands import whoami as admin_whoami

    ctx = click.Context(admin_whoami)
    ctx.params = {"verbose": verbose}

    # Run the admin command
    admin_whoami.callback(verbose)


@admin.group()
def scope() -> None:
    """Manage OAuth scopes."""
    pass


@scope.command("list")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def list_scopes(output_format: str) -> None:
    """List all OAuth scopes."""
    # Create a mock context for the admin command
    import click

    from authly.admin.scope_commands import list_scopes as admin_list_scopes

    ctx = click.Context(admin_list_scopes)
    ctx.params = {"format": output_format}

    # Run the admin command
    asyncio.run(admin_list_scopes.callback(output_format))


@scope.command("create")
@click.option("--name", required=True, help="Scope name")
@click.option("--description", required=True, help="Scope description")
def create_scope(name: str, description: str) -> None:
    """Create a new OAuth scope."""
    # Create a mock context for the admin command
    import click

    from authly.admin.scope_commands import create_scope as admin_create_scope

    ctx = click.Context(admin_create_scope)
    ctx.params = {"name": name, "description": description}

    # Run the admin command
    asyncio.run(admin_create_scope.callback(name, description))


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
