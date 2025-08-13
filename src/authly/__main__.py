#!/usr/bin/env python3
"""
Unified entry point for Authly authentication service.

This module provides a single command-line interface for all Authly operations:
- Web service mode (default)
- Embedded development mode
- Admin CLI mode (delegates to authly.admin.cli)
- Library mode (programmatic usage)

Usage:
    python -m authly                    # Show help
    python -m authly serve              # Start web service
    python -m authly serve --embedded   # Embedded development mode
    python -m authly admin status       # Admin CLI operations
"""

import asyncio
import logging
import os
import sys
from typing import cast

import click
import uvicorn

# Enable Click shell completion
from authly.app import create_production_app
from authly.main import lifespan, setup_logging

logger = logging.getLogger(__name__)


def _handle_shell_completion():
    """Check and handle shell completion requests before Click processes arguments."""
    complete_var = "_AUTHLY_COMPLETE"
    if complete_var in os.environ:
        # Handle shell completion and exit
        from click.shell_completion import shell_complete

        sys.exit(shell_complete(cli, {}, "authly", complete_var, os.environ[complete_var]))


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.option("--commands", is_flag=True, help="Show all available commands and options")
@click.option("--install-completion", is_flag=True, help="Install shell tab completion")
@click.option("--show-completion", is_flag=True, hidden=True, help="Show completion script for current shell")
@click.pass_context
def cli(ctx: click.Context, version: bool, commands: bool, install_completion: bool, show_completion: bool) -> None:
    """
    Authly Authentication Service - Unified Entry Point

    A production-ready OAuth 2.1 authorization server with comprehensive
    admin capabilities and embedded development support.
    """
    if version:
        try:
            from importlib.metadata import version as get_version

            authly_version = get_version("authly")
        except (ImportError, ModuleNotFoundError, AttributeError):
            authly_version = "unknown"
        click.echo(f"Authly Authentication Service v{authly_version}")
        return

    if commands:
        from authly.cli_tree import print_command_tree

        click.echo("Authly CLI Commands Reference")
        click.echo("=" * 40)
        # ctx.command is a Group since cli is decorated with @click.group
        if isinstance(ctx.command, click.Group):
            print_command_tree(ctx.command)
        else:
            click.echo("Error: Expected a command group")
        return

    if install_completion:
        from authly.completion import install_shell_completion

        success = install_shell_completion()
        sys.exit(0 if success else 1)

    if show_completion:
        from authly.completion import show_shell_completion

        show_shell_completion()
        return

    # If no subcommand is provided, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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
    # Check if we're running inside the standalone container
    # BUT allow s6 supervisor to start the server (it runs as authly user via s6-setuidgid)
    import os

    if os.getenv("AUTHLY_STANDALONE") == "true" and not os.getenv("S6_SERVICE_NAME") and os.getuid() != 1000:
        # 1000 is authly user UID
        click.echo("⚠️  Cannot start server - Authly is already running in this container!")
        click.echo("")
        click.echo("The Authly server is automatically managed by the standalone container.")
        click.echo("")
        click.echo("Available options:")
        click.echo("  • Check status:     authly admin status")
        click.echo("  • View logs:        tail -f /var/log/authly.log")
        click.echo("  • Check health:     curl http://localhost:8000/health")
        click.echo("  • Admin operations: authly admin --help")
        click.echo("")
        click.echo("To run a separate instance, use a different container or host system.")
        sys.exit(1)

    setup_logging()

    if embedded:
        # Use embedded development mode
        click.echo("🚀 Starting Authly in embedded development mode...")
        _run_embedded_mode(host, port, seed)
    else:
        # Use production mode
        click.echo(f"🚀 Starting Authly web service on {host}:{port}")
        _run_production_mode(host, port, workers, log_level, access_log)


# Admin command group - delegates to the actual admin CLI
@cli.group(cls=click.Group, invoke_without_command=False)
@click.pass_context
def admin(ctx: click.Context) -> None:
    """
    Administrative operations for Authly.

    Manage OAuth clients, scopes, users, and system configuration.
    """
    pass  # Commands are added dynamically in _setup_admin_commands()
    # Initialize context object if not exists (for proper delegation)
    if ctx.obj is None:
        ctx.obj = {}

    # Import the actual admin CLI module

    # Get the command name that was invoked
    if ctx.invoked_subcommand is None:
        # Show help if no subcommand
        click.echo(ctx.get_help())
        return


# Instead of duplicating all admin commands, we dynamically add them from the actual admin CLI
def _setup_admin_commands():
    """Dynamically add all commands from the admin CLI to avoid duplication."""
    from authly.admin import cli as admin_cli

    # Add all commands from the admin CLI main group
    # Cast admin to click.Group to access commands and add_command
    admin_group = cast(click.Group, admin)
    if hasattr(admin_cli.main, "commands"):
        for name, cmd in admin_cli.main.commands.items():
            # Skip if already exists (shouldn't happen but be safe)
            if name not in admin_group.commands:
                admin_group.add_command(cmd, name=name)


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


def main():
    """Main entry point for the CLI."""
    # Check for shell completion first
    _handle_shell_completion()

    # Set up admin commands
    _setup_admin_commands()

    # Run the CLI
    cli()


# Set up admin commands when module is imported
_setup_admin_commands()

if __name__ == "__main__":
    main()
