"""Authly Admin CLI - Command Line Interface for OAuth 2.1 Administration.

This module provides a comprehensive CLI for managing OAuth 2.1 clients and scopes.
"""

import asyncio
import os
from pathlib import Path
from typing import cast

import click
from click import Command

from authly.admin.api_client import AdminAPIClient


def get_api_url() -> str:
    """Get the API URL from environment or use default."""
    return os.getenv("AUTHLY_API_URL", "http://localhost:8000")


def get_api_client() -> AdminAPIClient:
    """Create an AdminAPIClient instance."""
    api_url = get_api_url()
    return AdminAPIClient(base_url=api_url)


@click.group()
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file (default: uses environment variables)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--dry-run", is_flag=True, help="Show what would be done without executing")
@click.pass_context
def main(ctx: click.Context, config: Path | None, verbose: bool, dry_run: bool):
    """
    Authly Admin CLI - OAuth 2.1 Administration Tool.

    Manage OAuth 2.1 clients and scopes for your Authly instance.

    \b
    Common Commands:
      authly status                      Show system status
      authly auth login                   Authenticate with admin API
      authly client list                 List all OAuth clients
      authly scope list                  List all OAuth scopes

    \b
    Examples:
      # Authenticate with the admin API
      $ authly auth login -u admin
      Password: ***
      ✅ Successfully logged in as admin

      # Create a public OAuth client for a SPA
      $ authly client create --name "My React App" --type public \\
          --redirect-uri "http://localhost:3000/callback"

      # Create a confidential OAuth client for a backend service
      $ authly client create --name "Backend API" --type confidential \\
          --redirect-uri "https://api.example.com/oauth/callback" \\
          --scope "read write"

      # Create OAuth scopes
      $ authly scope create --name read --description "Read access to resources"
      $ authly scope create --name write --description "Write access to resources" --default

      # List clients with JSON output
      $ authly client list --output json

      # Dry-run mode to preview changes
      $ authly --dry-run client delete abc123
      DRY RUN: Would deactivate client

    \b
    Environment Variables:
      AUTHLY_API_URL    API endpoint (default: http://localhost:8000)
      DATABASE_URL      PostgreSQL connection string
      JWT_SECRET_KEY    Secret key for JWT signing
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store global options
    ctx.obj["verbose"] = verbose
    ctx.obj["dry_run"] = dry_run
    ctx.obj["config_path"] = config

    if verbose:
        click.echo("Authly Admin CLI starting...")
        if config:
            click.echo(f"Using config file: {config}")
        if dry_run:
            click.echo("DRY RUN MODE: No changes will be made")


def status_impl(verbose: bool):
    """Implementation of status command."""

    async def run_status():
        click.echo("Authly Instance Status")
        click.echo("=" * 50)

        api_url = get_api_url()

        async with get_api_client() as client:
            try:
                # Check API health
                health = await client.get_health()
                click.echo(f"✅ API Health: {health.get('status', 'OK')}")
                click.echo(f"   API URL: {api_url}")

                # Check authentication status
                if not client.is_authenticated:
                    click.echo("⚠️  Authentication: Not logged in")
                    click.echo("   Use 'python -m authly admin auth login' to authenticate for detailed status")
                    return

                # Get detailed status (requires authentication)
                api_status = await client.get_status()

                # Database connection
                db_info = api_status.get("database", {})
                if db_info.get("connected"):
                    click.echo("✅ Database: Connected")
                    if verbose and db_info.get("version"):
                        click.echo(f"   Version: {db_info['version']}")
                else:
                    click.echo("❌ Database: Connection failed")
                    return

                # Configuration details
                if verbose:
                    click.echo("\nEnvironment Variables:")
                    env_vars = [
                        (
                            "AUTHLY_API_URL",
                            "✅ Set" if os.getenv("AUTHLY_API_URL") else "⚠️  Using default (http://localhost:8000)",
                        ),
                        ("DATABASE_URL", "✅ Set" if os.getenv("DATABASE_URL") else "⚠️  Using default"),
                        ("JWT_SECRET_KEY", "✅ Set" if os.getenv("JWT_SECRET_KEY") else "❌ Missing"),
                        ("JWT_REFRESH_SECRET_KEY", "✅ Set" if os.getenv("JWT_REFRESH_SECRET_KEY") else "❌ Missing"),
                        ("JWT_ALGORITHM", "✅ Set" if os.getenv("JWT_ALGORITHM") else "⚠️  Using default (HS256)"),
                        (
                            "ACCESS_TOKEN_EXPIRE_MINUTES",
                            "✅ Set" if os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES") else "⚠️  Using default (60)",
                        ),
                        (
                            "REFRESH_TOKEN_EXPIRE_DAYS",
                            "✅ Set" if os.getenv("REFRESH_TOKEN_EXPIRE_DAYS") else "⚠️  Using default (7)",
                        ),
                    ]

                    for var_name, status_text in env_vars:
                        click.echo(f"  {var_name}: {status_text}")

                # Service statistics
                stats = api_status.get("statistics", {})

                click.echo("\nService Statistics:")
                click.echo(f"  OAuth Clients: {stats.get('oauth_clients', 'Unknown')}")
                click.echo(f"  OAuth Scopes: {stats.get('oauth_scopes', 'Unknown')}")

                if stats.get("oauth_scopes", 0) == 0:
                    click.echo("\n⚠️  No scopes configured. Consider adding basic scopes:")
                    click.echo("   python -m authly admin scope create --name read --description 'Read access'")
                    click.echo("   python -m authly admin scope create --name write --description 'Write access'")

            except Exception as api_error:
                if "401" in str(api_error) or "403" in str(api_error):
                    click.echo("❌ Authentication: Invalid or expired credentials")
                    click.echo("   Use 'python -m authly admin auth login' to authenticate")
                else:
                    click.echo(f"❌ Error connecting to API: {api_error}")
                    click.echo(f"   Check that the API server is running at {api_url}")

    return asyncio.run(run_status())


@main.command()
@click.pass_context
def status(ctx: click.Context):
    """
    Show Authly instance status and configuration.

    \b
    Displays:
      - API health status
      - Database connection status
      - Authentication status
      - Service statistics (clients, scopes)
      - Environment configuration (with --verbose)

    \b
    Examples:
      # Basic status check
      $ authly status
      Authly Instance Status
      ==================================================
      ✅ API Health: OK
         API URL: http://localhost:8000
      ✅ Database: Connected

      # Verbose status with environment details
      $ authly status --verbose
      $ authly -v status  # Short form

    \b
    Exit Codes:
      0  All systems operational
      1  Connection or configuration error
    """
    verbose = ctx.obj.get("verbose", False)
    return status_impl(verbose)


# Import command groups after main is defined to avoid circular imports
from authly.admin.auth_commands import auth_group  # noqa: E402
from authly.admin.client_commands import client_group  # noqa: E402
from authly.admin.scope_commands import scope_group  # noqa: E402

# Add command groups
main.add_command(cast(Command, auth_group))
main.add_command(cast(Command, client_group))
main.add_command(cast(Command, scope_group))


def entry_point():
    """Entry point for authly-admin that handles shell completion."""
    import sys

    # Check if shell completion is being requested
    complete_var = "_AUTHLY_ADMIN_COMPLETE"
    if complete_var in os.environ:
        # Handle shell completion
        from click.shell_completion import shell_complete

        sys.exit(shell_complete(main, {}, "authly-admin", complete_var, os.environ[complete_var]))

    # Normal CLI execution
    main()


if __name__ == "__main__":
    entry_point()
