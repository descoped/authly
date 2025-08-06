"""OAuth 2.1 Scope Management Commands for Authly Admin CLI."""

import asyncio
import json
import os
import sys

import click

from authly.admin.api_client import AdminAPIClient, AdminAPIError


def get_api_url() -> str:
    """Get the API URL from environment or use default."""
    return os.getenv("AUTHLY_API_URL", "http://localhost:8000")


def get_api_client() -> AdminAPIClient:
    """Create an AdminAPIClient instance."""
    api_url = get_api_url()
    return AdminAPIClient(base_url=api_url)


@click.group(name="scope")
def scope_group():
    """Manage OAuth 2.1 scopes."""
    pass


@scope_group.command("create")
@click.option("--name", required=True, help="Scope name")
@click.option("--description", help="Scope description")
@click.option("--default", "is_default", is_flag=True, help="Mark as default scope")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.pass_context
def create_scope(ctx: click.Context, name: str, description: str | None, is_default: bool, output: str):
    """Create a new OAuth 2.1 scope."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if verbose:
        click.echo(f"Creating OAuth scope: {name}")

    if dry_run:
        click.echo("DRY RUN: Would create scope with the following configuration:")
        if output == "json":
            scope_data = {"name": name, "description": description, "is_default": is_default}
            click.echo(json.dumps(scope_data, indent=2))
        else:
            click.echo(f"  Name: {name}")
            click.echo(f"  Description: {description or 'None'}")
            click.echo(f"  Default: {'✅ Yes' if is_default else '❌ No'}")
        return

    async def run_create():
        async with get_api_client() as client:
            try:
                result = await client.create_scope(name=name, description=description, is_default=is_default)

                if output == "json":
                    click.echo(json.dumps(result.model_dump(), indent=2, default=str))
                else:
                    click.echo("✅ Scope created successfully!")
                    click.echo(f"  Scope Name: {result.scope_name}")
                    click.echo(f"  Description: {result.description or 'None'}")
                    click.echo(f"  Default: {'✅ Yes' if result.is_default else '❌ No'}")
                    click.echo(f"  Active: {'✅ Yes' if result.is_active else '❌ No'}")
                    click.echo(f"  Created: {result.created_at}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error creating scope: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_create())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@scope_group.command("list")
@click.option("--limit", type=int, default=100, help="Maximum number of scopes to return")
@click.option("--offset", type=int, default=0, help="Number of scopes to skip")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("--show-inactive", is_flag=True, help="Include inactive scopes")
@click.option("--default-only", is_flag=True, help="Show only default scopes")
@click.pass_context
def list_scopes(ctx: click.Context, limit: int, offset: int, output: str, show_inactive: bool, default_only: bool):
    """List OAuth 2.1 scopes."""
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        click.echo(f"Listing OAuth scopes (limit: {limit}, offset: {offset})")

    async def run_list():
        async with get_api_client() as client:
            try:
                if default_only:
                    scopes = await client.get_default_scopes()
                else:
                    scopes = await client.list_scopes(active_only=not show_inactive, limit=limit, offset=offset)

                if output == "json":
                    click.echo(json.dumps([scope.model_dump() for scope in scopes], indent=2, default=str))
                else:
                    if not scopes:
                        click.echo("No scopes found.")
                        return

                    # Table header
                    click.echo(f"{'Scope Name':<20} {'Description':<40} {'Default':<7} {'Active':<6} {'Created'}")
                    click.echo("-" * 100)

                    # Table rows
                    for scope in scopes:
                        description = scope.description or ""
                        if len(description) > 37:
                            description = description[:37] + "..."

                        default_flag = "✅" if scope.is_default else "❌"
                        active_flag = "✅" if scope.is_active else "❌"
                        created = scope.created_at.strftime("%Y-%m-%d")

                        click.echo(
                            f"{scope.scope_name:<20} {description:<40} {default_flag:<7} {active_flag:<6} {created}"
                        )

                    click.echo(f"\nTotal: {len(scopes)} scope(s)")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error listing scopes: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_list())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@scope_group.command("show")
@click.argument("scope_name")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.pass_context
def show_scope(ctx: click.Context, scope_name: str, output: str):
    """Show detailed information about a specific scope."""
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        click.echo(f"Getting scope details: {scope_name}")

    async def run_show():
        async with get_api_client() as client:
            try:
                scope = await client.get_scope(scope_name)

                if output == "json":
                    click.echo(json.dumps(scope.model_dump(), indent=2, default=str))
                else:
                    click.echo("Scope Details")
                    click.echo("=" * 50)
                    click.echo(f"Scope Name: {scope.scope_name}")
                    click.echo(f"Description: {scope.description or 'None'}")
                    click.echo(f"Default: {'✅ Yes' if scope.is_default else '❌ No'}")
                    click.echo(f"Active: {'✅ Yes' if scope.is_active else '❌ No'}")
                    click.echo(f"Created: {scope.created_at}")
                    click.echo(f"Updated: {scope.updated_at}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                if "404" in str(e):
                    click.echo(f"❌ Scope not found: {scope_name}", err=True)
                else:
                    click.echo(f"❌ Error getting scope details: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_show())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@scope_group.command("update")
@click.argument("scope_name")
@click.option("--description", help="Update scope description")
@click.option("--make-default", is_flag=True, help="Mark as default scope")
@click.option("--remove-default", is_flag=True, help="Remove default flag")
@click.option("--activate", is_flag=True, help="Activate scope")
@click.option("--deactivate", is_flag=True, help="Deactivate scope")
@click.pass_context
def update_scope(
    ctx: click.Context,
    scope_name: str,
    description: str | None,
    make_default: bool,
    remove_default: bool,
    activate: bool,
    deactivate: bool,
):
    """Update scope information."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if make_default and remove_default:
        click.echo("❌ Cannot specify both --make-default and --remove-default", err=True)
        sys.exit(1)

    if activate and deactivate:
        click.echo("❌ Cannot specify both --activate and --deactivate", err=True)
        sys.exit(1)

    # Build update data
    update_data = {}
    if description is not None:
        update_data["description"] = description
    if make_default:
        update_data["is_default"] = True
    elif remove_default:
        update_data["is_default"] = False
    if activate:
        update_data["is_active"] = True
    elif deactivate:
        update_data["is_active"] = False

    if not update_data:
        click.echo("❌ No update options specified", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Updating scope: {scope_name}")
        click.echo(f"Changes: {update_data}")

    if dry_run:
        click.echo("DRY RUN: Would update scope with:")
        for key, value in update_data.items():
            click.echo(f"  {key}: {value}")
        return

    async def run_update():
        async with get_api_client() as client:
            try:
                updated_scope = await client.update_scope(
                    scope_name,
                    description=update_data.get("description"),
                    is_default=update_data.get("is_default"),
                    is_active=update_data.get("is_active"),
                )

                click.echo("✅ Scope updated successfully!")
                click.echo(f"  Scope Name: {updated_scope.scope_name}")
                click.echo(f"  Description: {updated_scope.description or 'None'}")
                click.echo(f"  Default: {'✅ Yes' if updated_scope.is_default else '❌ No'}")
                click.echo(f"  Active: {'✅ Yes' if updated_scope.is_active else '❌ No'}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error updating scope: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_update())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@scope_group.command("delete")
@click.argument("scope_name")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def delete_scope(ctx: click.Context, scope_name: str, confirm: bool):
    """Delete (deactivate) a scope."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if verbose:
        click.echo(f"Deleting scope: {scope_name}")

    if not confirm and not dry_run and not click.confirm(f"This will deactivate scope '{scope_name}'. Continue?"):
        click.echo("Operation cancelled.")
        return

    if dry_run:
        click.echo("DRY RUN: Would deactivate scope")
        return

    async def run_delete():
        async with get_api_client() as client:
            try:
                result = await client.delete_scope(scope_name)

                click.echo("✅ Scope deactivated successfully!")
                click.echo(f"  Message: {result.get('message', 'Scope deleted')}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                if "404" in str(e):
                    click.echo("❌ Scope not found or cannot be deactivated", err=True)
                else:
                    click.echo(f"❌ Error deleting scope: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_delete())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@scope_group.command("defaults")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.pass_context
def show_defaults(ctx: click.Context, output: str):
    """Show all default scopes."""
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        click.echo("Getting default scopes")

    async def run_defaults():
        async with get_api_client() as client:
            try:
                default_scopes = await client.get_default_scopes()

                if output == "json":
                    click.echo(json.dumps([scope.model_dump() for scope in default_scopes], indent=2, default=str))
                else:
                    if not default_scopes:
                        click.echo("No default scopes configured.")
                        return

                    click.echo("Default Scopes")
                    click.echo("=" * 50)

                    for scope in default_scopes:
                        click.echo(f"  {scope.scope_name}")
                        if scope.description:
                            click.echo(f"    Description: {scope.description}")
                        click.echo(f"    Active: {'✅ Yes' if scope.is_active else '❌ No'}")
                        click.echo()

                    click.echo(f"Total: {len(default_scopes)} default scope(s)")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error getting default scopes: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_defaults())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)
