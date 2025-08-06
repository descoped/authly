"""OAuth 2.1 Client Management Commands for Authly Admin CLI."""

import asyncio
import json
import os
import sys

import click

from authly.admin.api_client import AdminAPIClient, AdminAPIError
from authly.oauth.models import ClientType, OAuthClientCreateRequest, TokenEndpointAuthMethod


def get_api_url() -> str:
    """Get the API URL from environment or use default."""
    return os.getenv("AUTHLY_API_URL", "http://localhost:8000")


def get_api_client() -> AdminAPIClient:
    """Create an AdminAPIClient instance."""
    api_url = get_api_url()
    return AdminAPIClient(base_url=api_url)


def validate_client_type(ctx, param, value):
    """Validate client type parameter."""
    if value is None:
        return None

    try:
        return ClientType(value)
    except ValueError as e:
        raise click.BadParameter(
            f"Invalid client type. Must be one of: {', '.join([ct.value for ct in ClientType])}"
        ) from e


def validate_auth_method(ctx, param, value):
    """Validate token endpoint auth method parameter."""
    if value is None:
        return None

    try:
        return TokenEndpointAuthMethod(value)
    except ValueError:
        methods = [method.value for method in TokenEndpointAuthMethod]
        raise click.BadParameter(f"Invalid auth method. Must be one of: {', '.join(methods)}") from None


@click.group(name="client")
def client_group():
    """Manage OAuth 2.1 clients."""
    pass


@client_group.command("create")
@click.option("--name", required=True, help="Client name")
@click.option(
    "--type",
    "client_type",
    type=click.Choice([ct.value for ct in ClientType]),
    required=True,
    callback=validate_client_type,
    help="Client type (confidential or public)",
)
@click.option(
    "--redirect-uri", "redirect_uris", multiple=True, required=True, help="Redirect URI (can specify multiple)"
)
@click.option("--scope", help="Default scopes (space-separated)")
@click.option("--client-uri", help="Client homepage URI")
@click.option("--logo-uri", help="Client logo URI")
@click.option("--tos-uri", help="Terms of service URI")
@click.option("--policy-uri", help="Privacy policy URI")
@click.option(
    "--auth-method",
    type=click.Choice([method.value for method in TokenEndpointAuthMethod]),
    callback=validate_auth_method,
    help="Token endpoint authentication method",
)
@click.option("--no-pkce", is_flag=True, help="Disable PKCE requirement (not recommended)")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.pass_context
def create_client(
    ctx: click.Context,
    name: str,
    client_type: ClientType,
    redirect_uris: list[str],
    scope: str | None,
    client_uri: str | None,
    logo_uri: str | None,
    tos_uri: str | None,
    policy_uri: str | None,
    auth_method: TokenEndpointAuthMethod | None,
    no_pkce: bool,
    output: str,
):
    """Create a new OAuth 2.1 client."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if verbose:
        click.echo(f"Creating {client_type.value} OAuth client: {name}")

    # Set default auth method based on client type
    if auth_method is None:
        auth_method = (
            TokenEndpointAuthMethod.NONE
            if client_type == ClientType.PUBLIC
            else TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
        )

    # Create request object
    create_request = OAuthClientCreateRequest(
        client_name=name,
        client_type=client_type,
        redirect_uris=list(redirect_uris),
        scope=scope,
        require_pkce=not no_pkce,
        token_endpoint_auth_method=auth_method,
        client_uri=client_uri,
        logo_uri=logo_uri,
        tos_uri=tos_uri,
        policy_uri=policy_uri,
    )

    if dry_run:
        click.echo("DRY RUN: Would create client with the following configuration:")
        if output == "json":
            click.echo(json.dumps(create_request.model_dump(), indent=2, default=str))
        else:
            click.echo(f"  Name: {name}")
            click.echo(f"  Type: {client_type.value}")
            click.echo(f"  Redirect URIs: {', '.join(redirect_uris)}")
            click.echo(f"  PKCE Required: {not no_pkce}")
            click.echo(f"  Auth Method: {auth_method.value}")
            if scope:
                click.echo(f"  Default Scopes: {scope}")
        return

    async def run_create():
        async with get_api_client() as client:
            try:
                result, secret = await client.create_client(create_request)

                if output == "json":
                    result_data = result.model_dump()
                    if secret:
                        result_data["client_secret"] = secret
                    click.echo(json.dumps(result_data, indent=2, default=str))
                else:
                    click.echo("✅ Client created successfully!")
                    click.echo(f"  Client ID: {result.client_id}")
                    click.echo(f"  Client Name: {result.client_name}")
                    click.echo(f"  Client Type: {result.client_type.value}")
                    if secret:
                        click.echo(f"  Client Secret: {secret}")
                        click.echo("  ⚠️  Store the client secret securely - it won't be shown again!")
                    else:
                        click.echo("  Client Secret: None (public client)")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error creating client: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_create())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@client_group.command("list")
@click.option("--limit", type=int, default=100, help="Maximum number of clients to return")
@click.option("--offset", type=int, default=0, help="Number of clients to skip")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("--show-inactive", is_flag=True, help="Include inactive clients")
@click.pass_context
def list_clients(ctx: click.Context, limit: int, offset: int, output: str, show_inactive: bool):
    """List OAuth 2.1 clients."""
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        click.echo(f"Listing OAuth clients (limit: {limit}, offset: {offset})")

    async def run_list():
        async with get_api_client() as client:
            try:
                clients = await client.list_clients(active_only=not show_inactive, limit=limit, offset=offset)

                if output == "json":
                    click.echo(json.dumps([client.model_dump() for client in clients], indent=2, default=str))
                else:
                    if not clients:
                        click.echo("No clients found.")
                        return

                    # Table header
                    click.echo(
                        f"{'Client ID':<36} {'Name':<20} {'Type':<12} {'Active':<6} {'PKCE':<4} {'Redirect URIs'}"
                    )
                    click.echo("-" * 120)

                    # Table rows
                    for client in clients:
                        status = "✅" if client.is_active else "❌"
                        pkce = "✅" if client.require_pkce else "❌"
                        redirect_uris = ", ".join(client.redirect_uris)
                        if len(redirect_uris) > 40:
                            redirect_uris = redirect_uris[:37] + "..."

                        click.echo(
                            f"{client.client_id:<36} {client.client_name:<20} "
                            f"{client.client_type.value:<12} {status:<6} {pkce:<4} {redirect_uris}"
                        )

                    click.echo(f"\nTotal: {len(clients)} client(s)")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error listing clients: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_list())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@client_group.command("show")
@click.argument("client_id")
@click.option("--output", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.pass_context
def show_client(ctx: click.Context, client_id: str, output: str):
    """Show detailed information about a specific client."""
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        click.echo(f"Getting client details: {client_id}")

    async def run_show():
        async with get_api_client() as client:
            try:
                client_details = await client.get_client(client_id)

                if output == "json":
                    click.echo(json.dumps(client_details.model_dump(), indent=2, default=str))
                else:
                    click.echo("Client Details")
                    click.echo("=" * 50)
                    click.echo(f"Client ID: {client_details.client_id}")
                    click.echo(f"Name: {client_details.client_name}")
                    click.echo(f"Type: {client_details.client_type.value}")
                    click.echo(f"Active: {'✅ Yes' if client_details.is_active else '❌ No'}")
                    click.echo(f"PKCE Required: {'✅ Yes' if client_details.require_pkce else '❌ No'}")
                    click.echo(f"Auth Method: {client_details.token_endpoint_auth_method.value}")
                    click.echo(f"Created: {client_details.created_at}")
                    click.echo(f"Updated: {client_details.updated_at}")

                    click.echo("\nRedirect URIs:")
                    for uri in client_details.redirect_uris:
                        click.echo(f"  - {uri}")

                    click.echo("\nGrant Types:")
                    for grant_type in client_details.grant_types:
                        click.echo(f"  - {grant_type.value}")

                    click.echo("\nResponse Types:")
                    for response_type in client_details.response_types:
                        click.echo(f"  - {response_type.value}")

                    if client_details.scope:
                        click.echo(f"\nDefault Scopes: {client_details.scope}")

                    # Optional metadata
                    if client_details.client_uri:
                        click.echo(f"\nClient URI: {client_details.client_uri}")
                    if client_details.logo_uri:
                        click.echo(f"Logo URI: {client_details.logo_uri}")
                    if client_details.tos_uri:
                        click.echo(f"Terms of Service: {client_details.tos_uri}")
                    if client_details.policy_uri:
                        click.echo(f"Privacy Policy: {client_details.policy_uri}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                if "404" in str(e):
                    click.echo(f"❌ Client not found: {client_id}", err=True)
                else:
                    click.echo(f"❌ Error getting client details: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_show())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@client_group.command("update")
@click.argument("client_id")
@click.option("--name", help="Update client name")
@click.option("--client-uri", help="Update client homepage URI")
@click.option("--logo-uri", help="Update client logo URI")
@click.option("--tos-uri", help="Update terms of service URI")
@click.option("--policy-uri", help="Update privacy policy URI")
@click.option("--activate", is_flag=True, help="Activate client")
@click.option("--deactivate", is_flag=True, help="Deactivate client")
@click.pass_context
def update_client(
    ctx: click.Context,
    client_id: str,
    name: str | None,
    client_uri: str | None,
    logo_uri: str | None,
    tos_uri: str | None,
    policy_uri: str | None,
    activate: bool,
    deactivate: bool,
):
    """Update client information."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if activate and deactivate:
        click.echo("❌ Cannot specify both --activate and --deactivate", err=True)
        sys.exit(1)

    # Build update data
    update_data = {}
    if name:
        update_data["client_name"] = name
    if client_uri is not None:
        update_data["client_uri"] = client_uri
    if logo_uri is not None:
        update_data["logo_uri"] = logo_uri
    if tos_uri is not None:
        update_data["tos_uri"] = tos_uri
    if policy_uri is not None:
        update_data["policy_uri"] = policy_uri
    if activate:
        update_data["is_active"] = True
    elif deactivate:
        update_data["is_active"] = False

    if not update_data:
        click.echo("❌ No update options specified", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Updating client: {client_id}")
        click.echo(f"Changes: {update_data}")

    if dry_run:
        click.echo("DRY RUN: Would update client with:")
        for key, value in update_data.items():
            click.echo(f"  {key}: {value}")
        return

    async def run_update():
        async with get_api_client() as client:
            try:
                updated_client = await client.update_client(client_id, update_data)

                click.echo("✅ Client updated successfully!")
                click.echo(f"  Client ID: {updated_client.client_id}")
                click.echo(f"  Name: {updated_client.client_name}")
                click.echo(f"  Active: {'✅ Yes' if updated_client.is_active else '❌ No'}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"❌ Error updating client: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_update())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@client_group.command("regenerate-secret")
@click.argument("client_id")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def regenerate_secret(ctx: click.Context, client_id: str, confirm: bool):
    """Regenerate client secret for confidential clients."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if verbose:
        click.echo(f"Regenerating secret for client: {client_id}")

    if not confirm and not dry_run and not click.confirm("This will invalidate the current client secret. Continue?"):
        click.echo("Operation cancelled.")
        return

    if dry_run:
        click.echo("DRY RUN: Would regenerate client secret")
        return

    async def run_regenerate():
        async with get_api_client() as client:
            try:
                credentials = await client.regenerate_client_secret(client_id)

                click.echo("✅ Client secret regenerated successfully!")
                click.echo(f"  New Secret: {credentials.client_secret}")
                click.echo("  ⚠️  Store the new secret securely - it won't be shown again!")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                if "404" in str(e):
                    click.echo("❌ Client not found", err=True)
                elif "public client" in str(e).lower():
                    click.echo("❌ Cannot regenerate secret for public client", err=True)
                else:
                    click.echo(f"❌ Error regenerating secret: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_regenerate())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@client_group.command("delete")
@click.argument("client_id")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def delete_client(ctx: click.Context, client_id: str, confirm: bool):
    """Delete (deactivate) a client."""
    verbose = ctx.obj.get("verbose", False)
    dry_run = ctx.obj.get("dry_run", False)

    if verbose:
        click.echo(f"Deleting client: {client_id}")

    if not confirm and not dry_run and not click.confirm(f"This will deactivate client '{client_id}'. Continue?"):
        click.echo("Operation cancelled.")
        return

    if dry_run:
        click.echo("DRY RUN: Would deactivate client")
        return

    async def run_delete():
        async with get_api_client() as client:
            try:
                result = await client.delete_client(client_id)

                click.echo("✅ Client deactivated successfully!")
                click.echo(f"  Message: {result.get('message', 'Client deleted')}")

            except AdminAPIError as e:
                click.echo(f"❌ {e.message}", err=True)
                sys.exit(1)
            except Exception as e:
                if "404" in str(e):
                    click.echo("❌ Client not found", err=True)
                else:
                    click.echo(f"❌ Error deleting client: {e}", err=True)
                sys.exit(1)

    try:
        asyncio.run(run_delete())
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)
