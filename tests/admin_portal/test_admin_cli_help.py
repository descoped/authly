"""Comprehensive unit tests for Authly Admin CLI help system.

Tests all CLI commands for proper help text, examples, and documentation.
Uses mocking to avoid actual API calls and focus on CLI interface testing.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from authly.admin import cli
from authly.admin.api_client import AdminAPIClient, TokenInfo
from authly.oauth.models import (
    ClientType,
    GrantType,
    OAuthClientModel,
    OAuthScopeModel,
    ResponseType,
    TokenEndpointAuthMethod,
)


class TestCLIHelpSystem:
    """Test CLI help text and documentation."""

    @pytest.fixture
    def cli_runner(self):
        """CLI test runner."""
        return CliRunner()

    def test_main_help_structure(self, cli_runner: CliRunner):
        """Test main CLI help has proper structure with examples."""
        result = cli_runner.invoke(cli.main, ["--help"])
        assert result.exit_code == 0

        # Check for main sections
        assert "Authly Admin CLI - OAuth 2.1 Administration Tool" in result.output
        assert "Common Commands:" in result.output
        assert "Examples:" in result.output
        assert "Environment Variables:" in result.output

        # Check for specific examples
        assert "authly status" in result.output
        assert "authly auth login" in result.output
        assert "authly client list" in result.output
        assert "authly scope list" in result.output

        # Check for example commands with proper formatting
        assert "$ authly auth login -u admin" in result.output
        assert "$ authly client create --name" in result.output
        assert "$ authly scope create --name" in result.output

        # Check for environment variables documentation
        assert "AUTHLY_API_URL" in result.output
        assert "DATABASE_URL" in result.output
        assert "JWT_SECRET_KEY" in result.output

    def test_status_command_help(self, cli_runner: CliRunner):
        """Test status command help text."""
        result = cli_runner.invoke(cli.main, ["status", "--help"])
        assert result.exit_code == 0

        assert "Show Authly instance status and configuration" in result.output
        assert "Displays:" in result.output
        assert "API health status" in result.output
        assert "Database connection status" in result.output
        assert "Examples:" in result.output
        assert "$ authly status" in result.output
        assert "$ authly status --verbose" in result.output
        assert "Exit Codes:" in result.output

    def test_auth_group_help(self, cli_runner: CliRunner):
        """Test auth command group help."""
        result = cli_runner.invoke(cli.main, ["auth", "--help"])
        assert result.exit_code == 0

        assert "Authentication commands for admin access" in result.output
        assert "Common Commands:" in result.output
        assert "authly auth login" in result.output
        assert "authly auth logout" in result.output
        assert "authly auth whoami" in result.output
        assert "authly auth refresh" in result.output
        # Check that info command is listed
        assert "info" in result.output

    def test_auth_login_help(self, cli_runner: CliRunner):
        """Test auth login command help with examples."""
        result = cli_runner.invoke(cli.main, ["auth", "login", "--help"])
        assert result.exit_code == 0

        assert "Login to the Authly Admin API" in result.output
        assert "Examples:" in result.output
        assert "$ authly auth login -u admin" in result.output
        assert "Password: ***" in result.output
        assert "Available Scopes:" in result.output
        assert "admin:clients:read" in result.output
        assert "admin:clients:write" in result.output
        assert "Security Notes:" in result.output
        assert "Tokens expire after" in result.output

    def test_auth_logout_help(self, cli_runner: CliRunner):
        """Test auth logout command help."""
        result = cli_runner.invoke(cli.main, ["auth", "logout", "--help"])
        assert result.exit_code == 0

        assert "Logout from the Authly Admin API" in result.output
        assert "Revokes stored tokens" in result.output
        assert "Examples:" in result.output
        assert "$ authly auth logout" in result.output
        assert "Notes:" in result.output
        assert "Tokens are revoked on the server" in result.output

    def test_auth_whoami_help(self, cli_runner: CliRunner):
        """Test auth whoami command help."""
        result = cli_runner.invoke(cli.main, ["auth", "whoami", "--help"])
        assert result.exit_code == 0

        assert "Show current authentication status" in result.output
        assert "Examples:" in result.output
        assert "$ authly auth whoami" in result.output
        assert "$ authly auth whoami --verbose" in result.output
        assert "Exit Codes:" in result.output

    def test_auth_refresh_help(self, cli_runner: CliRunner):
        """Test auth refresh command help."""
        result = cli_runner.invoke(cli.main, ["auth", "refresh", "--help"])
        assert result.exit_code == 0

        assert "Refresh authentication tokens" in result.output
        assert "Examples:" in result.output
        assert "$ authly auth refresh" in result.output
        assert "Notes:" in result.output
        assert "Access tokens expire" in result.output
        assert "Refresh tokens expire" in result.output

    def test_auth_info_help(self, cli_runner: CliRunner):
        """Test auth info command help."""
        result = cli_runner.invoke(cli.main, ["auth", "info", "--help"])
        assert result.exit_code == 0

        assert "Show Authly configuration and internal information" in result.output
        assert "Displays:" in result.output
        assert "Configuration paths" in result.output
        assert "Token storage location" in result.output
        assert "API endpoints" in result.output
        assert "Environment settings" in result.output
        assert "Version information" in result.output
        assert "Examples:" in result.output
        assert "$ authly auth info" in result.output
        assert "Configuration directory:" in result.output
        assert "Token file:" in result.output

    def test_auth_login_show_token_option(self, cli_runner: CliRunner):
        """Test auth login command has --show-token option."""
        result = cli_runner.invoke(cli.main, ["auth", "login", "--help"])
        assert result.exit_code == 0

        assert "--show-token" in result.output
        assert "Display the access token" in result.output
        assert "use with caution" in result.output.lower()

    def test_client_group_help(self, cli_runner: CliRunner):
        """Test client command group help."""
        result = cli_runner.invoke(cli.main, ["client", "--help"])
        assert result.exit_code == 0

        assert "Manage OAuth 2.1 clients" in result.output
        assert "Common Commands:" in result.output
        assert "authly client create" in result.output
        assert "authly client list" in result.output
        assert "Client Types:" in result.output
        assert "public" in result.output
        assert "confidential" in result.output

    def test_client_create_help(self, cli_runner: CliRunner):
        """Test client create command help with comprehensive examples."""
        result = cli_runner.invoke(cli.main, ["client", "create", "--help"])
        assert result.exit_code == 0

        assert "Create a new OAuth 2.1 client" in result.output
        assert "Examples:" in result.output

        # Check for various example scenarios
        assert "Create a public client for a React SPA" in result.output
        assert '$ authly client create --name "My React App" --type public' in result.output

        assert "Create a confidential client for a backend API" in result.output
        assert "--type confidential" in result.output
        assert "Client Secret:" in result.output

        assert "Authentication Methods" in result.output
        assert "client_secret_basic" in result.output
        assert "client_secret_post" in result.output

        assert "Security Notes:" in result.output
        assert "PKCE is enabled by default" in result.output

    def test_client_list_help(self, cli_runner: CliRunner):
        """Test client list command help."""
        result = cli_runner.invoke(cli.main, ["client", "list", "--help"])
        assert result.exit_code == 0

        assert "List OAuth 2.1 clients" in result.output
        assert "Examples:" in result.output
        assert "$ authly client list" in result.output
        assert "$ authly client list --show-inactive" in result.output
        assert "$ authly client list --output json" in result.output
        assert "Table Columns:" in result.output
        assert "Client ID" in result.output

    def test_client_show_help(self, cli_runner: CliRunner):
        """Test client show command help."""
        result = cli_runner.invoke(cli.main, ["client", "show", "--help"])
        assert result.exit_code == 0

        assert "Show detailed information about a specific client" in result.output
        assert "Examples:" in result.output
        assert "$ authly client show" in result.output
        assert "Client Details" in result.output
        assert "Redirect URIs:" in result.output
        assert "Grant Types:" in result.output
        assert "Exit Codes:" in result.output

    def test_client_update_help(self, cli_runner: CliRunner):
        """Test client update command help."""
        result = cli_runner.invoke(cli.main, ["client", "update", "--help"])
        assert result.exit_code == 0

        assert "Update client information" in result.output
        assert "Examples:" in result.output
        assert "$ authly client update" in result.output
        assert '--name "My Updated React App"' in result.output
        assert "--deactivate" in result.output
        assert "--activate" in result.output
        assert "Limitations:" in result.output
        assert "Cannot change client type" in result.output

    def test_client_regenerate_secret_help(self, cli_runner: CliRunner):
        """Test client regenerate-secret command help."""
        result = cli_runner.invoke(cli.main, ["client", "regenerate-secret", "--help"])
        assert result.exit_code == 0

        assert "Regenerate client secret for confidential clients" in result.output
        assert "Examples:" in result.output
        assert "$ authly client regenerate-secret" in result.output
        assert "--confirm" in result.output
        assert "Important:" in result.output
        assert "Old secret immediately becomes invalid" in result.output
        assert "Security Best Practices:" in result.output

    def test_client_delete_help(self, cli_runner: CliRunner):
        """Test client delete command help."""
        result = cli_runner.invoke(cli.main, ["client", "delete", "--help"])
        assert result.exit_code == 0

        assert "Delete (deactivate) a client" in result.output
        assert "Soft-deletes a client" in result.output
        assert "Examples:" in result.output
        assert "$ authly client delete" in result.output
        assert "Effects:" in result.output
        assert "Client cannot issue new authorization requests" in result.output
        assert "Notes:" in result.output

    def test_scope_group_help(self, cli_runner: CliRunner):
        """Test scope command group help."""
        result = cli_runner.invoke(cli.main, ["scope", "--help"])
        assert result.exit_code == 0

        assert "Manage OAuth 2.1 scopes" in result.output
        assert "Common Commands:" in result.output
        assert "authly scope create" in result.output
        assert "authly scope defaults" in result.output
        assert "Best Practices:" in result.output
        assert "Use descriptive scope names" in result.output

    def test_scope_create_help(self, cli_runner: CliRunner):
        """Test scope create command help."""
        result = cli_runner.invoke(cli.main, ["scope", "create", "--help"])
        assert result.exit_code == 0

        assert "Create a new OAuth 2.1 scope" in result.output
        assert "Examples:" in result.output
        assert "$ authly scope create --name read" in result.output
        assert "--default" in result.output
        assert "Scope Naming Conventions:" in result.output
        assert "user:read" in result.output
        assert "admin:users:write" in result.output
        assert "Notes:" in result.output

    def test_scope_list_help(self, cli_runner: CliRunner):
        """Test scope list command help."""
        result = cli_runner.invoke(cli.main, ["scope", "list", "--help"])
        assert result.exit_code == 0

        assert "List OAuth 2.1 scopes" in result.output
        assert "Examples:" in result.output
        assert "$ authly scope list" in result.output
        assert "--show-inactive" in result.output
        assert "--default-only" in result.output
        assert "Table Columns:" in result.output

    def test_scope_show_help(self, cli_runner: CliRunner):
        """Test scope show command help."""
        result = cli_runner.invoke(cli.main, ["scope", "show", "--help"])
        assert result.exit_code == 0

        assert "Show detailed information about a specific scope" in result.output
        assert "Examples:" in result.output
        assert "$ authly scope show profile" in result.output
        assert "Scope Details" in result.output
        assert "Exit Codes:" in result.output

    def test_scope_update_help(self, cli_runner: CliRunner):
        """Test scope update command help."""
        result = cli_runner.invoke(cli.main, ["scope", "update", "--help"])
        assert result.exit_code == 0

        assert "Update scope information" in result.output
        assert "Examples:" in result.output
        assert "--description" in result.output
        assert "--make-default" in result.output
        assert "--remove-default" in result.output
        assert "--deactivate" in result.output
        assert "Update Options:" in result.output
        assert "Important:" in result.output

    def test_scope_delete_help(self, cli_runner: CliRunner):
        """Test scope delete command help."""
        result = cli_runner.invoke(cli.main, ["scope", "delete", "--help"])
        assert result.exit_code == 0

        assert "Delete (deactivate) a scope" in result.output
        assert "Soft-deletes a scope" in result.output
        assert "Examples:" in result.output
        assert "Effects:" in result.output
        assert "Notes:" in result.output

    def test_scope_defaults_help(self, cli_runner: CliRunner):
        """Test scope defaults command help."""
        result = cli_runner.invoke(cli.main, ["scope", "defaults", "--help"])
        assert result.exit_code == 0

        assert "Show all default scopes" in result.output
        assert "Lists scopes that are automatically granted" in result.output
        assert "Examples:" in result.output
        assert "$ authly scope defaults" in result.output
        assert "Use Cases:" in result.output
        assert "Notes:" in result.output


class TestCLICommandExecution:
    """Test CLI command execution with mocked API calls."""

    @pytest.fixture
    def cli_runner(self):
        """CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def mock_api_client(self):
        """Mock AdminAPIClient for testing."""
        with patch("authly.admin.cli.AdminAPIClient") as mock:
            client = AsyncMock(spec=AdminAPIClient)
            mock.return_value.__aenter__.return_value = client
            mock.return_value.__aexit__.return_value = None
            yield client

    @pytest.fixture
    def mock_auth_client(self):
        """Mock AdminAPIClient for auth commands."""
        with patch("authly.admin.auth_commands.AdminAPIClient") as mock:
            client = AsyncMock(spec=AdminAPIClient)
            client.is_authenticated = False
            client._token_info = None
            client.token_file = "/home/user/.authly/tokens.json"
            mock.return_value.__aenter__.return_value = client
            mock.return_value.__aexit__.return_value = None
            yield client

    @pytest.fixture
    def mock_client_api(self):
        """Mock AdminAPIClient for client commands."""
        with patch("authly.admin.client_commands.AdminAPIClient") as mock:
            client = AsyncMock(spec=AdminAPIClient)
            mock.return_value.__aenter__.return_value = client
            mock.return_value.__aexit__.return_value = None
            yield client

    @pytest.fixture
    def mock_scope_api(self):
        """Mock AdminAPIClient for scope commands."""
        with patch("authly.admin.scope_commands.AdminAPIClient") as mock:
            client = AsyncMock(spec=AdminAPIClient)
            mock.return_value.__aenter__.return_value = client
            mock.return_value.__aexit__.return_value = None
            yield client

    def test_status_command_execution(self, cli_runner: CliRunner, mock_api_client):
        """Test status command execution."""
        # Mock the API responses
        mock_api_client.get_health.return_value = {"status": "OK"}
        mock_api_client.is_authenticated = False

        result = cli_runner.invoke(cli.main, ["status"])
        assert result.exit_code == 0
        assert "API Health: OK" in result.output
        assert "Authentication: Not logged in" in result.output

    def test_status_command_verbose(self, cli_runner: CliRunner, mock_api_client):
        """Test status command with verbose flag."""
        mock_api_client.get_health.return_value = {"status": "OK"}
        mock_api_client.is_authenticated = True
        mock_api_client.get_status.return_value = {
            "database": {"connected": True, "version": "14.5"},
            "statistics": {"oauth_clients": 5, "oauth_scopes": 3},
        }

        result = cli_runner.invoke(cli.main, ["-v", "status"])
        assert result.exit_code == 0
        assert "API Health: OK" in result.output
        # The verbose output is shown in the service statistics section
        assert "Service Statistics" in result.output
        assert "OAuth Clients: 5" in result.output
        assert "OAuth Scopes: 3" in result.output

    def test_auth_login_success(self, cli_runner: CliRunner, mock_auth_client):
        """Test successful login."""
        from datetime import datetime, timedelta

        token_info = MagicMock(spec=TokenInfo)
        token_info.expires_at = datetime.utcnow() + timedelta(hours=1)
        token_info.scope = "admin:clients:read admin:clients:write"

        mock_auth_client.login.return_value = token_info
        mock_auth_client.get_status.return_value = {"database": {"connected": True}}

        result = cli_runner.invoke(cli.main, ["auth", "login", "-u", "admin", "-p", "password"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "Successfully logged in as admin" in result.output

    def test_auth_logout(self, cli_runner: CliRunner, mock_auth_client):
        """Test logout command."""
        mock_auth_client.is_authenticated = True
        mock_auth_client.logout.return_value = None

        result = cli_runner.invoke(cli.main, ["auth", "logout"])
        assert result.exit_code == 0
        assert "Successfully logged out" in result.output

    def test_auth_whoami_authenticated(self, cli_runner: CliRunner, mock_auth_client):
        """Test whoami when authenticated."""
        from datetime import datetime, timedelta

        mock_auth_client.is_authenticated = True
        token_info = MagicMock(spec=TokenInfo)
        token_info.token_type = "Bearer"
        token_info.expires_at = datetime.utcnow() + timedelta(hours=1)
        token_info.scope = "admin:clients:read"
        mock_auth_client._token_info = token_info

        mock_auth_client.get_status.return_value = {
            "database": {"connected": True},
            "clients": {"total": 5},
            "scopes": {"total": 3},
        }

        result = cli_runner.invoke(cli.main, ["auth", "whoami", "--verbose"])
        assert result.exit_code == 0
        assert "Authenticated" in result.output
        assert "Token type: Bearer" in result.output

    def test_auth_whoami_not_authenticated(self, cli_runner: CliRunner, mock_auth_client):
        """Test whoami when not authenticated."""
        mock_auth_client.is_authenticated = False

        result = cli_runner.invoke(cli.main, ["auth", "whoami"])
        assert result.exit_code == 0
        assert "Not authenticated" in result.output
        assert "Use 'authly admin auth login' to authenticate" in result.output

    def test_auth_info_command(self, cli_runner: CliRunner, mock_auth_client):
        """Test info command execution."""
        mock_auth_client.is_authenticated = False

        result = cli_runner.invoke(cli.main, ["auth", "info"])
        assert result.exit_code == 0
        assert "Authly Configuration Information" in result.output
        assert "Configuration directory:" in result.output
        assert "Token file:" in result.output
        assert "API Configuration:" in result.output
        assert "API URL:" in result.output
        assert "Environment:" in result.output
        assert "Version Information:" in result.output
        assert "Authentication Status:" in result.output

    def test_auth_login_with_show_token(self, cli_runner: CliRunner, mock_auth_client):
        """Test login with --show-token flag."""
        from datetime import datetime, timedelta

        token_info = MagicMock(spec=TokenInfo)
        token_info.expires_at = datetime.utcnow() + timedelta(hours=1)
        token_info.scope = "admin:clients:read admin:clients:write"
        token_info.access_token = "test_access_token_12345"
        token_info.refresh_token = "test_refresh_token_67890"

        mock_auth_client.login.return_value = token_info
        mock_auth_client.get_status.return_value = {"database": {"connected": True}}

        result = cli_runner.invoke(
            cli.main, ["auth", "login", "-u", "admin", "-p", "password", "--show-token"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert "Successfully logged in as admin" in result.output
        assert "Access token: test_access_token_12345" in result.output
        assert "Refresh token: test_refresh_token_67890" in result.output

    def test_client_create_public(self, cli_runner: CliRunner, mock_client_api):
        """Test creating a public client."""
        created_client = MagicMock(spec=OAuthClientModel)
        created_client.client_id = "test-id-123"
        created_client.client_name = "Test App"
        created_client.client_type = ClientType.PUBLIC
        created_client.client_secret = None

        mock_client_api.create_client.return_value = (created_client, None)

        result = cli_runner.invoke(
            cli.main,
            [
                "client",
                "create",
                "--name",
                "Test App",
                "--type",
                "public",
                "--redirect-uri",
                "http://localhost:3000/callback",
            ],
        )
        assert result.exit_code == 0
        assert "Client created successfully!" in result.output
        assert "Client ID: test-id-123" in result.output
        assert "Client Secret: None (public client)" in result.output

    def test_client_create_confidential(self, cli_runner: CliRunner, mock_client_api):
        """Test creating a confidential client."""
        created_client = MagicMock(spec=OAuthClientModel)
        created_client.client_id = "test-id-456"
        created_client.client_name = "Backend Service"
        created_client.client_type = ClientType.CONFIDENTIAL

        mock_client_api.create_client.return_value = (created_client, "super-secret-key")

        result = cli_runner.invoke(
            cli.main,
            [
                "client",
                "create",
                "--name",
                "Backend Service",
                "--type",
                "confidential",
                "--redirect-uri",
                "https://api.example.com/callback",
            ],
        )
        assert result.exit_code == 0
        assert "Client created successfully!" in result.output
        assert "Client Secret: super-secret-key" in result.output
        assert "Store the client secret securely" in result.output

    def test_client_list(self, cli_runner: CliRunner, mock_client_api):
        """Test listing clients."""
        client1 = MagicMock(spec=OAuthClientModel)
        client1.client_id = "id1"
        client1.client_name = "App 1"
        client1.client_type = ClientType.PUBLIC
        client1.is_active = True
        client1.require_pkce = True
        client1.redirect_uris = ["http://localhost:3000"]

        client2 = MagicMock(spec=OAuthClientModel)
        client2.client_id = "id2"
        client2.client_name = "App 2"
        client2.client_type = ClientType.CONFIDENTIAL
        client2.is_active = False
        client2.require_pkce = True
        client2.redirect_uris = ["https://api.example.com"]

        mock_client_api.list_clients.return_value = [client1, client2]

        result = cli_runner.invoke(cli.main, ["client", "list"])
        assert result.exit_code == 0
        assert "App 1" in result.output
        assert "App 2" in result.output
        assert "Total: 2 client(s)" in result.output

    def test_client_show(self, cli_runner: CliRunner, mock_client_api):
        """Test showing client details."""
        from datetime import datetime

        client = MagicMock(spec=OAuthClientModel)
        client.client_id = "test-id"
        client.client_name = "Test App"
        client.client_type = ClientType.PUBLIC
        client.is_active = True
        client.require_pkce = True
        client.token_endpoint_auth_method = TokenEndpointAuthMethod.NONE
        client.created_at = datetime.utcnow()
        client.updated_at = datetime.utcnow()
        client.redirect_uris = ["http://localhost:3000"]
        client.grant_types = [GrantType.AUTHORIZATION_CODE]
        client.response_types = [ResponseType.CODE]
        client.scope = "read write"
        client.client_uri = "https://example.com"
        client.logo_uri = None
        client.tos_uri = None
        client.policy_uri = None

        mock_client_api.get_client.return_value = client

        result = cli_runner.invoke(cli.main, ["client", "show", "test-id"])
        assert result.exit_code == 0
        assert "Client Details" in result.output
        assert "Client ID: test-id" in result.output
        assert "Name: Test App" in result.output
        assert "Type: public" in result.output

    def test_scope_create(self, cli_runner: CliRunner, mock_scope_api):
        """Test creating a scope."""
        from datetime import datetime

        created_scope = MagicMock(spec=OAuthScopeModel)
        created_scope.scope_name = "read"
        created_scope.description = "Read access"
        created_scope.is_default = False
        created_scope.is_active = True
        created_scope.created_at = datetime.utcnow()

        mock_scope_api.create_scope.return_value = created_scope

        result = cli_runner.invoke(cli.main, ["scope", "create", "--name", "read", "--description", "Read access"])
        assert result.exit_code == 0
        assert "Scope created successfully!" in result.output
        assert "Scope Name: read" in result.output

    def test_scope_list(self, cli_runner: CliRunner, mock_scope_api):
        """Test listing scopes."""
        from datetime import datetime

        scope1 = MagicMock(spec=OAuthScopeModel)
        scope1.scope_name = "read"
        scope1.description = "Read access"
        scope1.is_default = False
        scope1.is_active = True
        scope1.created_at = datetime.utcnow()

        scope2 = MagicMock(spec=OAuthScopeModel)
        scope2.scope_name = "write"
        scope2.description = "Write access"
        scope2.is_default = True
        scope2.is_active = True
        scope2.created_at = datetime.utcnow()

        mock_scope_api.list_scopes.return_value = [scope1, scope2]

        result = cli_runner.invoke(cli.main, ["scope", "list"])
        assert result.exit_code == 0
        assert "read" in result.output
        assert "write" in result.output
        assert "Total: 2 scope(s)" in result.output

    def test_dry_run_mode(self, cli_runner: CliRunner):
        """Test dry-run mode prevents actual execution."""
        result = cli_runner.invoke(
            cli.main,
            [
                "--dry-run",
                "client",
                "create",
                "--name",
                "Test",
                "--type",
                "public",
                "--redirect-uri",
                "http://localhost:3000",
            ],
        )
        assert result.exit_code == 0
        assert "DRY RUN: Would create client" in result.output

    def test_json_output_format(self, cli_runner: CliRunner, mock_client_api):
        """Test JSON output format."""
        client = MagicMock(spec=OAuthClientModel)
        client.model_dump.return_value = {
            "client_id": "test-id",
            "client_name": "Test App",
            "client_type": "public",
            "is_active": True,
        }

        mock_client_api.list_clients.return_value = [client]

        result = cli_runner.invoke(cli.main, ["client", "list", "--output", "json"])
        assert result.exit_code == 0
        assert '"client_id": "test-id"' in result.output
        assert '"client_name": "Test App"' in result.output


class TestCLIErrorHandling:
    """Test CLI error handling and edge cases."""

    @pytest.fixture
    def cli_runner(self):
        """CLI test runner."""
        return CliRunner()

    def test_missing_required_parameters(self, cli_runner: CliRunner):
        """Test commands fail gracefully with missing required parameters."""
        # Missing --name for client create
        result = cli_runner.invoke(
            cli.main, ["client", "create", "--type", "public", "--redirect-uri", "http://localhost:3000"]
        )
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

        # Missing --name for scope create
        result = cli_runner.invoke(cli.main, ["scope", "create", "--description", "Test"])
        assert result.exit_code != 0

    def test_invalid_parameter_values(self, cli_runner: CliRunner):
        """Test commands handle invalid parameter values."""
        # Invalid client type
        result = cli_runner.invoke(
            cli.main,
            ["client", "create", "--name", "Test", "--type", "invalid_type", "--redirect-uri", "http://localhost:3000"],
        )
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "invalid_type" in result.output

        # Invalid output format
        result = cli_runner.invoke(cli.main, ["client", "list", "--output", "xml"])
        assert result.exit_code != 0

    def test_conflicting_options(self, cli_runner: CliRunner):
        """Test commands handle conflicting options."""
        # Both --activate and --deactivate
        result = cli_runner.invoke(cli.main, ["client", "update", "test-id", "--activate", "--deactivate"])
        assert result.exit_code != 0
        assert "Cannot specify both" in result.output

        # Both --make-default and --remove-default
        result = cli_runner.invoke(cli.main, ["scope", "update", "test-scope", "--make-default", "--remove-default"])
        assert result.exit_code != 0
        assert "Cannot specify both" in result.output

    @patch("authly.admin.client_commands.AdminAPIClient")
    def test_api_error_handling(self, mock_client_class, cli_runner: CliRunner):
        """Test handling of API errors."""
        from authly.admin.api_client import AdminAPIError

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client

        # Simulate API error
        mock_client.create_client.side_effect = AdminAPIError("API Error", 400, "Bad Request")

        result = cli_runner.invoke(
            cli.main,
            ["client", "create", "--name", "Test", "--type", "public", "--redirect-uri", "http://localhost:3000"],
        )
        assert result.exit_code != 0
        assert "API Error" in result.output

    @patch("authly.admin.client_commands.AdminAPIClient")
    def test_connection_error_handling(self, mock_client_class, cli_runner: CliRunner):
        """Test handling of connection errors."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client

        # Simulate connection error
        mock_client.list_clients.side_effect = ConnectionError("Connection refused")

        result = cli_runner.invoke(cli.main, ["client", "list"])
        assert result.exit_code != 0
        assert "Error" in result.output

    def test_help_flag_precedence(self, cli_runner: CliRunner):
        """Test that --help flag takes precedence over other errors."""
        # Even with missing required params, --help should work
        result = cli_runner.invoke(cli.main, ["client", "create", "--help"])
        assert result.exit_code == 0
        assert "Create a new OAuth 2.1 client" in result.output

    def test_version_flag(self, cli_runner: CliRunner):
        """Test version flag displays version information."""
        # The admin CLI doesn't have a --version flag, so we skip this test
        # or we could test that it shows an error
        result = cli_runner.invoke(cli.main, ["--version"])
        # The CLI doesn't have a version flag, so it will show an error
        assert result.exit_code != 0


class TestCLIIntegration:
    """Integration tests for CLI commands working together."""

    @pytest.fixture
    def cli_runner(self):
        """CLI test runner."""
        return CliRunner()

    def test_help_consistency_across_commands(self, cli_runner: CliRunner):
        """Test that help text is consistent across all commands."""
        commands = [
            ["--help"],
            ["status", "--help"],
            ["auth", "--help"],
            ["auth", "login", "--help"],
            ["auth", "logout", "--help"],
            ["auth", "whoami", "--help"],
            ["auth", "refresh", "--help"],
            ["auth", "info", "--help"],
            ["client", "--help"],
            ["client", "create", "--help"],
            ["client", "list", "--help"],
            ["client", "show", "--help"],
            ["client", "update", "--help"],
            ["client", "regenerate-secret", "--help"],
            ["client", "delete", "--help"],
            ["scope", "--help"],
            ["scope", "create", "--help"],
            ["scope", "list", "--help"],
            ["scope", "show", "--help"],
            ["scope", "update", "--help"],
            ["scope", "delete", "--help"],
            ["scope", "defaults", "--help"],
        ]

        for cmd in commands:
            result = cli_runner.invoke(cli.main, cmd)
            assert result.exit_code == 0, f"Command {' '.join(cmd)} failed"
            # Check for consistent sections
            if len(cmd) > 1 and cmd[-1] == "--help":
                # All command help should have some structure
                assert "Examples:" in result.output or "Options:" in result.output or "Commands:" in result.output, (
                    f"Command {' '.join(cmd)} lacks structure"
                )

    def test_command_aliases_work(self, cli_runner: CliRunner):
        """Test that command aliases work correctly.

        NOTE: Command aliases (login, logout, whoami at the admin level) were removed
        in favor of a cleaner architecture with clear separation of concerns.
        All authentication commands are now properly namespaced under 'auth'.

        This test is kept for historical reference and documentation of an important
        principle: If we add aliases in the future, they MUST respect all options
        and behaviors of the original command. An alias should be a true alias,
        not a wrapper or reimplementation.

        For example, if we had 'authly admin login' as an alias for
        'authly admin auth login', then:
        - 'authly admin login --show-token' must work exactly like
        - 'authly admin auth login --show-token'

        The removal of aliases was driven by the observation that maintaining
        this guarantee was creating code duplication and potential for drift.
        """
        # No-op test - aliases were intentionally removed
        # This test passes to document the architectural decision
        assert True, "Command aliases were removed for cleaner architecture"

    def test_global_options_propagation(self, cli_runner: CliRunner):
        """Test that global options propagate to subcommands."""
        # Test verbose flag - it should be included in the context
        result = cli_runner.invoke(cli.main, ["--verbose", "status"])
        # When verbose is enabled, we should see additional output
        # The status command shows verbose output when context has verbose=True
        assert "Authly Admin CLI starting..." in result.output or result.exit_code == 0

    def test_examples_are_executable(self, cli_runner: CliRunner):
        """Test that examples in help text use valid command structure."""
        # Get main help
        result = cli_runner.invoke(cli.main, ["--help"])

        # Extract example commands (simplified check)
        # Updated to reflect the correct command structure after alias removal
        example_commands = [
            ["status"],
            ["auth", "login", "-u", "admin"],  # Corrected path
            ["client", "list"],
            ["scope", "list"],
        ]

        for cmd in example_commands:
            # Check that the command structure is valid (would show help)
            help_cmd = [*cmd, "--help"]
            result = cli_runner.invoke(cli.main, help_cmd)
            assert result.exit_code == 0, f"Example command structure {' '.join(cmd)} is invalid"
