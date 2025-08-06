"""Tests for OAuth 2.1 FastAPI dependencies."""

import base64
import logging
from uuid import uuid4

import pytest
from fastapi import HTTPException
from psycopg_toolkit import TransactionManager

from authly.api.auth_dependencies import _parse_basic_auth_header, get_current_client
from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.client_service import ClientService
from authly.oauth.models import (
    ClientType,
    GrantType,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository

logger = logging.getLogger(__name__)


@pytest.fixture
async def test_confidential_client_data():
    """Test confidential client data for OAuth client creation."""
    return {
        "client_id": "test_confidential_client_" + uuid4().hex[:8],
        "client_name": "Test Confidential OAuth Client",
        "client_type": ClientType.CONFIDENTIAL,
        "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        "client_secret": "test_secret_123_" + uuid4().hex[:8],
        "is_active": True,
    }


@pytest.fixture
async def test_confidential_client_post_data():
    """Test confidential client data for CLIENT_SECRET_POST authentication."""
    return {
        "client_id": "test_post_client_" + uuid4().hex[:8],
        "client_name": "Test POST Auth OAuth Client",
        "client_type": ClientType.CONFIDENTIAL,
        "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_POST,
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        "client_secret": "test_post_secret_" + uuid4().hex[:8],
        "is_active": True,
    }


@pytest.fixture
async def test_public_client_data():
    """Test public client data for OAuth client creation."""
    return {
        "client_id": "test_public_client_" + uuid4().hex[:8],
        "client_name": "Test Public OAuth Client",
        "client_type": ClientType.PUBLIC,
        "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": [GrantType.AUTHORIZATION_CODE],
        "is_active": True,
    }


@pytest.fixture
async def created_confidential_client(
    initialize_authly: AuthlyResourceManager,
    test_confidential_client_data: dict,
    transaction_manager: TransactionManager,
):
    """Create a confidential client in the database for testing."""
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        return await client_repo.create_client(test_confidential_client_data)


@pytest.fixture
async def created_public_client(
    initialize_authly: AuthlyResourceManager, test_public_client_data: dict, transaction_manager: TransactionManager
):
    """Create a public client in the database for testing."""
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        return await client_repo.create_client(test_public_client_data)


@pytest.fixture
async def created_post_client(
    initialize_authly: AuthlyResourceManager,
    test_confidential_client_post_data: dict,
    transaction_manager: TransactionManager,
):
    """Create a confidential client with CLIENT_SECRET_POST auth method."""
    async with transaction_manager.transaction() as conn:
        client_repo = ClientRepository(conn)
        return await client_repo.create_client(test_confidential_client_post_data)


class TestParseBasicAuthHeader:
    """Test cases for Basic Auth header parsing."""

    def test_valid_basic_auth_header(self):
        """Test parsing valid Basic Auth header."""
        client_id = "test_client"
        client_secret = "test_secret"
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        header = f"Basic {encoded}"

        parsed_id, parsed_secret = _parse_basic_auth_header(header)

        assert parsed_id == client_id
        assert parsed_secret == client_secret

    def test_basic_auth_header_public_client(self):
        """Test parsing Basic Auth header for public client (empty secret)."""
        client_id = "test_public_client"
        credentials = f"{client_id}:"  # Empty secret
        encoded = base64.b64encode(credentials.encode()).decode()
        header = f"Basic {encoded}"

        parsed_id, parsed_secret = _parse_basic_auth_header(header)

        assert parsed_id == client_id
        assert parsed_secret is None

    def test_invalid_auth_scheme(self):
        """Test invalid authorization scheme raises HTTPException."""
        header = "Bearer some_token"

        with pytest.raises(HTTPException) as exc_info:
            _parse_basic_auth_header(header)

        assert exc_info.value.status_code == 401
        assert "Invalid authorization header format" in exc_info.value.detail

    def test_invalid_base64_encoding(self):
        """Test invalid base64 encoding raises HTTPException."""
        header = "Basic invalid_base64!!!"

        with pytest.raises(HTTPException) as exc_info:
            _parse_basic_auth_header(header)

        assert exc_info.value.status_code == 401
        assert "Invalid credentials format" in exc_info.value.detail

    def test_missing_colon_separator(self):
        """Test missing colon separator raises HTTPException."""
        credentials = "test_client_no_colon"
        encoded = base64.b64encode(credentials.encode()).decode()
        header = f"Basic {encoded}"

        with pytest.raises(HTTPException) as exc_info:
            _parse_basic_auth_header(header)

        assert exc_info.value.status_code == 401
        assert "Invalid credentials format" in exc_info.value.detail

    def test_empty_client_id(self):
        """Test empty client ID raises HTTPException."""
        credentials = ":test_secret"  # Empty client_id
        encoded = base64.b64encode(credentials.encode()).decode()
        header = f"Basic {encoded}"

        with pytest.raises(HTTPException) as exc_info:
            _parse_basic_auth_header(header)

        assert exc_info.value.status_code == 401
        assert "Client ID is required" in exc_info.value.detail

    def test_unicode_decode_error(self):
        """Test unicode decode error raises HTTPException."""
        # Create invalid UTF-8 bytes - escape them properly
        invalid_bytes = b"\xff\xfe"
        encoded = base64.b64encode(invalid_bytes).decode()
        header = f"Basic {encoded}"

        with pytest.raises(HTTPException) as exc_info:
            _parse_basic_auth_header(header)

        assert exc_info.value.status_code == 401
        # The actual error message depends on what fails first - format or encoding
        assert "Invalid credentials" in exc_info.value.detail


class TestGetCurrentClientDependency:
    """Test cases for get_current_client FastAPI dependency."""

    @pytest.mark.asyncio
    async def test_http_basic_auth_confidential_client(
        self,
        initialize_authly: AuthlyResourceManager,
        created_confidential_client,
        test_confidential_client_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test HTTP Basic Authentication with confidential client."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test the dependency
            client_id = test_confidential_client_data["client_id"]
            client_secret = test_confidential_client_data["client_secret"]
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(username=client_id, password=client_secret)

            authenticated_client = await get_current_client(
                request=request, client_service=client_service, basic_credentials=basic_credentials
            )

            assert authenticated_client is not None
            assert authenticated_client.client_id == client_id
            assert authenticated_client.client_type == ClientType.CONFIDENTIAL

    @pytest.mark.asyncio
    async def test_http_basic_auth_public_client(
        self,
        initialize_authly: AuthlyResourceManager,
        created_public_client,
        test_public_client_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test HTTP Basic Authentication with public client (no secret)."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test the dependency with public client (no credentials)
            client_id = test_public_client_data["client_id"]
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(username=client_id, password="")

            authenticated_client = await get_current_client(
                request=request, client_service=client_service, basic_credentials=basic_credentials
            )

            assert authenticated_client is not None
            assert authenticated_client.client_id == client_id
            assert authenticated_client.client_type == ClientType.PUBLIC

    @pytest.mark.asyncio
    async def test_invalid_client_credentials(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authentication failure with invalid credentials."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test with invalid credentials
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(username="invalid_client", password="invalid_secret")

            with pytest.raises(HTTPException) as exc_info:
                await get_current_client(
                    request=request, client_service=client_service, basic_credentials=basic_credentials
                )

            assert exc_info.value.status_code == 401
            assert "Invalid client credentials" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_missing_client_credentials(
        self, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authentication failure with missing credentials."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test with no credentials
            with pytest.raises(HTTPException) as exc_info:
                await get_current_client(request=request, client_service=client_service, basic_credentials=None)

            assert exc_info.value.status_code == 401
            assert "Client authentication required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_confidential_client_wrong_secret(
        self,
        initialize_authly: AuthlyResourceManager,
        created_confidential_client,
        test_confidential_client_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test confidential client with wrong secret fails authentication."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test with wrong secret
            client_id = test_confidential_client_data["client_id"]
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(username=client_id, password="wrong_secret")

            with pytest.raises(HTTPException) as exc_info:
                await get_current_client(
                    request=request, client_service=client_service, basic_credentials=basic_credentials
                )

            assert exc_info.value.status_code == 401
            assert "Invalid client credentials" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_public_client_with_secret_fails(
        self,
        initialize_authly: AuthlyResourceManager,
        created_public_client,
        test_public_client_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test public client providing secret fails authentication."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test public client with secret (should fail)
            client_id = test_public_client_data["client_id"]
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(username=client_id, password="unexpected_secret")

            with pytest.raises(HTTPException) as exc_info:
                await get_current_client(
                    request=request, client_service=client_service, basic_credentials=basic_credentials
                )

            assert exc_info.value.status_code == 401
            assert "Invalid client credentials" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_inactive_client_fails(
        self,
        initialize_authly: AuthlyResourceManager,
        test_confidential_client_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test inactive client fails authentication."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create inactive client
            inactive_client_data = test_confidential_client_data.copy()
            inactive_client_data["is_active"] = False
            inactive_client_data["client_id"] = "inactive_client_" + uuid4().hex[:8]

            created_client = await client_repo.create_client(inactive_client_data)

            # Deactivate the client
            await client_repo.delete_client(created_client.id)

            # Create simple mock request
            class MockRequest:
                def __init__(self):
                    self.headers = {}

            request = MockRequest()

            # Test with inactive client
            from fastapi.security import HTTPBasicCredentials

            basic_credentials = HTTPBasicCredentials(
                username=inactive_client_data["client_id"], password=inactive_client_data["client_secret"]
            )

            with pytest.raises(HTTPException) as exc_info:
                await get_current_client(
                    request=request, client_service=client_service, basic_credentials=basic_credentials
                )

            assert exc_info.value.status_code == 401
            assert "Invalid client credentials" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_form_data_authentication(
        self,
        initialize_authly: AuthlyResourceManager,
        created_post_client,
        test_confidential_client_post_data: dict,
        transaction_manager: TransactionManager,
    ):
        """Test client authentication via form data (CLIENT_SECRET_POST)."""
        async with transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            scope_repo = ScopeRepository(conn)
            config = initialize_authly.get_config()
            client_service = ClientService(client_repo, scope_repo, config)

            # Create mock request with form data
            class MockFormData:
                def get(self, key, default=None):
                    data = {
                        "client_id": test_confidential_client_post_data["client_id"],
                        "client_secret": test_confidential_client_post_data["client_secret"],
                    }
                    return data.get(key, default)

            class MockRequest:
                def __init__(self):
                    self.headers = {"content-type": "application/x-www-form-urlencoded"}

                async def form(self):
                    return MockFormData()

                async def json(self):
                    raise Exception("Not JSON")

            request = MockRequest()

            # Test the dependency (no basic credentials, should fallback to form data)
            authenticated_client = await get_current_client(
                request=request, client_service=client_service, basic_credentials=None
            )

            assert authenticated_client is not None
            assert authenticated_client.client_id == test_confidential_client_post_data["client_id"]
            assert authenticated_client.client_type == ClientType.CONFIDENTIAL
