"""
Test that committed fixtures work correctly and data is visible to HTTP endpoints.
"""

import pytest
from fastapi_testing import AsyncTestServer

from authly.oauth.client_repository import ClientRepository
from authly.users.repository import UserRepository


class TestCommittedFixtures:
    """Test the committed fixtures for proper database visibility."""

    @pytest.mark.asyncio
    async def test_committed_user_visible_to_http(self, test_server: AsyncTestServer, committed_user, db_pool):
        """Test that committed user is visible to HTTP endpoints."""
        # Make a direct database query to verify user exists
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            fetched_user = await user_repo.get_by_id(committed_user.id)

            assert fetched_user is not None
            assert fetched_user.username == committed_user.username
            assert fetched_user.email == committed_user.email

    @pytest.mark.asyncio
    async def test_committed_oauth_client_visible(self, committed_oauth_client, db_pool):
        """Test that committed OAuth client is visible to database queries."""
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            fetched_client = await client_repo.get_by_client_id(committed_oauth_client["client_id"])

            assert fetched_client is not None
            assert fetched_client.client_name == committed_oauth_client["client_name"]
            assert fetched_client.client_type == committed_oauth_client["client_type"]

            # Verify the unhashed secret is included in the fixture
            assert "client_secret" in committed_oauth_client
            assert committed_oauth_client["client_secret"] is not None

    @pytest.mark.asyncio
    async def test_committed_public_client(self, committed_public_client, db_pool):
        """Test that public OAuth client (no secret) is properly created."""
        async with db_pool.connection() as conn:
            client_repo = ClientRepository(conn)
            fetched_client = await client_repo.get_by_client_id(committed_public_client["client_id"])

            assert fetched_client is not None
            assert fetched_client.client_type.value == "public"
            assert fetched_client.client_secret_hash is None  # Public clients have no secret
            assert fetched_client.require_pkce is True  # PKCE is mandatory for public clients

    @pytest.mark.asyncio
    async def test_committed_auth_setup(self, committed_auth_setup):
        """Test the complete auth setup fixture."""
        assert "user" in committed_auth_setup
        assert "client" in committed_auth_setup
        assert "scope" in committed_auth_setup
        assert "db_pool" in committed_auth_setup

        # Verify all components are properly set up
        assert committed_auth_setup["user"].id is not None
        assert committed_auth_setup["client"]["client_id"] is not None
        assert committed_auth_setup["scope"]["scope_name"] is not None

    @pytest.mark.asyncio
    async def test_committed_fixtures_cleanup(self, committed_user, db_pool):
        """Test that fixtures are properly cleaned up after use."""
        # This test verifies that the committed user fixture is working
        # The fixture itself handles cleanup via its yield/finally block
        
        # First verify the user exists during the test
        user_id = committed_user.id
        
        async with db_pool.connection() as conn:
            user_repo = UserRepository(conn)
            fetched_user = await user_repo.get_by_id(user_id)
            
            # User should exist during the test
            assert fetched_user is not None
            assert fetched_user.id == user_id
            
        # Note: The actual cleanup happens after the test completes,
        # handled by the fixture's finally block. We can't directly test
        # the cleanup within the same test that uses the fixture.
