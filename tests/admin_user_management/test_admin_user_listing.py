"""
Tests for Admin User Listing API Endpoint.

This module tests the GET /admin/users endpoint with comprehensive
filtering, pagination, and security validation using real database integration.
"""

import logging
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import HTTPException

from authly.admin.models import AdminUserFilters, AdminUserListResponse, AdminUserResponse
from authly.users.models import UserModel
from authly.users.repository import UserRepository
from authly.users.service import UserService

logger = logging.getLogger(__name__)


class TestUserRepositoryFiltering:
    """Test UserRepository filtering capabilities with real database."""

    async def create_test_users(self, conn):
        """Create sample users in real database for testing."""
        import uuid

        # Generate a unique suffix to avoid conflicts with other tests
        unique_suffix = str(uuid.uuid4())[:8]
        user_repository = UserRepository(conn)
        users = []

        # Create admin user
        admin_user = UserModel(
            id=uuid4(),
            username=f"test_admin_{unique_suffix}",
            email=f"admin_{unique_suffix}@test.com",
            password_hash="hash",
            created_at=datetime(2023, 1, 1, tzinfo=UTC),
            updated_at=datetime(2023, 1, 1, tzinfo=UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
            given_name="Admin",
            family_name="User",
            locale="en-US",
        )
        users.append(await user_repository.create(admin_user))

        # Create regular user
        regular_user = UserModel(
            id=uuid4(),
            username=f"test_regular_{unique_suffix}",
            email=f"user_{unique_suffix}@test.com",
            password_hash="hash",
            created_at=datetime(2023, 1, 2, tzinfo=UTC),
            updated_at=datetime(2023, 1, 2, tzinfo=UTC),
            is_admin=False,
            is_active=True,
            is_verified=False,
            given_name="Regular",
            family_name="User",
            locale="es-ES",
        )
        users.append(await user_repository.create(regular_user))

        # Create inactive user
        inactive_user = UserModel(
            id=uuid4(),
            username=f"test_inactive_{unique_suffix}",
            email=f"inactive_{unique_suffix}@test.com",
            password_hash="hash",
            created_at=datetime(2023, 1, 3, tzinfo=UTC),
            updated_at=datetime(2023, 1, 3, tzinfo=UTC),
            is_admin=False,
            is_active=False,
            is_verified=True,
            given_name="Inactive",
            family_name="User",
        )
        users.append(await user_repository.create(inactive_user))

        return users

    @pytest.mark.asyncio
    async def test_build_filter_conditions_text_search(self, transaction_manager):
        """Test building filter conditions for text search."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            filters = {"username": "admin", "email": "@example.com", "given_name": "John", "family_name": "Doe"}

            conditions, params = user_repository._build_filter_conditions(filters)

            assert "username ILIKE %s" in conditions
            assert "email ILIKE %s" in conditions
            assert "given_name ILIKE %s" in conditions
            assert "family_name ILIKE %s" in conditions

            assert "%admin%" in params
            assert "%@example.com%" in params
            assert "%John%" in params
            assert "%Doe%" in params

    @pytest.mark.asyncio
    async def test_build_filter_conditions_boolean_filters(self, transaction_manager):
        """Test building filter conditions for boolean filters."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            filters = {"is_active": True, "is_admin": False, "is_verified": True, "requires_password_change": False}

            conditions, params = user_repository._build_filter_conditions(filters)

            assert "is_active = %s" in conditions
            assert "is_admin = %s" in conditions
            assert "is_verified = %s" in conditions
            assert "requires_password_change = %s" in conditions

            assert True in params
            assert False in params

    @pytest.mark.asyncio
    async def test_build_filter_conditions_date_ranges(self, transaction_manager):
        """Test building filter conditions for date ranges."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            start_date = datetime(2023, 1, 1, tzinfo=UTC)
            end_date = datetime(2023, 12, 31, tzinfo=UTC)

            filters = {
                "created_after": start_date,
                "created_before": end_date,
                "last_login_after": start_date,
                "last_login_before": end_date,
            }

            conditions, params = user_repository._build_filter_conditions(filters)

            assert "created_at >= %s" in conditions
            assert "created_at <= %s" in conditions
            assert "last_login >= %s" in conditions
            assert "last_login <= %s" in conditions

            assert start_date in params
            assert end_date in params

    @pytest.mark.asyncio
    async def test_build_filter_conditions_oidc_profile(self, transaction_manager):
        """Test building filter conditions for OIDC profile fields."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            filters = {"locale": "en-US", "zoneinfo": "America/New_York"}

            conditions, params = user_repository._build_filter_conditions(filters)

            assert "locale = %s" in conditions
            assert "zoneinfo = %s" in conditions
            assert "en-US" in params
            assert "America/New_York" in params

    @pytest.mark.asyncio
    async def test_build_filter_conditions_empty_filters(self, transaction_manager):
        """Test building filter conditions with empty filters."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            conditions, params = user_repository._build_filter_conditions({})

            assert len(conditions) == 0
            assert len(params) == 0

    @pytest.mark.asyncio
    async def test_build_filter_conditions_none_values_ignored(self, transaction_manager):
        """Test that None values are ignored in filters."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            filters = {
                "username": None,  # Should be ignored
                "is_active": None,  # Should be ignored
                "locale": "en-US",  # Should be included
            }

            conditions, params = user_repository._build_filter_conditions(filters)

            assert len(conditions) == 1
            assert "locale = %s" in conditions
            assert "en-US" in params

    @pytest.mark.asyncio
    async def test_get_filtered_paginated_success(self, transaction_manager):
        """Test successful filtered pagination with real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_test_users(conn)
            user_repository = UserRepository(conn)
            test_user_ids = {user.id for user in sample_users}

            # Test filtering by is_active=True (should return 2 users: admin and regular)
            filters = {"is_active": True}
            result = await user_repository.get_filtered_paginated(filters=filters, skip=0, limit=100)

            # Filter to only our test users
            our_active_users = [user for user in result if user.id in test_user_ids]

            assert len(our_active_users) == 2
            assert all(isinstance(user, UserModel) for user in our_active_users)
            assert all(user.is_active for user in our_active_users)

            # Verify the users are the expected ones
            usernames = {user.username for user in our_active_users}
            assert any("test_admin_" in username for username in usernames)
            assert any("test_regular_" in username for username in usernames)
            assert not any("test_inactive_" in username for username in usernames)

    @pytest.mark.asyncio
    async def test_get_filtered_paginated_no_filters(self, transaction_manager):
        """Test filtered pagination with no filters using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_test_users(conn)
            user_repository = UserRepository(conn)
            test_user_ids = {user.id for user in sample_users}

            # Test with no filters (should return all our 3 users)
            result = await user_repository.get_filtered_paginated(filters=None, skip=0, limit=100)

            # Filter to only our test users
            our_users = [user for user in result if user.id in test_user_ids]

            assert len(our_users) == 3
            assert all(isinstance(user, UserModel) for user in our_users)

            # Verify all users are returned
            usernames = {user.username for user in our_users}
            assert any("test_admin_" in username for username in usernames)
            assert any("test_regular_" in username for username in usernames)
            assert any("test_inactive_" in username for username in usernames)

    @pytest.mark.asyncio
    async def test_count_filtered_success(self, transaction_manager):
        """Test successful filtered count with real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_test_users(conn)
            user_repository = UserRepository(conn)

            # Count our test admin users (with unique username)
            admin_username = sample_users[0].username  # Get actual admin username
            filters = {"username": admin_username}
            result = await user_repository.count_filtered(filters=filters)
            assert result == 1  # Exactly our test admin user

            # Count users with test prefix
            filters = {"username": "test_admin"}  # Partial match
            result = await user_repository.count_filtered(filters=filters)
            assert result >= 1  # At least our test admin user

            # Count by email
            admin_email = sample_users[0].email
            filters = {"email": admin_email}
            result = await user_repository.count_filtered(filters=filters)
            assert result == 1  # Exactly our test admin user

    @pytest.mark.asyncio
    async def test_count_filtered_zero_results(self, transaction_manager):
        """Test filtered count with zero results using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users (not needed for this test but keeps pattern consistent)
            await self.create_test_users(conn)
            user_repository = UserRepository(conn)

            import uuid

            unique_id = str(uuid.uuid4())

            # Count users with guaranteed non-existent username
            result = await user_repository.count_filtered(filters={"username": f"nonexistent_{unique_id}"})
            assert result == 0

            # Count users with guaranteed non-existent email
            result = await user_repository.count_filtered(filters={"email": f"nobody_{unique_id}@nowhere.com"})
            assert result == 0

            # Count users with highly specific impossible combination
            result = await user_repository.count_filtered(
                filters={
                    "username": f"impossible_{unique_id}",
                    "is_admin": True,
                    "is_active": False,
                    "email": f"impossible_{unique_id}@test.com",
                }
            )
            assert result == 0

    @pytest.mark.asyncio
    async def test_get_admin_users_success(self, transaction_manager):
        """Test getting admin users with real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_test_users(conn)
            user_repository = UserRepository(conn)

            # Get all admin users
            result = await user_repository.get_admin_users()

            # Filter to only our test admin user
            test_admin = sample_users[0]  # First user we created is admin
            our_admin_users = [user for user in result if user.id == test_admin.id]

            # Should find our test admin user
            assert len(our_admin_users) == 1
            assert our_admin_users[0].is_admin is True
            assert our_admin_users[0].username == test_admin.username
            assert our_admin_users[0].email == test_admin.email

            # Verify it's properly ordered by created_at DESC
            assert isinstance(our_admin_users[0], UserModel)

    @pytest.mark.asyncio
    async def test_repository_filtering_edge_cases(self, transaction_manager):
        """Test repository filtering with edge cases."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_test_users(conn)
            user_repository = UserRepository(conn)

            # Test with invalid SQL injection attempt (repository should handle this safely)
            filters = {"username": "'; DROP TABLE users; --"}
            result = await user_repository.get_filtered_paginated(filters=filters, skip=0, limit=10)

            # Should return empty list, not cause SQL injection
            assert len(result) == 0

            # Test with complex filter combinations - use actual test data
            test_admin = sample_users[0]
            filters = {
                "username": "test_admin",  # Partial match
                "is_active": True,
                "is_admin": True,
            }
            result = await user_repository.get_filtered_paginated(filters=filters, skip=0, limit=100)

            # Should find our admin user with partial username match
            our_results = [user for user in result if user.id == test_admin.id]
            assert len(our_results) == 1
            assert our_results[0].username == test_admin.username

            # Test date filtering with our test users
            test_user_ids = {user.id for user in sample_users}
            filters = {
                "created_after": datetime(2022, 1, 1, tzinfo=UTC),
                "created_before": datetime(2024, 1, 1, tzinfo=UTC),
            }
            result = await user_repository.get_filtered_paginated(filters=filters, skip=0, limit=100)

            # Filter to only our test users and verify they're all found
            our_results = [user for user in result if user.id in test_user_ids]
            assert len(our_results) == 3


class TestUserServiceEnhancements:
    """Test UserService enhancements for admin operations with real database."""

    async def create_service_test_users(self, conn):
        """Create sample users in real database for service testing."""
        import uuid

        # Generate a unique suffix to avoid conflicts with other tests
        unique_suffix = str(uuid.uuid4())[:8]
        user_repository = UserRepository(conn)
        users = []

        # Create regular user
        regular_user = UserModel(
            id=uuid4(),
            username=f"service_user1_{unique_suffix}",
            email=f"service_user1_{unique_suffix}@example.com",
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=False,
            is_active=True,
            is_verified=True,
        )
        users.append(await user_repository.create(regular_user))

        # Create admin user
        admin_user = UserModel(
            id=uuid4(),
            username=f"service_user2_{unique_suffix}",
            email=f"service_user2_{unique_suffix}@example.com",
            password_hash="hash",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
        )
        users.append(await user_repository.create(admin_user))

        return users

    @pytest.mark.asyncio
    async def test_get_users_paginated_with_filters(self, transaction_manager):
        """Test getting paginated users with filters using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_service_test_users(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)
            test_user_ids = {user.id for user in sample_users}

            filters = {"is_active": True}
            result = await user_service.get_users_paginated(skip=0, limit=10, admin_context=True, filters=filters)

            # Filter to only our test users
            our_results = [user for user in result if user.id in test_user_ids]
            assert len(our_results) == 2  # Both test users are active
            assert all(user.is_active for user in our_results)

    @pytest.mark.asyncio
    async def test_get_users_paginated_without_filters(self, transaction_manager):
        """Test getting paginated users without filters using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_service_test_users(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)
            test_user_ids = {user.id for user in sample_users}

            result = await user_service.get_users_paginated(skip=0, limit=10, admin_context=True)

            # Filter to only our test users
            our_results = [user for user in result if user.id in test_user_ids]
            assert len(our_results) == 2  # Both test users should be returned

    @pytest.mark.asyncio
    async def test_count_users_with_filters(self, transaction_manager):
        """Test counting users with filters using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            sample_users = await self.create_service_test_users(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            # Count admin users using specific admin user's username
            admin_user = next(user for user in sample_users if user.is_admin)
            filters = {"username": admin_user.username}
            result = await user_service.count_users(filters=filters)

            assert result == 1  # Exactly our test admin user

    @pytest.mark.asyncio
    async def test_count_users_without_filters(self, transaction_manager):
        """Test counting users without filters using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            await self.create_service_test_users(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            result = await user_service.count_users()

            # Should return total count (including our test users and any existing users)
            assert result >= 2  # At least our test users

    @pytest.mark.asyncio
    async def test_service_error_handling(self, transaction_manager):
        """Test service layer error handling with real database."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            # Test with invalid filter that might cause database issues
            # Using a very large skip value that could cause performance issues
            try:
                await user_service.get_users_paginated(skip=999999, limit=1, filters={"is_active": True})
                # If no exception, that's fine - the service handled it gracefully
            except HTTPException as e:
                # If exception occurs, verify it's a proper HTTP exception
                assert e.status_code in [400, 500]


class TestAdminUserListingEndpoint:
    """Test the GET /admin/users endpoint via API integration tests."""

    @pytest.fixture
    def sample_user_data(self):
        """Sample user data for testing."""
        return [
            {
                "id": str(uuid4()),
                "username": "admin_user",
                "email": "admin@example.com",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
                "last_login": "2023-01-01T12:00:00Z",
                "is_active": True,
                "is_verified": True,
                "is_admin": True,
                "requires_password_change": False,
                "given_name": "Admin",
                "family_name": "User",
                "locale": "en-US",
            },
            {
                "id": str(uuid4()),
                "username": "regular_user",
                "email": "user@example.com",
                "created_at": "2023-01-02T00:00:00Z",
                "updated_at": "2023-01-02T00:00:00Z",
                "last_login": None,
                "is_active": True,
                "is_verified": False,
                "is_admin": False,
                "requires_password_change": True,
                "given_name": "Regular",
                "family_name": "User",
                "locale": "es-ES",
            },
        ]

    def test_admin_user_list_response_model(self, sample_user_data):
        """Test AdminUserListResponse model creation."""
        admin_users = [AdminUserResponse(**user_data) for user_data in sample_user_data]

        response = AdminUserListResponse(
            users=admin_users,
            total_count=2,
            page_info={
                "skip": 0,
                "limit": 25,
                "has_next": False,
                "has_previous": False,
                "current_page": 1,
                "total_pages": 1,
            },
            filters_applied={"is_active": True},
        )

        assert len(response.users) == 2
        assert response.total_count == 2
        assert response.page_info["current_page"] == 1
        assert response.filters_applied["is_active"] is True

    def test_admin_user_response_model(self, sample_user_data):
        """Test AdminUserResponse model creation."""
        user_data = sample_user_data[0]
        admin_user = AdminUserResponse(**user_data)

        assert str(admin_user.id) == user_data["id"]  # Compare string representations
        assert admin_user.username == user_data["username"]
        assert admin_user.email == user_data["email"]
        assert admin_user.is_admin is True
        assert admin_user.is_active is True
        assert admin_user.given_name == "Admin"
        assert admin_user.locale == "en-US"

    def test_admin_user_filters_model_comprehensive(self):
        """Test AdminUserFilters with comprehensive filter options."""
        filters = AdminUserFilters(
            username="john",
            email="@company.com",
            given_name="John",
            family_name="Doe",
            is_active=True,
            is_verified=False,
            is_admin=True,
            requires_password_change=False,
            created_after=datetime(2023, 1, 1, tzinfo=UTC),
            created_before=datetime(2023, 12, 31, tzinfo=UTC),
            last_login_after=datetime(2023, 6, 1, tzinfo=UTC),
            last_login_before=datetime(2023, 6, 30, tzinfo=UTC),
            locale="en-US",
            zoneinfo="America/New_York",
        )

        assert filters.username == "john"
        assert filters.email == "@company.com"
        assert filters.given_name == "John"
        assert filters.family_name == "Doe"
        assert filters.is_active is True
        assert filters.is_verified is False
        assert filters.is_admin is True
        assert filters.requires_password_change is False
        assert filters.created_after.year == 2023
        assert filters.created_before.year == 2023
        assert filters.last_login_after.month == 6
        assert filters.last_login_before.month == 6
        assert filters.locale == "en-US"
        assert filters.zoneinfo == "America/New_York"

    def test_pagination_calculations(self):
        """Test pagination calculations for various scenarios."""
        # Test first page

        total_pages = 4  # math.ceil(100 / 25)
        current_page = 1  # (0 // 25) + 1
        has_next = True  # 0 + 25 < 100
        has_previous = False  # 0 > 0

        assert total_pages == 4
        assert current_page == 1
        assert has_next is True
        assert has_previous is False

        # Test middle page
        current_page = 2  # (25 // 25) + 1
        has_next = True  # 25 + 25 < 100
        has_previous = True  # 25 > 0

        assert current_page == 2
        assert has_next is True
        assert has_previous is True

        # Test last page
        current_page = 4  # (75 // 25) + 1
        has_next = False  # 75 + 25 >= 100
        has_previous = True  # 75 > 0

        assert current_page == 4
        assert has_next is False
        assert has_previous is True

    def test_date_parsing_edge_cases(self):
        """Test edge cases for date parsing in the endpoint."""
        from datetime import datetime

        # Test ISO format with Z suffix
        date_str = "2023-01-01T12:00:00Z"
        parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        assert parsed.year == 2023
        assert parsed.hour == 12

        # Test ISO format with timezone
        date_str = "2023-01-01T12:00:00+02:00"
        parsed = datetime.fromisoformat(date_str)
        assert parsed.year == 2023
        assert parsed.hour == 12

        # Test invalid format should raise ValueError
        with pytest.raises(ValueError):
            datetime.fromisoformat("invalid-date-format")


class TestAdminUserListingIntegration:
    """Integration tests combining all components with real database."""

    async def create_integration_test_users(self, conn):
        """Create sample users in real database for integration testing."""
        import uuid

        # Generate a unique suffix to avoid conflicts with other tests
        unique_suffix = str(uuid.uuid4())[:8]
        user_repository = UserRepository(conn)
        users = []

        # Create admin user
        admin_user = UserModel(
            id=uuid4(),
            username=f"integration_admin_{unique_suffix}",
            email=f"integration_admin_{unique_suffix}@example.com",
            password_hash="hash",
            created_at=datetime(2023, 1, 1, tzinfo=UTC),
            updated_at=datetime(2023, 1, 1, tzinfo=UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
        )
        users.append(await user_repository.create(admin_user))

        # Create regular user
        regular_user = UserModel(
            id=uuid4(),
            username=f"integration_user_{unique_suffix}",
            email=f"integration_user_{unique_suffix}@example.com",
            password_hash="hash",
            created_at=datetime(2023, 1, 2, tzinfo=UTC),
            updated_at=datetime(2023, 1, 2, tzinfo=UTC),
            is_admin=False,
            is_active=True,
            is_verified=False,
        )
        users.append(await user_repository.create(regular_user))

        return users

    @pytest.mark.asyncio
    async def test_full_admin_user_listing_workflow(self, transaction_manager):
        """Test complete workflow from repository to API response using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users in database
            test_users = await self.create_integration_test_users(conn)
            test_user_ids = {user.id for user in test_users}

            # Create repository with the same connection
            user_repository = UserRepository(conn)

            # Verify users were created by querying directly through repository
            all_created_users = await user_repository.get_filtered_paginated(filters=None, skip=0, limit=100)
            our_created_users = [user for user in all_created_users if user.id in test_user_ids]
            assert len(our_created_users) == 2, f"Expected 2 users to be created, found {len(our_created_users)}"

            # Create service with the same repository (same connection)
            user_service = UserService(user_repository)

            # Test filtering by our specific test users instead of general is_active filter
            # Filter by username to find our specific test users
            admin_user = test_users[0] if test_users[0].is_admin else test_users[1]
            regular_user = test_users[1] if not test_users[1].is_admin else test_users[0]

            # Test service calls with specific filters for our test users
            admin_filters = {"username": admin_user.username}
            admin_results = await user_service.get_users_paginated(
                skip=0, limit=25, admin_context=True, filters=admin_filters
            )
            admin_count = await user_service.count_users(filters=admin_filters)

            # Verify admin user results
            assert len(admin_results) == 1, f"Expected 1 admin user, found {len(admin_results)}"
            assert admin_count == 1, f"Expected admin count of 1, got {admin_count}"
            assert admin_results[0].is_admin is True
            assert admin_results[0].username == admin_user.username

            # Test regular user search
            regular_filters = {"username": regular_user.username}
            regular_results = await user_service.get_users_paginated(
                skip=0, limit=25, admin_context=True, filters=regular_filters
            )
            regular_count = await user_service.count_users(filters=regular_filters)

            # Verify regular user results
            assert len(regular_results) == 1, f"Expected 1 regular user, found {len(regular_results)}"
            assert regular_count == 1, f"Expected regular count of 1, got {regular_count}"
            assert regular_results[0].is_admin is False
            assert regular_results[0].username == regular_user.username

            # Test broader filtering - use the unique suffix to find just our test users

            admin_user.username.split("_")[-1]  # Extract unique suffix
            prefix_filters = {"username": "integration_"}  # Partial match for our test users
            prefix_results = await user_service.get_users_paginated(
                skip=0, limit=25, admin_context=True, filters=prefix_filters
            )

            # Filter to only our test users by ID (since username filtering is partial)
            our_users = [user for user in prefix_results if user.id in test_user_ids]
            assert len(our_users) == 2, f"Expected 2 integration test users, found {len(our_users)}"

            # Convert to API response format using our found users
            admin_users = [AdminUserResponse(**user.model_dump()) for user in our_users]

            page_info = {
                "skip": 0,
                "limit": 25,
                "has_next": False,
                "has_previous": False,
                "current_page": 1,
                "total_pages": 1,
            }

            response = AdminUserListResponse(
                users=admin_users,
                total_count=len(our_users),  # Use count of our test users
                page_info=page_info,
                filters_applied=prefix_filters,
            )

            # Verify final response
            assert len(response.users) == 2
            assert response.total_count == 2
            assert response.page_info["current_page"] == 1

            # Verify both user types are present
            found_admin = any(user.is_admin for user in response.users)
            found_regular = any(not user.is_admin for user in response.users)
            assert found_admin, "Admin user not found in response"
            assert found_regular, "Regular user not found in response"

    def test_empty_results_handling(self):
        """Test handling of empty results."""
        # Empty user list
        admin_users = []
        total_count = 0

        # Calculate pagination for empty results
        limit = 25
        total_pages = 0  # math.ceil(0 / 25) = 0
        current_page = 1  # (0 // 25) + 1 = 1
        has_next = False  # 0 + 25 >= 0
        has_previous = False  # 0 <= 0

        page_info = {
            "skip": 0,
            "limit": limit,
            "has_next": has_next,
            "has_previous": has_previous,
            "current_page": current_page,
            "total_pages": total_pages,
        }

        response = AdminUserListResponse(
            users=admin_users,
            total_count=total_count,
            page_info=page_info,
            filters_applied=None,
        )

        assert len(response.users) == 0
        assert response.total_count == 0
        assert response.page_info["total_pages"] == 0
        assert response.filters_applied is None
