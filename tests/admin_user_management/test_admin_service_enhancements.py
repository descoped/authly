"""
Tests for Admin Service Layer Enhancements.

This module tests the enhanced UserService functionality that supports
admin operations, field filtering, and admin-specific features.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import HTTPException

from authly.admin.models import AdminUserFilters
from authly.users.models import UserModel
from authly.users.repository import UserRepository
from authly.users.service import ADMIN_ONLY_FIELDS, UserService


class TestUserServiceAdminEnhancements:
    """Test admin enhancements to UserService with real database integration."""

    async def create_test_admin_user(self, conn, username=None, email=None):
        """Create test admin user in database with unique identifiers."""
        import uuid

        unique_suffix = str(uuid.uuid4())[:8]

        if username is None:
            username = f"admin_user_{unique_suffix}"
        if email is None:
            email = f"admin_{unique_suffix}@example.com"

        user_repository = UserRepository(conn)
        admin_user = UserModel(
            id=uuid4(),
            username=username,
            email=email,
            password_hash="hashed_password",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
        )
        return await user_repository.create(admin_user)

    async def create_test_regular_user(self, conn, username=None, email=None):
        """Create test regular user in database with unique identifiers."""
        import uuid

        unique_suffix = str(uuid.uuid4())[:8]

        if username is None:
            username = f"regular_user_{unique_suffix}"
        if email is None:
            email = f"user_{unique_suffix}@example.com"

        user_repository = UserRepository(conn)
        regular_user = UserModel(
            id=uuid4(),
            username=username,
            email=email,
            password_hash="hashed_password",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=False,
            is_active=True,
            is_verified=False,
        )
        return await user_repository.create(regular_user)

    def test_admin_only_fields_constant(self):
        """Test that ADMIN_ONLY_FIELDS contains expected fields."""
        expected_fields = {
            "password_hash",
            "is_admin",
            "is_active",
            "is_verified",
            "requires_password_change",
            "last_login",
            "created_at",
            "updated_at",
        }
        assert expected_fields == ADMIN_ONLY_FIELDS

    @pytest.mark.asyncio
    async def test_filter_user_fields_regular_context(self, transaction_manager):
        """Test field filtering in regular context."""
        async with transaction_manager.transaction() as conn:
            regular_user = await self.create_test_regular_user(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            filtered_data = user_service._filter_user_fields(regular_user, is_admin_context=False)

            # Admin-only fields should be removed
            for field in ADMIN_ONLY_FIELDS:
                assert field not in filtered_data

            # Regular fields should be present
            assert "id" in filtered_data
            assert "username" in filtered_data
            assert "email" in filtered_data
            assert "given_name" in filtered_data

    @pytest.mark.asyncio
    async def test_filter_user_fields_admin_context_without_admin_fields(self, transaction_manager):
        """Test field filtering in admin context but without admin fields."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            filtered_data = user_service._filter_user_fields(
                admin_user, is_admin_context=True, include_admin_fields=False
            )

            # Admin-only fields should still be removed
            for field in ADMIN_ONLY_FIELDS:
                assert field not in filtered_data

    @pytest.mark.asyncio
    async def test_filter_user_fields_admin_context_with_admin_fields(self, transaction_manager):
        """Test field filtering in admin context with admin fields included."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            filtered_data = user_service._filter_user_fields(
                admin_user, is_admin_context=True, include_admin_fields=True
            )

            # All fields should be present
            for field in ADMIN_ONLY_FIELDS:
                assert field in filtered_data
            assert "id" in filtered_data
            assert "username" in filtered_data

    @pytest.mark.asyncio
    async def test_update_user_with_admin_context(self, transaction_manager):
        """Test updating user with admin context using real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            admin_user = await self.create_test_admin_user(conn)
            regular_user = await self.create_test_regular_user(conn)

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            update_data = {
                "username": "new_username",
                "is_admin": True,  # Admin-only field
            }

            # Should succeed with admin context
            result = await user_service.update_user(
                user_id=regular_user.id,
                update_data=update_data,
                requesting_user=admin_user,
                admin_override=True,
                admin_context=True,
            )

            # Verify the user was updated
            assert result is not None
            assert result.username == "new_username"
            assert result.is_admin is True

    @pytest.mark.asyncio
    async def test_update_user_admin_fields_without_admin_context(self, transaction_manager):
        """Test updating admin fields without admin context fails."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)
            regular_user = await self.create_test_regular_user(conn)

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            update_data = {
                "is_admin": True,  # Admin-only field
            }

            # Should fail without admin context
            with pytest.raises(HTTPException) as exc_info:
                await user_service.update_user(
                    user_id=regular_user.id,
                    update_data=update_data,
                    requesting_user=admin_user,
                    admin_override=True,
                    admin_context=False,  # No admin context
                )

            assert exc_info.value.status_code == 403
            assert "Admin privileges required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_update_user_admin_fields_non_admin_user(self, transaction_manager):
        """Test non-admin user cannot update admin fields even with admin context."""
        async with transaction_manager.transaction() as conn:
            await self.create_test_admin_user(conn)
            regular_user = await self.create_test_regular_user(conn)

            # Create another user to be target of update
            import uuid

            unique_suffix = str(uuid.uuid4())[:8]
            user_repository = UserRepository(conn)
            another_user = UserModel(
                id=uuid4(),
                username=f"another_user_{unique_suffix}",
                email=f"another_{unique_suffix}@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=False,
                is_active=True,
                is_verified=True,
            )
            another_user = await user_repository.create(another_user)

            user_service = UserService(user_repository)

            update_data = {
                "is_admin": True,  # Admin-only field
            }

            # Should fail because requesting user is not admin
            with pytest.raises(HTTPException) as exc_info:
                await user_service.update_user(
                    user_id=another_user.id,
                    update_data=update_data,
                    requesting_user=regular_user,  # Not admin
                    admin_override=True,
                    admin_context=True,
                )

            assert exc_info.value.status_code == 403
            assert "Admin privileges required" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_delete_user_with_admin_override(self, transaction_manager):
        """Test admin can delete any user with admin override."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)
            regular_user = await self.create_test_regular_user(conn)

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            await user_service.delete_user(user_id=regular_user.id, requesting_user=admin_user, admin_override=True)

            # Verify user was deleted
            with pytest.raises(HTTPException) as exc_info:
                await user_service.get_user_by_id(regular_user.id)
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_user_non_admin_permission_denied(self, transaction_manager):
        """Test permission denied when non-admin tries to delete other user."""
        async with transaction_manager.transaction() as conn:
            regular_user = await self.create_test_regular_user(conn)

            # Create another user
            import uuid

            unique_suffix = str(uuid.uuid4())[:8]
            user_repository = UserRepository(conn)
            another_user = UserModel(
                id=uuid4(),
                username=f"another_user_{unique_suffix}",
                email=f"another_{unique_suffix}@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=False,
                is_active=True,
                is_verified=True,
            )
            another_user = await user_repository.create(another_user)

            user_service = UserService(user_repository)

            with pytest.raises(HTTPException) as exc_info:
                await user_service.delete_user(
                    user_id=another_user.id,
                    requesting_user=regular_user,  # Non-admin user
                    admin_override=False,
                )

            assert exc_info.value.status_code == 403
            assert "Not authorized to delete this user" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_user_by_id_with_admin_context(self, transaction_manager):
        """Test getting user by ID with admin context."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            result = await user_service.get_user_by_id(user_id=admin_user.id, admin_context=True)

            assert result.id == admin_user.id
            assert result.username == admin_user.username
            assert result.is_admin is True

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, transaction_manager):
        """Test getting non-existent user raises proper exception."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            non_existent_id = uuid4()
            with pytest.raises(HTTPException) as exc_info:
                await user_service.get_user_by_id(non_existent_id)

            assert exc_info.value.status_code == 404
            assert "User not found" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_users_paginated_with_admin_context(self, transaction_manager):
        """Test getting paginated users with admin context and filters."""
        async with transaction_manager.transaction() as conn:
            admin_user = await self.create_test_admin_user(conn)
            regular_user = await self.create_test_regular_user(conn)

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)
            test_user_ids = {admin_user.id, regular_user.id}

            filters = {"is_admin": True}
            all_results = await user_service.get_users_paginated(skip=0, limit=10, admin_context=True, filters=filters)

            # Filter to only our test users
            our_results = [user for user in all_results if user.id in test_user_ids]

            # Should find only the admin user
            assert len(our_results) == 1
            assert our_results[0].id == admin_user.id
            assert our_results[0].is_admin is True

    @pytest.mark.asyncio
    async def test_get_users_paginated_database_error(self, transaction_manager):
        """Test database error handling in get_users_paginated."""
        async with transaction_manager.transaction() as conn:
            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            # Test with invalid parameters that could cause issues
            try:
                # Using very large skip might cause issues
                await user_service.get_users_paginated(skip=999999, limit=1)
                # If no exception, the service handled it gracefully
            except HTTPException as e:
                # If exception occurs, verify it's properly handled
                assert e.status_code in [400, 500]
                assert "Failed to retrieve users" in str(e.detail) or "error" in str(e.detail).lower()

    def test_update_user_regular_fields_allowed(self):
        """Test that regular users can update non-admin fields."""
        update_data = {"given_name": "John", "family_name": "Doe", "email": "newemail@example.com"}

        # Check that no admin fields are in the update
        admin_fields_in_update = set(update_data.keys()) & ADMIN_ONLY_FIELDS
        assert len(admin_fields_in_update) == 0

    def test_update_user_identifies_admin_fields(self):
        """Test that admin-only fields are properly identified."""
        update_data = {
            "username": "newname",
            "is_admin": True,  # Admin-only
            "is_active": False,  # Admin-only
            "given_name": "John",  # Regular field
        }

        admin_fields_in_update = set(update_data.keys()) & ADMIN_ONLY_FIELDS
        expected_admin_fields = {"is_admin", "is_active"}

        assert admin_fields_in_update == expected_admin_fields


class TestAdminUserFiltersModel:
    """Test AdminUserFilters model."""

    def test_admin_user_filters_creation(self):
        """Test creating AdminUserFilters with various filter options."""
        filters = AdminUserFilters(
            username="john",
            email="@example.com",
            is_active=True,
            is_admin=False,
            created_after=datetime(2023, 1, 1, tzinfo=UTC),
            locale="en-US",
        )

        assert filters.username == "john"
        assert filters.email == "@example.com"
        assert filters.is_active is True
        assert filters.is_admin is False
        assert filters.created_after.year == 2023
        assert filters.locale == "en-US"

    def test_admin_user_filters_all_none(self):
        """Test creating AdminUserFilters with all None values."""
        filters = AdminUserFilters()

        assert filters.username is None
        assert filters.email is None
        assert filters.is_active is None
        assert filters.is_admin is None
        assert filters.created_after is None
        assert filters.locale is None

    def test_admin_user_filters_model_dump(self):
        """Test model dump functionality."""
        filters = AdminUserFilters(username="testuser", is_active=True, is_verified=False)

        dumped = filters.model_dump(exclude_none=True)

        assert "username" in dumped
        assert "is_active" in dumped
        assert "is_verified" in dumped
        assert "email" not in dumped  # Should be excluded because it's None


class TestServiceLayerIntegration:
    """Integration tests for service layer enhancements with real database."""

    async def create_service_test_users(self, conn):
        """Create test users for service integration testing."""
        import uuid

        unique_suffix = str(uuid.uuid4())[:8]

        user_repository = UserRepository(conn)
        users = []

        # Create admin user
        admin_user = UserModel(
            id=uuid4(),
            username=f"service_admin_{unique_suffix}",
            email=f"service_admin_{unique_suffix}@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=True,
            is_active=True,
            is_verified=True,
        )
        users.append(await user_repository.create(admin_user))

        # Create regular user
        regular_user = UserModel(
            id=uuid4(),
            username=f"service_regular_{unique_suffix}",
            email=f"service_regular_{unique_suffix}@example.com",
            password_hash="hashed_password",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_admin=False,
            is_active=True,
            is_verified=False,
        )
        users.append(await user_repository.create(regular_user))

        return users

    @pytest.mark.asyncio
    async def test_admin_workflow_create_update_delete(self, transaction_manager):
        """Test complete admin workflow: create, update, delete user with real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            service_users = await self.create_service_test_users(conn)
            admin_user = service_users[0]  # First user is admin

            user_repository = UserRepository(conn)
            user_service = UserService(user_repository)

            # 1. Create user
            import uuid

            unique_suffix = str(uuid.uuid4())[:8]
            new_user = await user_service.create_user(
                username=f"testuser_{unique_suffix}",
                email=f"test_{unique_suffix}@example.com",
                password="SecurePass123!",
                is_admin=False,
                is_verified=False,
                is_active=True,
            )

            assert f"testuser_{unique_suffix}" in new_user.username
            assert new_user.is_admin is False
            assert new_user.is_verified is False

            # 2. Update user with admin privileges
            update_data = {
                "is_verified": True,  # Admin-only field
                "given_name": "Test",
            }

            updated_user = await user_service.update_user(
                user_id=new_user.id,
                update_data=update_data,
                requesting_user=admin_user,
                admin_override=True,
                admin_context=True,
            )

            assert updated_user.is_verified is True
            assert updated_user.given_name == "Test"

            # 3. Delete user
            await user_service.delete_user(user_id=new_user.id, requesting_user=admin_user, admin_override=True)

            # Verify user was deleted
            with pytest.raises(HTTPException) as exc_info:
                await user_service.get_user_by_id(new_user.id)
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_permission_boundaries(self, transaction_manager):
        """Test that permission boundaries are enforced correctly with real database."""
        async with transaction_manager.transaction() as conn:
            # Create test users
            service_users = await self.create_service_test_users(conn)
            admin_user = service_users[0]  # First user is admin
            regular_user = service_users[1]  # Second user is regular

            # Create another target user
            import uuid

            unique_suffix = str(uuid.uuid4())[:8]
            user_repository = UserRepository(conn)
            target_user = UserModel(
                id=uuid4(),
                username=f"target_{unique_suffix}",
                email=f"target_{unique_suffix}@example.com",
                password_hash="hash",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                is_admin=False,
                is_active=True,
                is_verified=True,
            )
            target_user = await user_repository.create(target_user)

            user_service = UserService(user_repository)

            # Regular user should not be able to update admin fields
            with pytest.raises(HTTPException) as exc_info:
                await user_service.update_user(
                    user_id=target_user.id,
                    update_data={"is_admin": True},
                    requesting_user=regular_user,
                    admin_override=False,
                    admin_context=True,  # Even with admin context
                )

            assert exc_info.value.status_code == 403

            # Regular user should not be able to delete other users
            with pytest.raises(HTTPException) as exc_info:
                await user_service.delete_user(
                    user_id=target_user.id, requesting_user=regular_user, admin_override=False
                )

            assert exc_info.value.status_code == 403

            # But admin should be able to do both
            updated_user = await user_service.update_user(
                user_id=target_user.id,
                update_data={"is_admin": True},
                requesting_user=admin_user,
                admin_override=True,
                admin_context=True,
            )
            assert updated_user.is_admin is True

            # Admin can delete user
            await user_service.delete_user(user_id=target_user.id, requesting_user=admin_user, admin_override=True)
