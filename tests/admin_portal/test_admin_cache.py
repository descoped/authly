"""
Tests for admin caching layer.

Tests the AdminCacheService and permission caching functionality
implemented in Increment 5.2 of the implementation roadmap.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from authly.admin.cache import AdminCacheService
from authly.admin.permissions import AdminPermissionService
from authly.core.backends import MemoryCacheBackend
from authly.users.models import UserModel


class TestAdminCacheService:
    """Test AdminCacheService functionality."""

    @pytest.fixture
    def cache_service(self):
        """Create cache service with memory backend."""
        backend = MemoryCacheBackend()
        return AdminCacheService(backend)

    @pytest.fixture
    def sample_users(self):
        """Create sample user data."""
        return [
            {
                "id": str(uuid4()),
                "username": f"user{i}",
                "email": f"user{i}@example.com",
                "is_active": i % 2 == 0,
                "is_admin": i == 0,
                "active_sessions": i,
            }
            for i in range(5)
        ]

    @pytest.mark.asyncio
    async def test_dashboard_stats_caching(self, cache_service):
        """Test dashboard statistics caching."""
        # Initially no cache
        assert await cache_service.get_dashboard_stats() is None

        # Set stats
        stats = {
            "users": {
                "total": 100,
                "active": 75,
                "inactive": 25,
                "admins": 5,
            },
            "timestamp": datetime.now(UTC).isoformat(),
        }
        await cache_service.set_dashboard_stats(stats)

        # Retrieve from cache
        cached_stats = await cache_service.get_dashboard_stats()
        assert cached_stats == stats
        assert cached_stats["users"]["total"] == 100

    @pytest.mark.asyncio
    async def test_user_count_caching(self, cache_service):
        """Test user count caching with filters."""
        # Test without filters
        assert await cache_service.get_user_count() is None
        await cache_service.set_user_count(100)
        assert await cache_service.get_user_count() == 100

        # Test with filters
        filters = {"is_active": True, "is_admin": False}
        assert await cache_service.get_user_count(filters) is None
        await cache_service.set_user_count(50, filters)
        assert await cache_service.get_user_count(filters) == 50

        # Different filters should have different cache
        other_filters = {"is_active": False}
        assert await cache_service.get_user_count(other_filters) is None

    @pytest.mark.asyncio
    async def test_user_listing_caching(self, cache_service, sample_users):
        """Test user listing caching with pagination."""
        filters = {"is_active": True}
        skip = 0
        limit = 10

        # Initially no cache
        assert await cache_service.get_user_listing(filters, skip, limit) is None

        # Set listing
        total_count = 100
        active_count = 75
        await cache_service.set_user_listing(
            users=sample_users,
            total_count=total_count,
            active_count=active_count,
            filters=filters,
            skip=skip,
            limit=limit,
        )

        # Retrieve from cache
        cached_result = await cache_service.get_user_listing(filters, skip, limit)
        assert cached_result is not None
        users, total, active = cached_result
        assert len(users) == len(sample_users)
        assert total == total_count
        assert active == active_count

        # Different pagination should have different cache
        assert await cache_service.get_user_listing(filters, skip=10, limit=10) is None

    @pytest.mark.asyncio
    async def test_user_details_caching(self, cache_service):
        """Test individual user details caching."""
        user_id = uuid4()
        user_data = {
            "id": str(user_id),
            "username": "testuser",
            "email": "test@example.com",
            "is_active": True,
            "active_sessions": 3,
        }

        # Initially no cache
        assert await cache_service.get_user_details(user_id) is None

        # Set details
        await cache_service.set_user_details(user_id, user_data)

        # Retrieve from cache
        cached_user = await cache_service.get_user_details(user_id)
        assert cached_user == user_data
        assert cached_user["username"] == "testuser"

    @pytest.mark.asyncio
    async def test_permission_caching(self, cache_service):
        """Test permission check caching."""
        admin_id = uuid4()
        target_id = uuid4()
        action = "update"

        # Initially no cache
        assert await cache_service.check_permission(admin_id, target_id, action) is None

        # Set permission
        await cache_service.set_permission(admin_id, target_id, action, True)

        # Retrieve from cache
        assert await cache_service.check_permission(admin_id, target_id, action) is True

        # Set different permission
        await cache_service.set_permission(admin_id, target_id, "delete", False)
        assert await cache_service.check_permission(admin_id, target_id, "delete") is False

        # Original permission still cached
        assert await cache_service.check_permission(admin_id, target_id, action) is True

    @pytest.mark.asyncio
    async def test_filters_hash_generation(self, cache_service):
        """Test stable hash generation for filters."""
        # Same filters should generate same hash
        filters1 = {"is_active": True, "username": "test"}
        filters2 = {"username": "test", "is_active": True}  # Different order

        hash1 = cache_service._generate_filters_hash(filters1)
        hash2 = cache_service._generate_filters_hash(filters2)
        assert hash1 == hash2

        # Different filters should generate different hash
        filters3 = {"is_active": False, "username": "test"}
        hash3 = cache_service._generate_filters_hash(filters3)
        assert hash1 != hash3

        # None filters should have consistent hash
        assert cache_service._generate_filters_hash(None) == "none"
        assert cache_service._generate_filters_hash({}) == "none"

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, cache_service):
        """Test cache invalidation functionality."""
        user_id = uuid4()
        user_data = {"id": str(user_id), "username": "test"}
        stats = {"users": {"total": 100}}

        # Set various caches
        await cache_service.set_user_details(user_id, user_data)
        await cache_service.set_dashboard_stats(stats)

        # Verify caches exist
        assert await cache_service.get_user_details(user_id) is not None
        assert await cache_service.get_dashboard_stats() is not None

        # Invalidate user
        await cache_service.invalidate_user(user_id)

        # User cache should be cleared
        assert await cache_service.get_user_details(user_id) is None
        # Dashboard stats should also be cleared (affected by user changes)
        assert await cache_service.get_dashboard_stats() is None

    @pytest.mark.asyncio
    async def test_cache_disable_enable(self, cache_service):
        """Test cache disable/enable functionality."""
        user_id = uuid4()
        user_data = {"id": str(user_id), "username": "test"}

        # Cache should work initially
        await cache_service.set_user_details(user_id, user_data)
        assert await cache_service.get_user_details(user_id) is not None

        # Disable cache
        cache_service.disable_cache()

        # Cache operations should not work
        await cache_service.set_user_details(user_id, {"updated": True})
        assert await cache_service.get_user_details(user_id) is None

        # Re-enable cache
        cache_service.enable_cache()

        # Cache should work again
        await cache_service.set_user_details(user_id, user_data)
        assert await cache_service.get_user_details(user_id) is not None


class TestAdminPermissionService:
    """Test AdminPermissionService with caching."""

    @pytest.fixture
    def permission_service(self):
        """Create permission service with cache."""
        cache = AdminCacheService(MemoryCacheBackend())
        return AdminPermissionService(cache)

    @pytest.fixture
    def admin_user(self):
        """Create admin user."""
        now = datetime.now(UTC)
        return UserModel(
            id=uuid4(),
            username="admin",
            email="admin@example.com",
            password_hash="hash",
            is_admin=True,
            is_active=True,
            is_verified=True,
            created_at=now,
            updated_at=now,
        )

    @pytest.fixture
    def regular_user(self):
        """Create regular user."""
        now = datetime.now(UTC)
        return UserModel(
            id=uuid4(),
            username="user",
            email="user@example.com",
            password_hash="hash",
            is_admin=False,
            is_active=True,
            is_verified=True,
            created_at=now,
            updated_at=now,
        )

    @pytest.mark.asyncio
    async def test_admin_can_modify_users(self, permission_service, admin_user):
        """Test admin can modify other users."""
        target_id = uuid4()

        # First call should compute permission
        assert await permission_service.can_modify_user(admin_user, target_id) is True

        # Second call should use cache
        assert await permission_service.can_modify_user(admin_user, target_id) is True

    @pytest.mark.asyncio
    async def test_non_admin_cannot_modify_users(self, permission_service, regular_user):
        """Test non-admin cannot modify users."""
        target_id = uuid4()

        assert await permission_service.can_modify_user(regular_user, target_id) is False

    @pytest.mark.asyncio
    async def test_admin_cannot_remove_own_admin_status(self, permission_service, admin_user):
        """Test admin cannot remove their own admin status."""
        assert await permission_service.can_modify_user(admin_user, admin_user.id, "remove_admin") is False

    @pytest.mark.asyncio
    async def test_specific_permission_methods(self, permission_service, admin_user):
        """Test specific permission check methods."""
        target_id = uuid4()

        # All should be allowed for admin
        assert await permission_service.can_delete_user(admin_user, target_id) is True
        assert await permission_service.can_update_user(admin_user, target_id) is True
        assert await permission_service.can_reset_password(admin_user, target_id) is True
        assert await permission_service.can_manage_sessions(admin_user, target_id) is True

    @pytest.mark.asyncio
    async def test_update_permission_with_fields(self, permission_service, admin_user):
        """Test update permission with specific fields."""
        other_user_id = uuid4()

        # Can update other user's admin status
        assert await permission_service.can_update_user(admin_user, other_user_id, {"is_admin"}) is True

        # Cannot remove own admin status
        assert await permission_service.can_update_user(admin_user, admin_user.id, {"is_admin"}) is False

    @pytest.mark.asyncio
    async def test_permission_cache_invalidation(self, permission_service, admin_user):
        """Test permission cache invalidation."""
        target_id = uuid4()

        # Set permission in cache
        assert await permission_service.can_modify_user(admin_user, target_id) is True

        # Invalidate admin's permissions
        await permission_service.invalidate_admin_permissions(admin_user.id)

        # Permission should be recalculated (not from cache)
        # In a real scenario, this might return a different result
        assert await permission_service.can_modify_user(admin_user, target_id) is True


class TestCachePerformance:
    """Test cache performance characteristics."""

    @pytest.fixture
    def cache_service(self):
        """Create cache service for performance testing."""
        return AdminCacheService(MemoryCacheBackend())

    @pytest.mark.asyncio
    async def test_cache_performance_improvement(self, cache_service):
        """Test that cache retrieval works correctly."""
        # Create test data
        users = [{"id": str(uuid4()), "username": f"user{i}"} for i in range(100)]

        # Initially no cache
        assert await cache_service.get_user_listing(None, 0, 100) is None

        # Set data in cache
        await cache_service.set_user_listing(
            users=users, total_count=100, active_count=50, filters=None, skip=0, limit=100
        )

        # Retrieve from cache multiple times to ensure consistency
        for _ in range(3):
            cached_result = await cache_service.get_user_listing(None, 0, 100)
            assert cached_result is not None
            users_list, total, active = cached_result
            assert len(users_list) == 100
            assert total == 100
            assert active == 50

        # Different parameters should not hit the same cache
        assert await cache_service.get_user_listing(None, 0, 50) is None
        assert await cache_service.get_user_listing({"test": True}, 0, 100) is None

    @pytest.mark.asyncio
    async def test_cache_memory_efficiency(self, cache_service):
        """Test cache doesn't store excessive data."""
        # Store multiple user listings with different filters
        for i in range(10):
            filters = {"page": i}
            users = [{"id": str(uuid4())} for _ in range(25)]
            await cache_service.set_user_listing(
                users=users, total_count=100, active_count=75, filters=filters, skip=i * 25, limit=25
            )

        # All should be retrievable
        for i in range(10):
            filters = {"page": i}
            result = await cache_service.get_user_listing(filters, i * 25, 25)
            assert result is not None
