"""
Tests for query optimization improvements.

This module tests the optimized CTE-based queries and ensures they provide
the same results as the legacy queries while offering better performance.
"""

import logging
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.auth.core import get_password_hash
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class TestQueryOptimization:
    """Test query optimization features."""

    @pytest.fixture
    async def sample_users(self, transaction_manager: TransactionManager):
        """Create sample users for testing."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            users = []

            # Create 10 test users with varying attributes
            for i in range(10):
                user = UserModel(
                    id=uuid4(),
                    username=f"testuser_{i:03d}_{uuid4().hex[:8]}",
                    email=f"testuser_{i:03d}_{uuid4().hex[:8]}@example.com",
                    password_hash=get_password_hash("TestPassword123!"),
                    given_name=f"Test{i:03d}",
                    family_name=f"User{i % 3}",  # Some shared family names
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    is_active=i % 8 != 0,  # Make every 8th user inactive
                    is_verified=i % 6 != 0,  # Make every 6th user unverified
                    is_admin=i == 0,  # Make first user admin
                    locale="en-US" if i % 2 == 0 else "fr-FR",
                    zoneinfo="America/New_York" if i % 3 == 0 else "Europe/Paris",
                )
                created_user = await user_repo.create(user)
                users.append(created_user)

            return users

    @pytest.fixture
    async def sample_tokens(self, transaction_manager: TransactionManager, sample_users):
        """Create sample tokens for testing session counts."""
        async with transaction_manager.transaction() as conn:
            token_repo = TokenRepository(conn)
            tokens = []

            # Create varying numbers of tokens per user
            for i, user in enumerate(sample_users[:5]):  # Only for first 5 users
                num_tokens = (i % 3) + 1  # 1-3 tokens per user

                for j in range(num_tokens):
                    # Create access token
                    access_token = TokenModel(
                        id=uuid4(),
                        user_id=user.id,
                        token_jti=f"jti_access_{user.id}_{j}",
                        token_value=f"access_token_{uuid4().hex}",
                        token_type=TokenType.ACCESS,
                        expires_at=datetime.now(UTC).replace(year=2030),  # Far future
                        created_at=datetime.now(UTC),
                        invalidated=False,
                        scope="openid profile",
                    )
                    await token_repo.store_token(access_token)
                    tokens.append(access_token)

                    # Create refresh token
                    refresh_token = TokenModel(
                        id=uuid4(),
                        user_id=user.id,
                        token_jti=f"jti_refresh_{user.id}_{j}",
                        token_value=f"refresh_token_{uuid4().hex}",
                        token_type=TokenType.REFRESH,
                        expires_at=datetime.now(UTC).replace(year=2030),  # Far future
                        created_at=datetime.now(UTC),
                        invalidated=False,
                        scope="openid profile",
                    )
                    await token_repo.store_token(refresh_token)
                    tokens.append(refresh_token)

            return tokens

    @pytest.mark.asyncio
    async def test_optimized_admin_listing_basic(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test basic optimized admin listing functionality."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Test basic listing
            users_data, total_count, active_count = await user_repo.get_optimized_admin_listing(
                filters={}, skip=0, limit=25
            )

            # Verify we got results
            assert len(users_data) > 0
            assert total_count >= len(users_data)
            assert active_count <= total_count

            # Verify each user has session count
            for user_data in users_data:
                assert "active_sessions" in user_data
                assert isinstance(user_data["active_sessions"], int)
                assert user_data["active_sessions"] >= 0

    @pytest.mark.asyncio
    async def test_optimized_admin_listing_vs_legacy(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test that optimized listing returns same data as legacy methods."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Get results from optimized method
            optimized_users, optimized_total, _ = await user_repo.get_optimized_admin_listing(
                filters={}, skip=0, limit=5
            )

            # Get results from legacy methods
            legacy_users = await user_repo.get_filtered_paginated(filters={}, skip=0, limit=5)
            legacy_total = await user_repo.count_filtered(filters={})

            # Compare counts
            assert len(optimized_users) == len(legacy_users)
            assert optimized_total == legacy_total

            # Compare user data (excluding session counts)
            optimized_ids = {user_data["id"] for user_data in optimized_users}
            legacy_ids = {user.id for user in legacy_users}
            assert optimized_ids == legacy_ids

    @pytest.mark.asyncio
    async def test_optimized_admin_listing_with_filters(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test optimized listing with various filters."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Test active user filter
            active_users, active_total, active_count = await user_repo.get_optimized_admin_listing(
                filters={"is_active": True}, skip=0, limit=25
            )

            # Verify all returned users are active
            for user_data in active_users:
                assert user_data["is_active"] is True

            assert active_count == active_total  # All filtered users should be active

            # Test admin filter
            admin_users, admin_total, _ = await user_repo.get_optimized_admin_listing(
                filters={"is_admin": True}, skip=0, limit=25
            )

            # Should have at least one admin (from fixture)
            assert admin_total >= 1
            for user_data in admin_users:
                assert user_data["is_admin"] is True

    @pytest.mark.asyncio
    async def test_optimized_admin_listing_text_search(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test optimized listing with text search filters."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Test username search
            username_results, username_total, _ = await user_repo.get_optimized_admin_listing(
                filters={"username": "testuser_"}, skip=0, limit=25
            )

            # Should find users with matching usernames
            assert username_total > 0
            for user_data in username_results:
                assert "testuser_" in user_data["username"].lower()

            # Test family name search
            family_results, family_total, _ = await user_repo.get_optimized_admin_listing(
                filters={"family_name": "User0"}, skip=0, limit=25
            )

            # Should find users with matching family names
            for user_data in family_results:
                assert "User0" in user_data.get("family_name", "")

    @pytest.mark.asyncio
    async def test_optimized_admin_listing_pagination(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test pagination in optimized listing."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Get first page
            page1_users, total_count, _ = await user_repo.get_optimized_admin_listing(filters={}, skip=0, limit=3)

            # Get second page
            page2_users, total_count2, _ = await user_repo.get_optimized_admin_listing(filters={}, skip=3, limit=3)

            # Verify pagination
            assert len(page1_users) <= 3
            assert len(page2_users) <= 3
            assert total_count == total_count2  # Total should be consistent

            # Verify no overlap between pages
            page1_ids = {user_data["id"] for user_data in page1_users}
            page2_ids = {user_data["id"] for user_data in page2_users}
            assert page1_ids.isdisjoint(page2_ids)

    @pytest.mark.asyncio
    async def test_user_with_session_count(self, transaction_manager: TransactionManager, sample_users, sample_tokens):
        """Test getting single user with session count."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            token_repo = TokenRepository(conn)

            # Get a user with tokens
            test_user = sample_users[0]  # First user should have tokens

            # Get user with session count
            user_data = await user_repo.get_user_with_session_count(test_user.id)

            assert user_data is not None
            assert user_data["id"] == test_user.id
            assert "active_sessions" in user_data

            # Verify session count is accurate
            expected_sessions = await token_repo.count_active_sessions(test_user.id)
            assert user_data["active_sessions"] == expected_sessions

    @pytest.mark.asyncio
    async def test_session_count_accuracy(self, transaction_manager: TransactionManager, sample_users, sample_tokens):
        """Test that session counts in listings are accurate."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)
            token_repo = TokenRepository(conn)

            # Get optimized listing
            users_data, _, _ = await user_repo.get_optimized_admin_listing(filters={}, skip=0, limit=25)

            # Verify session counts for each user
            for user_data in users_data:
                user_id = user_data["id"]
                listed_sessions = user_data["active_sessions"]

                # Get actual session count
                actual_sessions = await token_repo.count_active_sessions(user_id)

                assert listed_sessions == actual_sessions, (
                    f"Session count mismatch for user {user_id}: listed={listed_sessions}, actual={actual_sessions}"
                )

    @pytest.mark.asyncio
    async def test_empty_results_handling(self, transaction_manager: TransactionManager):
        """Test handling of empty results in optimized queries."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Test with filters that should return no results
            users_data, total_count, active_count = await user_repo.get_optimized_admin_listing(
                filters={"username": "nonexistent_user_12345"}, skip=0, limit=25
            )

            assert users_data == []
            assert total_count == 0
            assert active_count == 0

    @pytest.mark.asyncio
    async def test_complex_filter_combinations(
        self, transaction_manager: TransactionManager, sample_users, sample_tokens
    ):
        """Test complex filter combinations in optimized queries."""
        async with transaction_manager.transaction() as conn:
            user_repo = UserRepository(conn)

            # Test multiple filters
            complex_filters = {"is_active": True, "locale": "en-US", "username": "testuser_"}

            users_data, total_count, active_count = await user_repo.get_optimized_admin_listing(
                filters=complex_filters, skip=0, limit=25
            )

            # Verify all conditions are met
            for user_data in users_data:
                assert user_data["is_active"] is True
                assert user_data["locale"] == "en-US"
                assert "testuser_" in user_data["username"]

            # Active count should equal total count since we filtered for active users
            assert active_count == total_count
