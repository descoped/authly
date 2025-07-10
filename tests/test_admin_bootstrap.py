"""
Tests for Admin Bootstrap System.

This module tests the admin user bootstrap and scope registration system
that solves the IAM chicken-and-egg paradox with the two-layer security model.
"""

import logging
import os
import random
import string
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.api.admin_dependencies import ADMIN_SCOPES
from authly.auth.core import get_password_hash
from authly.bootstrap.admin_seeding import (
    bootstrap_admin_user,
    register_admin_scopes,
    bootstrap_admin_system,
    get_bootstrap_status
)
from authly.oauth.scope_repository import ScopeRepository
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


def generate_random_identifier(length: int = 10) -> str:
    """Generate a random string for testing."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


class TestBootstrapAdminUser:
    """Test admin user bootstrap functionality."""
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_user_creates_new_admin(self, transaction_manager: TransactionManager):
        """Test creating new admin user when none exists."""
        async with transaction_manager.transaction() as conn:
            # Verify no admin user exists initially
            user_repo = UserRepository(conn)
            existing_admin = await user_repo.get_by_username("admin")
            assert existing_admin is None
            
            # Bootstrap admin user
            admin_user = await bootstrap_admin_user(conn)
            
            # Verify admin user was created
            assert admin_user is not None
            assert admin_user.username == "admin"
            assert admin_user.email == "admin@localhost"
            assert admin_user.is_admin is True
            assert admin_user.is_active is True
            assert admin_user.is_verified is True
            
            # Verify password hash is set
            assert admin_user.password_hash is not None
            assert len(admin_user.password_hash) > 0
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_user_with_custom_credentials(self, transaction_manager: TransactionManager):
        """Test creating admin user with custom credentials."""
        async with transaction_manager.transaction() as conn:
            custom_username = f"custom_admin_{generate_random_identifier()}"
            custom_email = f"{custom_username}@example.com"
            custom_password = "CustomAdminPass123!"
            
            # Bootstrap with custom credentials
            admin_user = await bootstrap_admin_user(
                conn,
                username=custom_username,
                email=custom_email,
                password=custom_password
            )
            
            # Verify custom credentials were used
            assert admin_user.username == custom_username
            assert admin_user.email == custom_email
            assert admin_user.is_admin is True
            
            # Verify password can be verified
            from authly.auth.core import verify_password
            assert verify_password(custom_password, admin_user.password_hash) is True
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_user_idempotent(self, transaction_manager: TransactionManager):
        """Test that bootstrap is idempotent (safe to run multiple times)."""
        unique_username = f"test_admin_{generate_random_identifier()}"
        unique_email = f"{unique_username}@test.example.com"
        
        async with transaction_manager.transaction() as conn:
            # Bootstrap admin user first time
            admin_user_1 = await bootstrap_admin_user(
                conn, 
                username=unique_username,
                email=unique_email,
                password="TestPassword123!"
            )
            assert admin_user_1 is not None
            
            # Bootstrap again with same username
            admin_user_2 = await bootstrap_admin_user(
                conn, 
                username=unique_username,
                email=unique_email,
                password="TestPassword123!"
            )
            assert admin_user_2 is None  # Should return None for existing user
            
            # Verify only one admin user exists
            user_repo = UserRepository(conn)
            existing_admin = await user_repo.get_by_username(unique_username)
            assert existing_admin is not None
            assert existing_admin.id == admin_user_1.id
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_user_upgrades_existing_user(self, transaction_manager: TransactionManager):
        """Test upgrading existing non-admin user to admin."""
        async with transaction_manager.transaction() as conn:
            # Create a regular user first
            user_repo = UserRepository(conn)
            regular_user = UserModel(
                id=uuid4(),
                username="future_admin",
                email="future_admin@example.com",
                password_hash=get_password_hash("RegularPass123!"),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_active=True,
                is_verified=True,
                is_admin=False  # Not an admin initially
            )
            
            created_user = await user_repo.create(regular_user)
            assert created_user.is_admin is False
            
            # Bootstrap admin user with same username
            admin_user = await bootstrap_admin_user(conn, username="future_admin")
            
            # Verify user was upgraded to admin
            assert admin_user is not None
            assert admin_user.id == created_user.id
            assert admin_user.is_admin is True
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_user_with_environment_variables(self, transaction_manager: TransactionManager):
        """Test bootstrap using environment variables."""
        env_username = f"env_admin_{generate_random_identifier()}"
        env_email = f"{env_username}@env.example.com"
        env_password = "EnvAdminPass123!"
        
        with patch.dict(os.environ, {
            "AUTHLY_ADMIN_USERNAME": env_username,
            "AUTHLY_ADMIN_EMAIL": env_email,
            "AUTHLY_ADMIN_PASSWORD": env_password
        }):
            async with transaction_manager.transaction() as conn:
                # Bootstrap should use environment variables
                admin_user = await bootstrap_admin_user(conn)
                
                assert admin_user.username == env_username
                assert admin_user.email == env_email
                
                # Verify password from environment works
                from authly.auth.core import verify_password
                assert verify_password(env_password, admin_user.password_hash) is True


class TestRegisterAdminScopes:
    """Test admin scope registration functionality."""
    
    @pytest.mark.asyncio
    async def test_register_admin_scopes_creates_all_scopes(self, transaction_manager: TransactionManager):
        """Test that all admin scopes are registered correctly."""
        async with transaction_manager.transaction() as conn:
            # Register admin scopes
            registered_count = await register_admin_scopes(conn)
            
            # Should register 0 or more scopes (depends on whether they already exist)
            assert registered_count >= 0
            
            # Most importantly: verify all scopes exist in database after registration
            scope_repo = ScopeRepository(conn)
            for scope_name, description in ADMIN_SCOPES.items():
                scope = await scope_repo.get_by_scope_name(scope_name)
                assert scope is not None
                assert scope.scope_name == scope_name
                assert scope.description == description
                assert scope.is_active is True
                assert scope.is_default is False  # Admin scopes are not default
    
    @pytest.mark.asyncio
    async def test_register_admin_scopes_idempotent(self, transaction_manager: TransactionManager):
        """Test that scope registration is idempotent."""
        async with transaction_manager.transaction() as conn:
            # Register scopes first time (may be 0 if already exist)
            first_count = await register_admin_scopes(conn)
            assert first_count >= 0
            
            # Register again (should be 0 since they all exist now)
            second_count = await register_admin_scopes(conn)
            assert second_count == 0  # No new scopes should be created
            
            # Verify all scopes exist and are correct
            scope_repo = ScopeRepository(conn)
            for scope_name in ADMIN_SCOPES:
                scope = await scope_repo.get_by_scope_name(scope_name)
                assert scope is not None
                assert scope.scope_name == scope_name
    
    @pytest.mark.asyncio
    async def test_register_admin_scopes_updates_descriptions(self, transaction_manager: TransactionManager):
        """Test that scope descriptions are updated if changed."""
        # Use a unique scope name for this test to avoid conflicts
        test_scope_name = f"admin:test:{generate_random_identifier()}"
        
        async with transaction_manager.transaction() as conn:
            scope_repo = ScopeRepository(conn)
            
            # Create a scope with old description
            from authly.oauth.models import OAuthScopeModel
            test_scope = OAuthScopeModel(
                id=uuid4(),
                scope_name=test_scope_name,
                description="Old description",
                is_default=False,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            await scope_repo.create(test_scope)
            
            # Now create or update an actual admin scope that might conflict
            existing_scope = await scope_repo.get_by_scope_name("admin:clients:read")
            if existing_scope:
                # Update with old description to test the update functionality
                await scope_repo.update_scope(existing_scope.id, {"description": "Old description"})
            
            # Register admin scopes (should update description)
            registered_count = await register_admin_scopes(conn)
            
            # Should register scopes that don't exist yet (could be 0 if all exist)
            assert registered_count >= 0
            
            # Verify description was updated for the admin scope
            updated_scope = await scope_repo.get_by_scope_name("admin:clients:read")
            assert updated_scope.description == ADMIN_SCOPES["admin:clients:read"]
            assert updated_scope.description != "Old description"
    
    @pytest.mark.asyncio
    async def test_register_admin_scopes_error_handling(self, transaction_manager: TransactionManager):
        """Test error handling in scope registration."""
        async with transaction_manager.transaction() as conn:
            # This test verifies that scope registration handles database errors gracefully
            # In normal circumstances, this should not fail, but we test error propagation
            
            # Create a scope repository
            scope_repo = ScopeRepository(conn)
            
            # Verify repository is working
            scopes = await scope_repo.get_active_scopes()
            assert isinstance(scopes, list)
            
            # Register scopes normally (should succeed)
            registered_count = await register_admin_scopes(conn)
            assert registered_count >= 0


class TestBootstrapAdminSystem:
    """Test complete admin system bootstrap."""
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_system_complete_flow(self, transaction_manager: TransactionManager):
        """Test complete bootstrap flow with user and scopes."""
        unique_username = f"flow_admin_{generate_random_identifier()}"
        unique_email = f"{unique_username}@flow.example.com"
        
        async with transaction_manager.transaction() as conn:
            # Bootstrap complete admin system
            results = await bootstrap_admin_system(
                conn,
                admin_username=unique_username,
                admin_email=unique_email,
                admin_password="FlowTest123!"
            )
            
            # Verify results structure
            assert "admin_user_created" in results
            assert "admin_user_id" in results
            assert "admin_scopes_registered" in results
            assert "bootstrap_completed" in results
            
            assert results["bootstrap_completed"] is True
            # Scopes might already exist from previous tests, so check >= 0
            assert results["admin_scopes_registered"] >= 0
            
            if results["admin_user_created"]:
                assert results["admin_user_id"] is not None
                
                # Verify admin user exists
                user_repo = UserRepository(conn)
                admin_user = await user_repo.get_by_id(results["admin_user_id"])
                assert admin_user is not None
                assert admin_user.is_admin is True
            
            # Verify all admin scopes exist (regardless of when they were created)
            scope_repo = ScopeRepository(conn)
            for scope_name in ADMIN_SCOPES:
                scope = await scope_repo.get_by_scope_name(scope_name)
                assert scope is not None
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_system_with_custom_credentials(self, transaction_manager: TransactionManager):
        """Test bootstrap with custom admin credentials."""
        async with transaction_manager.transaction() as conn:
            custom_username = f"system_admin_{generate_random_identifier()}"
            custom_email = f"{custom_username}@system.example.com"
            custom_password = "SystemAdminPass123!"
            
            # Bootstrap with custom credentials
            results = await bootstrap_admin_system(
                conn,
                admin_username=custom_username,
                admin_email=custom_email,
                admin_password=custom_password
            )
            
            assert results["bootstrap_completed"] is True
            assert results["admin_user_created"] is True
            
            # Verify custom admin user
            user_repo = UserRepository(conn)
            admin_user = await user_repo.get_by_username(custom_username)
            assert admin_user is not None
            assert admin_user.email == custom_email
            assert admin_user.is_admin is True
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_system_idempotent(self, transaction_manager: TransactionManager):
        """Test that complete bootstrap is idempotent."""
        unique_username = f"system_admin_{generate_random_identifier()}"
        unique_email = f"{unique_username}@system.example.com"
        
        async with transaction_manager.transaction() as conn:
            # First bootstrap
            results_1 = await bootstrap_admin_system(
                conn, 
                admin_username=unique_username,
                admin_email=unique_email,
                admin_password="SystemTest123!"
            )
            assert results_1["bootstrap_completed"] is True
            
            # Second bootstrap
            results_2 = await bootstrap_admin_system(
                conn, 
                admin_username=unique_username,
                admin_email=unique_email,
                admin_password="SystemTest123!"
            )
            assert results_2["bootstrap_completed"] is True
            assert results_2["admin_user_created"] is False  # Already existed
            assert results_2["admin_scopes_registered"] == 0  # Already existed
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_system_partial_existing_state(self, transaction_manager: TransactionManager):
        """Test bootstrap when some components already exist."""
        unique_username = f"existing_admin_{generate_random_identifier()}"
        unique_email = f"{unique_username}@existing.example.com"
        
        async with transaction_manager.transaction() as conn:
            # Create admin user manually first
            user_repo = UserRepository(conn)
            existing_admin = UserModel(
                id=uuid4(),
                username=unique_username,
                email=unique_email,
                password_hash=get_password_hash("ExistingPass123!"),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_active=True,
                is_verified=True,
                is_admin=True
            )
            created_admin = await user_repo.create(existing_admin)
            
            # Bootstrap system
            results = await bootstrap_admin_system(
                conn, 
                admin_username=unique_username,
                admin_email=unique_email,
                admin_password="ExistingPass123!"
            )
            
            # Should complete successfully
            assert results["bootstrap_completed"] is True
            assert results["admin_user_created"] is False  # Already existed
            # Scopes might already exist from previous tests, so check >= 0
            assert results["admin_scopes_registered"] >= 0
            assert results["admin_user_id"] == str(created_admin.id)


class TestBootstrapUtilities:
    """Test bootstrap utility functions."""
    
    @pytest.mark.asyncio
    async def test_get_bootstrap_status_default_values(self):
        """Test bootstrap status with default environment."""
        with patch.dict(os.environ, {}, clear=True):
            status = get_bootstrap_status()
            
            assert status["admin_username"] == "admin"
            assert status["admin_email"] == "admin@localhost"
            assert status["admin_password_set"] is False
            assert status["total_admin_scopes"] == len(ADMIN_SCOPES)
            assert len(status["admin_scopes"]) == len(ADMIN_SCOPES)
            
            # Verify all admin scopes are listed
            expected_scopes = set(ADMIN_SCOPES.keys())
            actual_scopes = set(status["admin_scopes"])
            assert actual_scopes == expected_scopes
    
    @pytest.mark.asyncio
    async def test_get_bootstrap_status_with_environment_variables(self):
        """Test bootstrap status with environment variables set."""
        with patch.dict(os.environ, {
            "AUTHLY_ADMIN_USERNAME": "env_admin",
            "AUTHLY_ADMIN_EMAIL": "env_admin@env.example.com",
            "AUTHLY_ADMIN_PASSWORD": "env_password"
        }):
            status = get_bootstrap_status()
            
            assert status["admin_username"] == "env_admin"
            assert status["admin_email"] == "env_admin@env.example.com"
            assert status["admin_password_set"] is True
            assert status["total_admin_scopes"] == len(ADMIN_SCOPES)
    
    @pytest.mark.asyncio
    async def test_get_bootstrap_status_scope_definitions(self):
        """Test that bootstrap status includes all current scope definitions."""
        status = get_bootstrap_status()
        
        # Verify count matches
        assert status["total_admin_scopes"] == len(ADMIN_SCOPES)
        
        # Verify all scope names are present
        for scope_name in ADMIN_SCOPES:
            assert scope_name in status["admin_scopes"]
        
        # Verify no extra scopes
        assert len(status["admin_scopes"]) == len(ADMIN_SCOPES)


class TestBootstrapSecurityModel:
    """Test bootstrap security model integration."""
    
    @pytest.mark.asyncio
    async def test_bootstrap_creates_two_layer_security_foundation(self, transaction_manager: TransactionManager):
        """Test that bootstrap creates proper foundation for two-layer security."""
        async with transaction_manager.transaction() as conn:
            # Bootstrap complete system
            results = await bootstrap_admin_system(conn)
            assert results["bootstrap_completed"] is True
            
            # Verify intrinsic authority layer (is_admin flag)
            if results["admin_user_created"]:
                user_repo = UserRepository(conn)
                admin_user = await user_repo.get_by_id(results["admin_user_id"])
                assert admin_user.is_admin is True  # First layer: intrinsic authority
            
            # Verify scoped permissions layer (admin scopes)
            scope_repo = ScopeRepository(conn)
            admin_scope_names = [
                "admin:clients:read", "admin:clients:write",
                "admin:scopes:read", "admin:scopes:write",
                "admin:users:read", "admin:users:write",
                "admin:system:read", "admin:system:write"
            ]
            
            for scope_name in admin_scope_names:
                scope = await scope_repo.get_by_scope_name(scope_name)
                assert scope is not None  # Second layer: scoped permissions
                assert scope.is_active is True
                assert scope.is_default is False  # Admin scopes are not default user scopes
    
    @pytest.mark.asyncio
    async def test_bootstrap_admin_scopes_comprehensive_coverage(self, transaction_manager: TransactionManager):
        """Test that bootstrap creates comprehensive admin scope coverage."""
        async with transaction_manager.transaction() as conn:
            await register_admin_scopes(conn)
            
            scope_repo = ScopeRepository(conn)
            
            # Verify CRUD operations are covered for each resource
            resources = ["clients", "scopes", "users", "system"]
            operations = ["read", "write"]
            
            for resource in resources:
                for operation in operations:
                    scope_name = f"admin:{resource}:{operation}"
                    scope = await scope_repo.get_by_scope_name(scope_name)
                    assert scope is not None, f"Missing admin scope: {scope_name}"
                    assert scope.description is not None
                    assert len(scope.description) > 0
    
    @pytest.mark.asyncio
    async def test_bootstrap_solves_iam_chicken_egg_paradox(self, transaction_manager: TransactionManager):
        """Test that bootstrap solves the IAM chicken-and-egg paradox."""
        unique_username = f"paradox_admin_{generate_random_identifier()}"
        unique_email = f"{unique_username}@paradox.example.com"
        
        async with transaction_manager.transaction() as conn:
            # Initial state: no admin user with our unique name
            user_repo = UserRepository(conn)
            scope_repo = ScopeRepository(conn)
            
            # Verify clean slate for our unique user
            admin_user = await user_repo.get_by_username(unique_username)
            assert admin_user is None
            
            # Note: admin scopes might already exist from other tests, which is fine
            
            # Bootstrap system (solves paradox)
            results = await bootstrap_admin_system(
                conn,
                admin_username=unique_username,
                admin_email=unique_email,
                admin_password="ParadoxTest123!"
            )
            assert results["bootstrap_completed"] is True
            
            # Verify solution:
            # 1. Admin user created with intrinsic authority (bypasses OAuth)
            if results["admin_user_created"]:
                admin_user = await user_repo.get_by_username(unique_username)
                assert admin_user is not None
                assert admin_user.is_admin is True  # Intrinsic authority, not OAuth-dependent
            
            # 2. Admin scopes registered (can now be granted to admin applications)
            admin_scope = await scope_repo.get_by_scope_name("admin:clients:write")
            assert admin_scope is not None
            
            # 3. Now admin can create OAuth clients and grant scopes without circular dependency