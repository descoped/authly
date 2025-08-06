"""
Admin User Bootstrap and Scope Seeding for Authly authentication service.

This module implements the security bootstrap strategy that solves the
IAM chicken-and-egg paradox by creating the initial admin user with
intrinsic authority and registering admin scopes during system initialization.
"""

import logging
import os
import secrets
import string
from datetime import UTC, datetime
from uuid import uuid4

from psycopg import AsyncConnection

from authly.api.admin_dependencies import ADMIN_SCOPES
from authly.auth import get_password_hash
from authly.oauth.models import OAuthScopeModel
from authly.oauth.scope_repository import ScopeRepository
from authly.oidc.scopes import get_oidc_scopes_with_descriptions
from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password.

    Creates a password with guaranteed complexity:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Args:
        length: Password length (minimum 16)

    Returns:
        Secure random password string
    """
    if length < 16:
        length = 16

    # Character sets
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

    # Ensure at least one of each required type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]

    # Fill the rest with random characters
    for _ in range(length - 4):
        password.append(secrets.choice(alphabet))

    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


async def bootstrap_admin_user(
    conn: AsyncConnection, username: str | None = None, email: str | None = None, password: str | None = None
) -> UserModel | None:
    """
    Create the initial admin user with intrinsic authority.

    This function implements the first part of the security bootstrap strategy
    by creating an admin user that bypasses OAuth dependency through the
    database-level is_admin flag.

    Args:
        conn: Database connection
        username: Admin username (defaults to environment variable or "admin")
        email: Admin email (defaults to environment variable or "admin@localhost")
        password: Admin password (defaults to environment variable or generated)

    Returns:
        Created admin user model, or None if admin already exists

    Raises:
        Exception: If admin user creation fails
    """
    try:
        # Get admin credentials from environment or use defaults
        admin_username = username or os.getenv("AUTHLY_ADMIN_USERNAME", "admin")
        admin_email = email or os.getenv("AUTHLY_ADMIN_EMAIL", "admin@localhost")
        admin_password = password or os.getenv("AUTHLY_ADMIN_PASSWORD")

        # Check for development mode override
        dev_mode = os.getenv("AUTHLY_BOOTSTRAP_DEV_MODE", "false").lower() == "true"

        # Generate secure password if not provided
        generated_password = False
        if not admin_password:
            admin_password = generate_secure_password()
            generated_password = True

            # Log the generated password with high visibility
            logger.warning("=" * 70)
            logger.warning("ADMIN BOOTSTRAP - SECURE PASSWORD GENERATED")
            logger.warning("=" * 70)
            logger.warning(f"Username: {admin_username}")
            logger.warning(f"Password: {admin_password}")
            logger.warning("=" * 70)
            logger.warning("SAVE THIS PASSWORD NOW - IT WILL NOT BE SHOWN AGAIN")
            logger.warning("You will be required to change it on first login")
            logger.warning("=" * 70)
        elif dev_mode:
            # Development mode with provided password
            logger.warning("=" * 70)
            logger.warning("DEVELOPMENT MODE BOOTSTRAP ACTIVE")
            logger.warning("=" * 70)
            logger.warning(f"Username: {admin_username}")
            logger.warning("Password: [PROVIDED VIA AUTHLY_ADMIN_PASSWORD]")
            logger.warning("Password change requirement: DISABLED")
            logger.warning("=" * 70)
            logger.warning("WARNING: This mode should NEVER be used in production!")
            logger.warning("Set AUTHLY_BOOTSTRAP_DEV_MODE=false for production security")
            logger.warning("=" * 70)

        logger.info(f"Bootstrap: Checking for existing admin user: {admin_username}")

        # Check if admin user already exists
        user_repo = UserRepository(conn)
        existing_admin = await user_repo.get_by_username(admin_username)

        if existing_admin:
            if existing_admin.is_admin:
                logger.info(f"Admin user already exists: {admin_username}")
                return None
            else:
                # Upgrade existing user to admin
                logger.info(f"Upgrading existing user to admin: {admin_username}")
                update_data = {"is_admin": True}
                return await user_repo.update(existing_admin.id, update_data)

        # Create new admin user with intrinsic authority
        # Determine password change requirement based on mode
        requires_password_change = True  # Default: always require change
        if dev_mode and not generated_password:
            # Only disable password change in dev mode with provided password
            requires_password_change = False

        admin_user = UserModel(
            id=uuid4(),
            username=admin_username,
            email=admin_email,
            password_hash=get_password_hash(admin_password),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            is_active=True,
            is_verified=True,
            is_admin=True,  # Intrinsic authority - not an OAuth scope
            requires_password_change=requires_password_change,
        )

        created_user = await user_repo.create(admin_user)

        logger.info(
            f"Bootstrap: Created admin user successfully - username: {admin_username}, user_id: {created_user.id}"
        )

        # Log bootstrap completion
        logger.info("Admin user created with requires_password_change=True. Password must be changed on first login.")

        return created_user

    except Exception as e:
        logger.error(f"Failed to bootstrap admin user: {e}")
        raise RuntimeError("Failed to bootstrap admin user: See logs for details") from None


async def register_admin_scopes(conn: AsyncConnection) -> int:
    """
    Register admin scopes in the database during system initialization.

    This function implements the second part of the security bootstrap strategy
    by registering all admin scopes that can then be granted to admin applications.

    Args:
        conn: Database connection

    Returns:
        Number of scopes registered (new scopes only)

    Raises:
        Exception: If scope registration fails
    """
    try:
        logger.info("Bootstrap: Registering admin scopes")

        scope_repo = ScopeRepository(conn)
        registered_count = 0

        for scope_name, description in ADMIN_SCOPES.items():
            # Check if scope already exists
            existing_scope = await scope_repo.get_by_scope_name(scope_name)

            if existing_scope:
                logger.debug(f"Admin scope already exists: {scope_name}")
                # Update description if different
                if existing_scope.description != description:
                    logger.info(f"Updating admin scope description: {scope_name}")
                    await scope_repo.update(existing_scope.id, {"description": description})
                continue

            # Create new admin scope

            scope = OAuthScopeModel(
                id=uuid4(),
                scope_name=scope_name,
                description=description,
                is_default=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            await scope_repo.create(scope)
            registered_count += 1

            logger.info(f"Registered admin scope: {scope_name}")

        logger.info(f"Bootstrap: Registered {registered_count} new admin scopes")
        return registered_count

    except Exception as e:
        logger.error(f"Failed to register admin scopes: {e}")
        raise RuntimeError("Failed to register admin scopes: See logs for details") from None


async def register_oidc_scopes(conn: AsyncConnection) -> int:
    """
    Register OIDC scopes in the database during system initialization.

    This function registers standard OpenID Connect scopes that enable
    OIDC flows on top of the OAuth 2.1 foundation.

    Args:
        conn: Database connection

    Returns:
        Number of scopes registered (new scopes only)

    Raises:
        Exception: If scope registration fails
    """
    try:
        logger.info("Bootstrap: Registering OIDC scopes")

        scope_repo = ScopeRepository(conn)
        registered_count = 0

        # Get OIDC scopes with descriptions
        oidc_scopes = get_oidc_scopes_with_descriptions()

        for scope_name, description in oidc_scopes.items():
            # Check if scope already exists
            existing_scope = await scope_repo.get_by_scope_name(scope_name)

            if existing_scope:
                logger.debug(f"OIDC scope already exists: {scope_name}")
                # Update description if different
                if existing_scope.description != description:
                    logger.info(f"Updating OIDC scope description: {scope_name}")
                    await scope_repo.update(existing_scope.id, {"description": description})
                continue

            # Create new OIDC scope

            scope = OAuthScopeModel(
                id=uuid4(),
                scope_name=scope_name,
                description=description,
                is_default=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            await scope_repo.create(scope)
            registered_count += 1

            logger.info(f"Registered OIDC scope: {scope_name}")

        logger.info(f"Bootstrap: Registered {registered_count} new OIDC scopes")
        return registered_count

    except Exception as e:
        logger.error(f"Failed to register OIDC scopes: {e}")
        raise RuntimeError("Failed to register OIDC scopes: See logs for details") from None


async def bootstrap_admin_system(
    conn: AsyncConnection,
    admin_username: str | None = None,
    admin_email: str | None = None,
    admin_password: str | None = None,
) -> dict:
    """
    Complete admin system bootstrap process.

    This function orchestrates the full security bootstrap by creating
    the admin user and registering admin scopes in the correct order.

    Args:
        conn: Database connection
        admin_username: Admin username (optional)
        admin_email: Admin email (optional)
        admin_password: Admin password (optional)

    Returns:
        Dictionary with bootstrap results

    Raises:
        Exception: If bootstrap process fails
    """
    try:
        logger.info("Starting admin system bootstrap")

        results = {
            "admin_user_created": False,
            "admin_user_id": None,
            "admin_scopes_registered": 0,
            "oidc_scopes_registered": 0,
            "bootstrap_completed": False,
        }

        # Step 1: Register admin scopes first
        admin_scopes_registered = await register_admin_scopes(conn)
        results["admin_scopes_registered"] = admin_scopes_registered

        # Step 2: Register OIDC scopes
        oidc_scopes_registered = await register_oidc_scopes(conn)
        results["oidc_scopes_registered"] = oidc_scopes_registered

        # Step 3: Create admin user with intrinsic authority
        admin_user = await bootstrap_admin_user(conn, admin_username, admin_email, admin_password)

        if admin_user:
            results["admin_user_created"] = True
            results["admin_user_id"] = str(admin_user.id)
            logger.info(f"Admin user bootstrap completed: {admin_user.username}")
        else:
            # User already exists, get the existing user ID
            logger.info("Admin user already exists, skipping creation")
            admin_username = admin_username or os.getenv("AUTHLY_ADMIN_USERNAME", "admin")
            user_repo = UserRepository(conn)
            existing_admin = await user_repo.get_by_username(admin_username)
            if existing_admin:
                results["admin_user_id"] = str(existing_admin.id)

        results["bootstrap_completed"] = True

        logger.info(
            f"Admin system bootstrap completed successfully - "
            f"admin_scopes: {admin_scopes_registered}, oidc_scopes: {oidc_scopes_registered}, "
            f"admin_created: {admin_user is not None}"
        )

        return results

    except Exception as e:
        logger.error(f"Admin system bootstrap failed: {e}")
        raise RuntimeError("An error occurred") from None


def get_bootstrap_status() -> dict:
    """
    Get current bootstrap configuration status.

    Returns:
        Dictionary with bootstrap configuration information
    """
    oidc_scopes = get_oidc_scopes_with_descriptions()

    return {
        "admin_username": os.getenv("AUTHLY_ADMIN_USERNAME", "admin"),
        "admin_email": os.getenv("AUTHLY_ADMIN_EMAIL", "admin@localhost"),
        "admin_password_set": bool(os.getenv("AUTHLY_ADMIN_PASSWORD")),
        "total_admin_scopes": len(ADMIN_SCOPES),
        "admin_scopes": list(ADMIN_SCOPES.keys()),
        "total_oidc_scopes": len(oidc_scopes),
        "oidc_scopes": list(oidc_scopes.keys()),
    }
