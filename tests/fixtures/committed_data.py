"""
Committed data fixtures for test isolation.

These fixtures create data that is committed to the database and visible to HTTP endpoints,
unlike transactional fixtures that are isolated within a transaction.

This solves the transaction isolation problem where HTTP endpoints cannot see data
created within test transactions.
"""

import secrets
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from authly.auth import get_password_hash
from authly.oauth.authorization_code_repository import AuthorizationCodeRepository
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import (
    ClientType,
    CodeChallengeMethod,
    GrantType,
    TokenEndpointAuthMethod,
)
from authly.oauth.scope_repository import ScopeRepository
from authly.tokens.models import TokenModel, TokenType
from authly.tokens.repository import TokenRepository
from authly.users.models import UserModel


@pytest.fixture
async def committed_user(db_pool: AsyncConnectionPool) -> UserModel:
    """
    Create a user that is committed to the database and visible to HTTP endpoints.

    The user is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        # Generate unique user data
        user_id = uuid4()
        username = f"test_user_{uuid4().hex[:8]}"
        email = f"{username}@example.com"

        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "password_hash": get_password_hash("TestPassword123!"),
            "is_active": True,
            "is_verified": True,
            "is_admin": False,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }

        # Create user with autocommit using direct SQL
        await conn.set_autocommit(True)
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO users (id, username, email, password_hash, is_active, is_verified, is_admin, created_at, updated_at)
                VALUES (%(id)s, %(username)s, %(email)s, %(password_hash)s, %(is_active)s, %(is_verified)s, %(is_admin)s, %(created_at)s, %(updated_at)s)
                RETURNING *
            """,
                user_data,
            )
            result = await cur.fetchone()

        # Create UserModel from result
        created_user = UserModel(**result)

        yield created_user

        # Cleanup: Delete the user
        with suppress(Exception):
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM users WHERE id = %s", (created_user.id,))


@pytest.fixture
async def committed_admin_user(db_pool: AsyncConnectionPool) -> UserModel:
    """
    Create an admin user that is committed to the database and visible to HTTP endpoints.

    The user is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        # Generate unique user data
        user_id = uuid4()
        username = f"admin_user_{uuid4().hex[:8]}"
        email = f"{username}@example.com"

        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "password_hash": get_password_hash("AdminPassword123!"),
            "is_active": True,
            "is_verified": True,
            "is_admin": True,  # Admin user
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }

        # Create user with autocommit using direct SQL
        await conn.set_autocommit(True)
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO users (id, username, email, password_hash, is_active, is_verified, is_admin, created_at, updated_at)
                VALUES (%(id)s, %(username)s, %(email)s, %(password_hash)s, %(is_active)s, %(is_verified)s, %(is_admin)s, %(created_at)s, %(updated_at)s)
                RETURNING *
            """,
                user_data,
            )
            result = await cur.fetchone()

        # Create UserModel from result
        created_user = UserModel(**result)

        yield created_user

        # Cleanup: Delete the user
        with suppress(Exception):
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM users WHERE id = %s", (created_user.id,))


@pytest.fixture
async def committed_oauth_client(db_pool: AsyncConnectionPool) -> dict:
    """
    Create an OAuth client that is committed to the database and visible to HTTP endpoints.

    Returns a dict with client details including the unhashed secret.
    The client is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        client_repo = ClientRepository(conn)

        # Generate unique client data
        client_id = f"test_client_{uuid4().hex[:8]}"
        client_secret = secrets.token_urlsafe(32)

        client_data = {
            "client_id": client_id,
            "client_name": "Test OAuth Client",
            "client_type": ClientType.CONFIDENTIAL,
            "client_secret_hash": get_password_hash(client_secret),
            "redirect_uris": ["http://localhost:8000/callback", "http://localhost:3000/callback"],
            "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.CLIENT_CREDENTIALS],
            "response_types": ["code"],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
            "require_pkce": True,
            "is_active": True,
        }

        # Create client with autocommit
        await conn.set_autocommit(True)
        created_client = await client_repo.create_client(client_data)

        # Return client with unhashed secret
        client_dict = created_client.model_dump()
        client_dict["client_secret"] = client_secret  # Add unhashed secret for testing

        yield client_dict

        # Cleanup: Delete the client
        with suppress(Exception):
            # delete_client expects a client_id string, not UUID
            await conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", created_client.client_id)


@pytest.fixture
async def committed_public_client(db_pool: AsyncConnectionPool) -> dict:
    """
    Create a public OAuth client (no secret) that is committed to the database.

    Public clients are used for SPAs and mobile apps where the client secret cannot be kept confidential.
    The client is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        client_repo = ClientRepository(conn)

        # Generate unique client data
        client_id = f"public_client_{uuid4().hex[:8]}"

        client_data = {
            "client_id": client_id,
            "client_name": "Test Public OAuth Client",
            "client_type": ClientType.PUBLIC,
            "redirect_uris": ["http://localhost:3000/callback", "myapp://callback"],
            "grant_types": [GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
            "response_types": ["code"],
            "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,  # Public clients don't use secrets
            "require_pkce": True,  # PKCE is mandatory for public clients
            "is_active": True,
        }

        # Create client with autocommit
        await conn.set_autocommit(True)
        created_client = await client_repo.create_client(client_data)

        yield created_client.model_dump()

        # Cleanup: Delete the client
        with suppress(Exception):
            # delete_client expects a client_id string, not UUID
            await conn.execute("DELETE FROM oauth_clients WHERE client_id = $1", created_client.client_id)


@pytest.fixture
async def committed_scope(db_pool: AsyncConnectionPool) -> dict:
    """
    Create a scope that is committed to the database and visible to HTTP endpoints.

    The scope is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        scope_repo = ScopeRepository(conn)

        # Generate unique scope data
        scope_name = f"test_scope_{uuid4().hex[:8]}"

        scope_data = {
            "scope_name": scope_name,
            "description": f"Test scope for {scope_name}",
            "is_active": True,
        }

        # Create scope with autocommit
        await conn.set_autocommit(True)

        # Handle case where scope might already exist
        with suppress(Exception):
            created_scope = await scope_repo.create_scope(scope_data)

            yield created_scope.model_dump()

            # Cleanup: Delete the scope
            with suppress(Exception):
                await scope_repo.delete_scope(created_scope.id)
            return

        # If creation failed, try to get existing scope
        existing_scope = await scope_repo.get_scope_by_name(scope_name)
        if existing_scope:
            yield existing_scope.model_dump()
        else:
            # Create standard scopes if custom fails
            for standard_scope in ["read", "write", "openid", "profile", "email"]:
                with suppress(Exception):
                    await scope_repo.create_scope(
                        {
                            "scope_name": standard_scope,
                            "description": f"Standard {standard_scope} scope",
                            "is_active": True,
                        }
                    )

            # Return a standard scope
            read_scope = await scope_repo.get_scope_by_name("read")
            yield read_scope.model_dump() if read_scope else {"scope_name": "read", "description": "Read access"}


@pytest.fixture
async def committed_authorization_code(
    db_pool: AsyncConnectionPool,
    committed_user: UserModel,
    committed_oauth_client: dict,
) -> dict:
    """
    Create an authorization code that is committed to the database.

    The code is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        auth_code_repo = AuthorizationCodeRepository(conn)

        # Generate authorization code
        code = secrets.token_urlsafe(32)
        code_challenge = "test_challenge_" + secrets.token_urlsafe(32)

        auth_code_data = {
            "code": code,
            "client_id": committed_oauth_client["client_id"],
            "user_id": committed_user.id,
            "redirect_uri": committed_oauth_client["redirect_uris"][0],
            "scope": "read write openid",
            "code_challenge": code_challenge,
            "code_challenge_method": CodeChallengeMethod.S256,
            "expires_at": datetime.now(UTC) + timedelta(minutes=10),
            "used": False,
        }

        # Create auth code with autocommit
        await conn.set_autocommit(True)
        created_code = await auth_code_repo.create_authorization_code(auth_code_data)

        # Return code data with the actual code string
        code_dict = created_code.model_dump() if hasattr(created_code, "model_dump") else created_code
        code_dict["code"] = code  # Ensure the code string is included
        code_dict["code_challenge"] = code_challenge

        yield code_dict

        # Cleanup: Mark as used or delete
        with suppress(Exception):
            await auth_code_repo.mark_code_as_used(code)


@pytest.fixture
async def committed_token(
    db_pool: AsyncConnectionPool,
    committed_user: UserModel,
    committed_oauth_client: dict,
) -> dict:
    """
    Create a token that is committed to the database.

    The token is automatically cleaned up after the test.
    """
    async with db_pool.connection() as conn:
        token_repo = TokenRepository(conn)

        # Generate token data
        jti = str(uuid4())

        token_data = TokenModel(
            jti=jti,
            user_id=committed_user.id,
            client_id=committed_oauth_client["client_id"],
            token_type=TokenType.ACCESS,
            scope="read write",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            is_revoked=False,
        )

        # Store token with autocommit
        await conn.set_autocommit(True)
        await token_repo.store_token(token_data)

        yield {"jti": jti, "token_data": token_data}

        # Cleanup: Revoke the token
        with suppress(Exception):
            await token_repo.revoke_token(jti)


# Fixture combinations for common test scenarios


@pytest.fixture
async def committed_auth_setup(
    db_pool: AsyncConnectionPool,
    committed_user: UserModel,
    committed_oauth_client: dict,
    committed_scope: dict,
) -> dict:
    """
    Complete setup for authorization testing with committed data.

    Returns a dict with user, client, and scope all committed to the database.
    """
    return {
        "user": committed_user,
        "client": committed_oauth_client,
        "scope": committed_scope,
        "db_pool": db_pool,
    }


@pytest.fixture
async def committed_client_credentials_setup(
    db_pool: AsyncConnectionPool,
    committed_oauth_client: dict,
    committed_scope: dict,
) -> dict:
    """
    Setup for client credentials grant testing with committed data.

    Returns a dict with client and scope committed to the database.
    """
    return {
        "client": committed_oauth_client,
        "scope": committed_scope,
        "db_pool": db_pool,
    }
