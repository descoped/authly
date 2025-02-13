import logging
from datetime import datetime
from uuid import uuid4

import pytest
from psycopg import AsyncConnection
from psycopg_toolkit import RecordNotFoundError

from authly.users.models import UserModel
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


@pytest.fixture
async def user_repo(db_connection_rollback_transaction: AsyncConnection, transaction) -> UserRepository:
    logger.debug("Creating user repository")
    return UserRepository(db_connection_rollback_transaction)


@pytest.fixture
async def sample_user() -> UserModel:
    return UserModel(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        password_hash="hashed_password",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )


@pytest.mark.asyncio
async def test_create_user(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    assert created_user.username == sample_user.username
    assert created_user.email == sample_user.email
    assert created_user.id is not None


@pytest.mark.asyncio
async def test_get_user_by_id(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    retrieved_user = await user_repo.get_by_id(created_user.id)
    assert retrieved_user is not None
    assert retrieved_user.username == sample_user.username


@pytest.mark.asyncio
async def test_get_user_by_username(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    retrieved_user = await user_repo.get_by_username(sample_user.username)
    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id


@pytest.mark.asyncio
async def test_get_user_by_email(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    retrieved_user = await user_repo.get_by_email(sample_user.email)
    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id


@pytest.mark.asyncio
async def test_update_user(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    updated_data = {"username": "updated_user"}
    updated_user = await user_repo.update(created_user.id, updated_data)
    assert updated_user.username == "updated_user"
    assert updated_user.email == sample_user.email


@pytest.mark.asyncio
async def test_update_last_login(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    initial_login = created_user.last_login
    updated_user = await user_repo.update_last_login(created_user.id)
    assert updated_user.last_login is not None
    assert updated_user.last_login != initial_login


@pytest.mark.asyncio
async def test_delete_user(user_repo: UserRepository, sample_user: UserModel, transaction):
    created_user = await user_repo.create(sample_user)
    await user_repo.delete(created_user.id)
    with pytest.raises(RecordNotFoundError):
        await user_repo.get_by_id(created_user.id)


@pytest.mark.asyncio
async def test_get_all_users(user_repo: UserRepository, sample_user: UserModel, transaction):
    await user_repo.create(sample_user)
    second_user = sample_user.model_copy(update={"id": uuid4(), "username": "user2", "email": "user2@example.com"})
    await user_repo.create(second_user)

    all_users = await user_repo.get_all()
    assert len(all_users) >= 2
    assert any(user.username == sample_user.username for user in all_users)
    assert any(user.username == "user2" for user in all_users)
