from fastapi import Depends

from authly import authly_db_connection
from authly.tokens.models import TokenType, TokenModel
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService
from authly.tokens.store import get_token_store_class
from authly.tokens.store.base import TokenStore
from authly.tokens.store.postgres import PostgresTokenStore

__all__ = [
    "TokenType",
    "TokenModel",
    "TokenRepository",
    "TokenService",
    "TokenStore",
    "PostgresTokenStore",
    "get_token_repository",
    "get_token_store",
    "get_token_service",
]


async def get_token_repository(db_connection=Depends(authly_db_connection)) -> TokenRepository:
    return TokenRepository(db_connection)


async def get_token_store(db_connection=Depends(authly_db_connection)) -> TokenStore:
    """
    FastAPI dependency for getting a configured TokenStore instance.

    Returns:
        TokenStore: An instance of the configured token store implementation
    """
    store_class = get_token_store_class()
    return store_class.create(db_connection)


async def get_token_service(token_store: TokenStore = Depends(get_token_store)) -> TokenService:
    return TokenService(token_store)
