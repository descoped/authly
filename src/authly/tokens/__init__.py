from fastapi import Depends

from authly import authly_db_connection
from authly.tokens.models import TokenModel, TokenPairResponse, TokenType
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService

__all__ = [
    "TokenType",
    "TokenModel",
    "TokenPairResponse",
    "TokenRepository",
    "TokenService",
    "get_token_repository",
    "get_token_service",
]


async def get_token_repository(db_connection=Depends(authly_db_connection)) -> TokenRepository:
    """Get TokenRepository instance with database connection."""
    return TokenRepository(db_connection)


async def get_token_service(repository: TokenRepository = Depends(get_token_repository)) -> TokenService:
    """Get TokenService instance with TokenRepository dependency."""
    return TokenService(repository)
