from fastapi import Depends

from authly.config import AuthlyConfig
from authly.core.dependencies import get_config, get_database_connection
from authly.tokens.models import TokenModel, TokenPairResponse, TokenType
from authly.tokens.repository import TokenRepository
from authly.tokens.service import TokenService

__all__ = [
    "TokenModel",
    "TokenPairResponse",
    "TokenRepository",
    "TokenService",
    "TokenType",
    "get_token_repository",
    "get_token_service",
]


async def get_token_repository(db_connection=Depends(get_database_connection)) -> TokenRepository:
    """Get TokenRepository instance with database connection."""
    return TokenRepository(db_connection)


async def get_token_service(
    _repository: TokenRepository = Depends(get_token_repository),
    config: AuthlyConfig = Depends(get_config),
) -> TokenService:
    """Get TokenService instance with required dependencies."""
    return TokenService(_repository, config, None)


async def get_token_service_with_client(
    db_connection=Depends(get_database_connection),
    config: AuthlyConfig = Depends(get_config),
) -> TokenService:
    """Get TokenService instance with client repository for ID token generation."""
    from authly.oauth.client_repository import ClientRepository
    from authly.tokens.repository import TokenRepository

    token_repo = TokenRepository(db_connection)
    client_repo = ClientRepository(db_connection)

    return TokenService(token_repo, config, client_repo)
