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
    repository: TokenRepository = Depends(get_token_repository),
    config: AuthlyConfig = Depends(get_config),
) -> TokenService:
    """Get TokenService instance with required dependencies."""
    return TokenService(repository, config, None)


async def get_token_service_with_client(
    repository: TokenRepository = Depends(get_token_repository),
    config: AuthlyConfig = Depends(get_config),
) -> TokenService:
    """Get TokenService instance with client repository for ID token generation."""
    from authly.api.auth_dependencies import get_client_repository
    from authly.core.dependencies import get_database_connection

    # Get client repository for ID token generation
    db_connection = await get_database_connection()
    client_repo = await get_client_repository(db_connection)

    return TokenService(repository, config, client_repo)
