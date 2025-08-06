from authly.tokens.store.base import TokenStore
from authly.tokens.store.postgres import PostgresTokenStore

__all__ = ["PostgresTokenStore", "TokenStore", "get_token_store_class"]


def get_token_store_class() -> type[TokenStore]:
    """
    Get the configured token store class.
    This allows for easy switching between different implementations.
    """
    return PostgresTokenStore
