import logging
import threading
from typing import Optional

from psycopg_pool import AsyncConnectionPool

from authly.config.config import AuthlyConfig

logger = logging.getLogger(__name__)


class Authly:
    """Singleton class for managing resources to Authly."""

    _instance = None
    _lock = threading.Lock()
    _config: Optional[AuthlyConfig] = None
    _pool: Optional[AsyncConnectionPool] = None

    def __init__(
            self,
            pool: AsyncConnectionPool,
            configuration: Optional[AuthlyConfig] = None
    ):
        if not hasattr(self, '_initialized'):
            self._pool = pool
            self._config = configuration or AuthlyConfig.load()
            self._initialized = True

    @classmethod
    def initialize(
            cls,
            pool: AsyncConnectionPool,
            configuration: Optional[AuthlyConfig] = None
    ) -> 'Authly':
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = cls(pool, configuration)
        return cls._instance

    @classmethod
    def get_instance(cls) -> 'Authly':
        if not cls._instance:
            raise RuntimeError("Authly not initialized")
        return cls._instance

    def get_config(self) -> AuthlyConfig:
        return self._config

    def get_pool(self) -> AsyncConnectionPool:
        return self._pool
