import logging

from authly.api.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

from dataclasses import dataclass
from typing import Final, Optional
from asyncio import Lock
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException
from fastapi import Request


@dataclass(frozen=True)
class OAuth2State:
    oauth: Final[OAuth2PasswordBearer]
    token_url: Final[str]


class DeferredOAuth2PasswordBearer:
    def __init__(self):
        self._state: Optional[OAuth2State] = None
        self._lock = Lock()
        self._init_error: Optional[Exception] = None

    def get_token_url(self) -> str:
        from authly import get_config
        try:
            config = get_config()
            return f"{config.fastapi_api_version_prefix}/auth/token"
        except Exception as e:
            self._init_error = e
            raise

    async def initialize(self) -> OAuth2State:
        """Thread-safe, retry-safe initialization"""
        if self._init_error:
            self._init_error = None

        async with self._lock:
            if self._state is None:
                try:
                    token_url = self.get_token_url()
                    oauth = OAuth2PasswordBearer(
                        tokenUrl=token_url,
                        auto_error=True
                    )
                    self._state = OAuth2State(oauth=oauth, token_url=token_url)
                except Exception as e:
                    self._init_error = e
                    raise HTTPException(
                        status_code=503,
                        detail="Authentication service temporarily unavailable"
                    )

        return self._state

    async def __call__(self, request: Request) -> str:
        """
        This is the method that FastAPI will call as a dependency.
        It needs to return the token string, not the OAuth2PasswordBearer instance.
        """
        state = await self.initialize()
        return await state.oauth(request)


# Single instance
oauth2_scheme = DeferredOAuth2PasswordBearer()


def get_rate_limiter():
    return RateLimiter()
