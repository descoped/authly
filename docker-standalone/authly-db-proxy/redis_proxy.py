#!/usr/bin/env python3
"""
Redis/KeyDB Proxy with Authly Authentication
This proxy validates OAuth tokens with Authly before allowing cache access.
"""

import logging
import os
from typing import Any

import aiohttp
import aioredis
from aiohttp import web

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthlyRedisProxy:
    def __init__(self, authly_url: str, redis_url: str, port: int = 6380):
        self.authly_url = authly_url
        self.redis_url = redis_url
        self.port = port
        self.app = web.Application()
        self.setup_routes()

    def setup_routes(self):
        self.app.router.add_post("/command", self.handle_command)
        self.app.router.add_get("/health", self.handle_health)

    async def validate_token(self, token: str) -> dict[str, Any] | None:
        """Validate token with Authly's introspection endpoint"""
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    f"{self.authly_url}/api/v1/oauth/introspect",
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as resp,
            ):
                result = await resp.json()
                if result.get("active"):
                    return result
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
        return None

    async def handle_health(self, request):
        """Health check endpoint"""
        return web.json_response({"status": "healthy"})

    async def handle_command(self, request):
        """Execute Redis command with Authly authentication"""

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response({"error": "Missing or invalid Authorization header"}, status=401)

        token = auth_header[7:]  # Remove 'Bearer ' prefix

        # Validate token with Authly
        token_info = await self.validate_token(token)
        if not token_info:
            return web.json_response({"error": "Invalid or expired token"}, status=401)

        # Check for required scope
        scopes = token_info.get("scope", "").split()
        if "cache:read" not in scopes and "cache:write" not in scopes:
            return web.json_response(
                {"error": "Insufficient permissions. Required scope: cache:read or cache:write"}, status=403
            )

        try:
            # Parse request body
            body = await request.json()
            command = body.get("command")
            args = body.get("args", [])

            if not command:
                return web.json_response({"error": "Missing command parameter"}, status=400)

            # Check if command is write operation
            write_commands = [
                "SET",
                "DEL",
                "EXPIRE",
                "ZADD",
                "SADD",
                "HSET",
                "LPUSH",
                "RPUSH",
                "INCR",
                "DECR",
                "FLUSHDB",
                "FLUSHALL",
            ]

            is_write = command.upper() in write_commands

            if is_write and "cache:write" not in scopes:
                return web.json_response({"error": f"Command {command} requires cache:write scope"}, status=403)

            # Connect to Redis
            redis = await aioredis.create_redis_pool(self.redis_url)

            try:
                # Add user context as key prefix for isolation
                username = token_info.get("username", "anonymous")
                user_prefix = f"user:{token_info['sub']}:"

                # Modify keys to include user prefix for isolation
                if args and isinstance(args[0], str) and not args[0].startswith("user:"):
                    args[0] = user_prefix + args[0]

                # Execute command
                result = await redis.execute(command, *args)

                # Format response
                if isinstance(result, bytes):
                    result = result.decode("utf-8")
                elif isinstance(result, list):
                    result = [r.decode("utf-8") if isinstance(r, bytes) else r for r in result]

                return web.json_response({"result": result, "command": command, "user": username})

            finally:
                redis.close()
                await redis.wait_closed()

        except Exception as e:
            logger.error(f"Redis error: {e}")
            return web.json_response({"error": f"Redis error: {e!s}"}, status=500)

    def run(self):
        """Start the proxy server"""
        logger.info(f"Starting Authly Redis Proxy on port {self.port}")
        logger.info(f"Authly URL: {self.authly_url}")
        logger.info(f"Redis URL: {self.redis_url}")
        web.run_app(self.app, port=self.port)


if __name__ == "__main__":
    # Configuration from environment variables
    authly_url = os.getenv("AUTHLY_URL", "http://localhost:8000")
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    proxy_port = int(os.getenv("PROXY_PORT", "6380"))

    proxy = AuthlyRedisProxy(authly_url, redis_url, proxy_port)
    proxy.run()
