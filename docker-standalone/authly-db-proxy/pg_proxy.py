#!/usr/bin/env python3
"""
PostgreSQL Proxy with Authly Authentication
This proxy validates OAuth tokens with Authly before allowing database access.
"""

import logging
import os
from typing import Any

import aiohttp
import asyncpg
from aiohttp import web

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthlyPostgreSQLProxy:
    def __init__(self, authly_url: str, db_url: str, port: int = 5433):
        self.authly_url = authly_url
        self.db_url = db_url
        self.port = port
        self.app = web.Application()
        self.setup_routes()

    def setup_routes(self):
        self.app.router.add_post("/query", self.handle_query)
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

    async def handle_query(self, request):
        """Execute SQL query with Authly authentication"""

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
        if "database:read" not in scopes and "database:write" not in scopes:
            return web.json_response(
                {"error": "Insufficient permissions. Required scope: database:read or database:write"}, status=403
            )

        try:
            # Parse request body
            body = await request.json()
            query = body.get("query")
            params = body.get("params", [])

            if not query:
                return web.json_response({"error": "Missing query parameter"}, status=400)

            # Check if query is read-only
            is_write = any(
                keyword in query.upper() for keyword in ["INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER"]
            )

            if is_write and "database:write" not in scopes:
                return web.json_response({"error": "Write operations require database:write scope"}, status=403)

            # Connect to database
            conn = await asyncpg.connect(self.db_url)

            try:
                # Set session context for row-level security
                await conn.execute("SET LOCAL authly.user_id = $1", token_info["sub"])
                await conn.execute("SET LOCAL authly.username = $1", token_info.get("username", "anonymous"))
                await conn.execute("SET LOCAL authly.scopes = $1", token_info.get("scope", ""))

                # Execute query
                if query.strip().upper().startswith("SELECT"):
                    result = await conn.fetch(query, *params)
                    return web.json_response({"data": [dict(r) for r in result], "row_count": len(result)})
                else:
                    result = await conn.execute(query, *params)
                    # Extract affected rows from result string
                    affected = int(result.split()[-1]) if result else 0
                    return web.json_response({"message": "Query executed successfully", "affected_rows": affected})

            finally:
                await conn.close()

        except asyncpg.PostgresError as e:
            logger.error(f"Database error: {e}")
            return web.json_response({"error": f"Database error: {e!s}"}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return web.json_response({"error": "Internal server error"}, status=500)

    def run(self):
        """Start the proxy server"""
        logger.info(f"Starting Authly PostgreSQL Proxy on port {self.port}")
        logger.info(f"Authly URL: {self.authly_url}")
        logger.info(f"Database URL: {self.db_url}")
        web.run_app(self.app, port=self.port)


if __name__ == "__main__":
    # Configuration from environment variables
    authly_url = os.getenv("AUTHLY_URL", "http://localhost:8000")
    db_url = os.getenv("DATABASE_URL", "postgresql://authly:admin@localhost:5432/authly")
    proxy_port = int(os.getenv("PROXY_PORT", "5433"))

    proxy = AuthlyPostgreSQLProxy(authly_url, db_url, proxy_port)
    proxy.run()
