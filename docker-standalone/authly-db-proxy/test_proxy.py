#!/usr/bin/env python3
"""
Test client for Authly database proxies
Demonstrates using OAuth tokens for database access
"""

import asyncio
import sys

import aiohttp


async def get_authly_token(authly_url: str, username: str, password: str, scope: str = "database:read cache:read"):
    """Get an OAuth token from Authly"""
    async with (
        aiohttp.ClientSession() as session,
        session.post(
            f"{authly_url}/api/v1/oauth/token",
            data={"grant_type": "password", "username": username, "password": password, "scope": scope},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp,
    ):
        if resp.status == 200:
            result = await resp.json()
            return result["access_token"]
        else:
            text = await resp.text()
            raise Exception(f"Failed to get token: {text}")


async def test_postgres_proxy(proxy_url: str, token: str):
    """Test PostgreSQL proxy with token authentication"""
    print("\n=== Testing PostgreSQL Proxy ===")

    async with aiohttp.ClientSession() as session:
        # Test SELECT query
        async with session.post(
            f"{proxy_url}/query",
            json={"query": "SELECT tablename FROM pg_tables WHERE schemaname = $1 LIMIT 5", "params": ["public"]},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            result = await resp.json()
            if resp.status == 200:
                print(f"✅ SELECT query successful. Found {result['row_count']} tables:")
                for row in result["data"]:
                    print(f"   - {row['tablename']}")
            else:
                print(f"❌ SELECT query failed: {result}")

        # Test write query (will fail without database:write scope)
        print("\nTesting write operation (should fail with read-only token):")
        async with session.post(
            f"{proxy_url}/query",
            json={
                "query": "INSERT INTO oauth_scopes (name, description) VALUES ($1, $2)",
                "params": ["test:scope", "Test scope"],
            },
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            result = await resp.json()
            if resp.status == 403:
                print(f"✅ Write operation correctly blocked: {result['error']}")
            else:
                print(f"❌ Unexpected response: {result}")


async def test_redis_proxy(proxy_url: str, token: str):
    """Test Redis proxy with token authentication"""
    print("\n=== Testing Redis Proxy ===")

    async with aiohttp.ClientSession() as session:
        # Test SET command
        async with session.post(
            f"{proxy_url}/command",
            json={"command": "SET", "args": ["test_key", "test_value"]},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            result = await resp.json()
            if resp.status == 200:
                print(f"✅ SET command successful: {result}")
            else:
                print(f"❌ SET command failed: {result}")

        # Test GET command
        async with session.post(
            f"{proxy_url}/command",
            json={"command": "GET", "args": ["test_key"]},
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            result = await resp.json()
            if resp.status == 200:
                print(f"✅ GET command successful: {result}")
            else:
                print(f"❌ GET command failed: {result}")


async def main():
    # Configuration
    authly_url = "http://localhost:8000"
    pg_proxy_url = "http://localhost:5433"
    redis_proxy_url = "http://localhost:6380"

    try:
        # Get token from Authly
        print("Getting OAuth token from Authly...")
        token = await get_authly_token(
            authly_url, username="admin", password="admin", scope="database:read database:write cache:read cache:write"
        )
        print(f"✅ Got token: {token[:20]}...")

        # Test PostgreSQL proxy
        await test_postgres_proxy(pg_proxy_url, token)

        # Test Redis proxy
        await test_redis_proxy(redis_proxy_url, token)

    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
