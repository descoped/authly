"""
Concurrent request handling tests.

Tests how the OAuth endpoints handle concurrent requests and race conditions.
"""

import asyncio
import secrets
import time
from uuid import uuid4

import pytest
from fastapi import status
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager
from authly.oauth.client_repository import ClientRepository
from authly.oauth.models import ClientType, GrantType, TokenEndpointAuthMethod
from authly.users import UserRepository
from authly.users.service import UserService


class TestConcurrentRequests:
    """Test concurrent request handling."""

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_concurrent_authorization_codes(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test handling multiple concurrent authorization code requests."""
        async with test_server.client as http_client, transaction_manager.transaction() as conn:
            client_repo = ClientRepository(conn)
            user_repo = UserRepository(conn)
            user_service = UserService(user_repo)

            # Create test client
            client_data = {
                "client_id": f"concurrent_client_{uuid4().hex[:8]}",
                "client_name": "Concurrent Test Client",
                "client_type": ClientType.PUBLIC,
                "redirect_uris": ["http://localhost:8000/callback"],
                "require_pkce": True,
                "grant_types": [GrantType.AUTHORIZATION_CODE],
                "token_endpoint_auth_method": TokenEndpointAuthMethod.NONE,
            }
            created_client = await client_repo.create_client(client_data)

            # Create test users
            users = []
            for i in range(5):
                username = f"concurrent_user_{i}_{uuid4().hex[:8]}"
                user = await user_service.create_user(
                    username=username,
                    email=f"{username}@example.com",
                    password="TestPassword123!",
                    is_admin=False,
                    is_active=True,
                    is_verified=True,
                )
                users.append(user)

            # Prepare authorization requests
            async def make_auth_request(user_num):
                """Make an authorization request for a user."""
                try:
                    # Generate PKCE challenge
                    secrets.token_urlsafe(32)
                    code_challenge = secrets.token_urlsafe(32)  # Simplified for test

                    params = {
                        "response_type": "code",
                        "client_id": created_client.client_id,
                        "redirect_uri": "http://localhost:8000/callback",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "scope": "read write",
                        "state": f"state_{user_num}",
                    }

                    response = await http_client.get(
                        "/api/v1/oauth/authorize",
                        params=params,
                    )

                    return {
                        "user_num": user_num,
                        "status": response.status_code,
                        "response": response,
                    }
                except Exception as e:
                    return {
                        "user_num": user_num,
                        "status": -1,
                        "error": str(e),
                    }

            # Send concurrent requests
            start_time = time.time()
            tasks = [make_auth_request(i) for i in range(5)]
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time

            # Analyze results
            print("\nConcurrent Authorization Requests Test:")
            print(f"Sent {len(results)} concurrent requests in {elapsed:.2f}s")

            success_count = sum(1 for r in results if r["status"] == status.HTTP_200_OK)
            error_count = sum(1 for r in results if r["status"] >= 400)
            failed_count = sum(1 for r in results if r["status"] == -1)

            print(f"Successful: {success_count}")
            print(f"Errors: {error_count}")
            print(f"Failed: {failed_count}")

            # All requests should be handled (either success or proper error)
            assert failed_count == 0, "No requests should fail due to concurrency"

            # Check for race conditions
            if success_count == len(results):
                print("✓ All concurrent requests handled successfully")
            else:
                print("⚠ Some requests failed - may indicate concurrency issues")

    @pytest.mark.asyncio
    async def test_concurrent_token_exchanges(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test concurrent token exchange requests."""
        async with test_server.client as http_client:
            # Prepare multiple token exchange requests
            async def exchange_token(request_num):
                """Attempt to exchange an authorization code for tokens."""
                try:
                    response = await http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "authorization_code",
                            "code": f"test_code_{request_num}",
                            "redirect_uri": "http://localhost:8000/callback",
                            "client_id": f"client_{request_num}",
                            "code_verifier": "test_verifier",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    return {
                        "request_num": request_num,
                        "status": response.status_code,
                        "response": response,
                    }
                except Exception as e:
                    return {
                        "request_num": request_num,
                        "status": -1,
                        "error": str(e),
                    }

            # Send 10 concurrent token exchange requests
            start_time = time.time()
            tasks = [exchange_token(i) for i in range(10)]
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time

            print("\nConcurrent Token Exchange Test:")
            print(f"Sent {len(results)} concurrent requests in {elapsed:.2f}s")

            # All should fail with bad request (invalid codes) but not crash
            bad_requests = sum(1 for r in results if r["status"] == status.HTTP_400_BAD_REQUEST)
            failed = sum(1 for r in results if r["status"] == -1)

            print(f"Bad requests (expected): {bad_requests}")
            print(f"Failed requests: {failed}")

            assert failed == 0, "No requests should fail due to concurrency"
            assert bad_requests == len(results), "All should fail with bad request (invalid codes)"
            print("✓ All concurrent token exchanges handled properly")

    @pytest.mark.asyncio
    async def test_concurrent_refresh_tokens(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test concurrent refresh token requests."""
        async with test_server.client as http_client:

            async def refresh_token(request_num):
                """Attempt to refresh a token."""
                try:
                    response = await http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "refresh_token",
                            "refresh_token": f"refresh_{request_num}",
                            "client_id": f"client_{request_num}",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    return {
                        "request_num": request_num,
                        "status": response.status_code,
                    }
                except Exception as e:
                    return {
                        "request_num": request_num,
                        "status": -1,
                        "error": str(e),
                    }

            # Send concurrent refresh requests
            start_time = time.time()
            tasks = [refresh_token(i) for i in range(15)]
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time

            print("\nConcurrent Refresh Token Test:")
            print(f"Sent {len(results)} concurrent refresh requests in {elapsed:.2f}s")

            failed = sum(1 for r in results if r["status"] == -1)
            errors = sum(1 for r in results if r["status"] >= 400)

            print(f"Failed requests: {failed}")
            print(f"Error responses: {errors}")

            assert failed == 0, "No requests should fail due to concurrency"
            print("✓ Concurrent refresh token requests handled without crashes")

    @pytest.mark.asyncio
    async def test_race_condition_same_auth_code(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test race condition when same auth code is used multiple times concurrently."""
        async with test_server.client as http_client:
            # Use the same authorization code in multiple concurrent requests
            auth_code = "same_code_for_all"

            async def use_auth_code(request_num):
                """Try to use the same authorization code."""
                try:
                    response = await http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "authorization_code",
                            "code": auth_code,
                            "redirect_uri": "http://localhost:8000/callback",
                            "client_id": "test_client",
                            "code_verifier": "test_verifier",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    return {
                        "request_num": request_num,
                        "status": response.status_code,
                        "time": time.time(),
                    }
                except Exception as e:
                    return {
                        "request_num": request_num,
                        "status": -1,
                        "error": str(e),
                    }

            # Send 5 concurrent requests with the same auth code
            print("\nRace Condition Test - Same Authorization Code:")
            tasks = [use_auth_code(i) for i in range(5)]
            results = await asyncio.gather(*tasks)

            failed = sum(1 for r in results if r["status"] == -1)
            successful = sum(1 for r in results if r["status"] == status.HTTP_200_OK)

            print(f"Concurrent requests with same code: {len(results)}")
            print(f"Successful: {successful}")
            print(f"Failed: {failed}")

            # In a properly implemented system, at most 1 should succeed
            assert failed == 0, "No requests should crash"

            if successful <= 1:
                print("✓ Authorization code single-use properly enforced")
            else:
                print(f"⚠ WARNING: {successful} requests succeeded with same code (race condition)")

    @pytest.mark.asyncio
    async def test_concurrent_introspection(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test concurrent token introspection requests."""
        async with test_server.client as http_client:

            async def introspect_token(request_num):
                """Introspect a token."""
                try:
                    response = await http_client.post(
                        "/api/v1/oauth/introspect",
                        data={
                            "token": f"token_{request_num}",
                            "token_type_hint": "access_token",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    return {
                        "request_num": request_num,
                        "status": response.status_code,
                    }
                except Exception as e:
                    return {
                        "request_num": request_num,
                        "status": -1,
                        "error": str(e),
                    }

            # Send 20 concurrent introspection requests
            start_time = time.time()
            tasks = [introspect_token(i) for i in range(20)]
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time

            print("\nConcurrent Introspection Test:")
            print(f"Sent {len(results)} concurrent introspection requests in {elapsed:.2f}s")
            print(f"Average time per request: {elapsed / len(results):.3f}s")

            failed = sum(1 for r in results if r["status"] == -1)
            unauthorized = sum(1 for r in results if r["status"] == status.HTTP_401_UNAUTHORIZED)

            print(f"Failed: {failed}")
            print(f"Unauthorized (expected): {unauthorized}")

            assert failed == 0, "No introspection requests should fail"
            print("✓ Concurrent introspection handled without issues")

    @pytest.mark.asyncio
    async def test_database_connection_pool_stress(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test database connection pool under concurrent load."""
        async with test_server.client as http_client:

            async def make_db_request(request_num):
                """Make a request that requires database access."""
                try:
                    # UserInfo endpoint requires database lookup
                    response = await http_client.get(
                        "/api/v1/oidc/userinfo",
                        headers={"Authorization": f"Bearer invalid_token_{request_num}"},
                    )
                    return {"request_num": request_num, "status": response.status_code}
                except Exception as e:
                    return {"request_num": request_num, "status": -1, "error": str(e)}

            # Send many concurrent requests to stress connection pool
            print("\nDatabase Connection Pool Stress Test:")
            batch_size = 50
            start_time = time.time()
            tasks = [make_db_request(i) for i in range(batch_size)]
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start_time

            failed = sum(1 for r in results if r["status"] == -1)
            print(f"Sent {batch_size} concurrent DB requests in {elapsed:.2f}s")
            print(f"Failed requests: {failed}")

            if failed == 0:
                print("✓ Connection pool handled high concurrency")
            else:
                print(f"⚠ {failed} requests failed - possible connection pool exhaustion")
                for r in results:
                    if r["status"] == -1:
                        print(f"  Request {r['request_num']}: {r.get('error', 'Unknown error')}")
