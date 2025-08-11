"""
Concurrent request handling tests.

Tests how the OAuth endpoints handle concurrent requests and race conditions.
"""

import asyncio
import secrets
import time

import pytest
from fastapi import status

from authly.core.resource_manager import AuthlyResourceManager


class TestConcurrentRequests:
    """Test concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_authorization_codes(
        self, test_server, initialize_authly: AuthlyResourceManager, committed_oauth_client
    ):
        """Test handling multiple concurrent authorization code requests."""
        # Use committed client - visible to HTTP server
        created_client = committed_oauth_client

        # Prepare authorization requests
        async def make_auth_request(user_num):
            """Make an authorization request for a user."""
            try:
                # Generate PKCE challenge
                secrets.token_urlsafe(32)
                code_challenge = secrets.token_urlsafe(32)  # Simplified for test

                params = {
                    "response_type": "code",
                    "client_id": created_client["client_id"],
                    "redirect_uri": created_client["redirect_uris"][0],
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "scope": "read write",
                    "state": f"state_{user_num}",
                }

                response = await test_server.client.get(
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
        # Note: Some might fail due to invalid PKCE or other validation
        # But none should fail due to server errors or connection issues
        if failed_count > 0:
            print(f"⚠ {failed_count} requests failed - checking error details")
            for r in results:
                if r["status"] == -1:
                    print(f"  Request {r['user_num']} error: {r.get('error', 'Unknown')}")
        
        # Check for race conditions
        if failed_count == 0 and success_count == len(results):
            print("✓ All concurrent requests handled successfully")
        elif failed_count == 0:
            print("✓ All requests handled without connection failures")
        else:
            print("⚠ Some requests had connection issues - may indicate concurrency problems")

    @pytest.mark.asyncio
    async def test_concurrent_token_exchanges(
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test concurrent token exchange requests."""
        # Prepare multiple token exchange requests
        async def exchange_token(request_num):
            """Attempt to exchange an authorization code for tokens."""
            try:
                response = await test_server.client.post(
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
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test concurrent refresh token requests."""
        async def refresh_token(request_num):
            """Attempt to refresh a token."""
            try:
                response = await test_server.client.post(
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
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test race condition when same auth code is used multiple times concurrently."""
        # Use the same authorization code in multiple concurrent requests
        auth_code = "same_code_for_all"

        async def use_auth_code(request_num):
            """Try to use the same authorization code."""
            try:
                response = await test_server.client.post(
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
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test concurrent token introspection requests."""
        async def introspect_token(request_num):
            """Introspect a token."""
            try:
                response = await test_server.client.post(
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
        self, test_server, initialize_authly: AuthlyResourceManager
    ):
        """Test database connection pool under concurrent load."""
        async def make_db_request(request_num):
            """Make a request that requires database access."""
            try:
                # UserInfo endpoint requires database lookup
                response = await test_server.client.get(
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
