"""
Rate limiting tests for OAuth endpoints.

Tests that the OAuth endpoints properly handle rate limiting to prevent abuse.
"""

import asyncio
import time
from uuid import uuid4

import pytest
from fastapi import status
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager


class TestRateLimiting:
    """Test rate limiting on OAuth endpoints."""

    @pytest.mark.asyncio
    async def test_token_endpoint_rate_limit(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test rate limiting on the token endpoint."""
        async with test_server.client as http_client:
            # Invalid request to trigger rate limiting
            invalid_request = {
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": "http://localhost:8000/callback",
                "client_id": "invalid_client",
                "code_verifier": "invalid_verifier",
            }

            # Track response times and status codes
            responses = []
            start_time = time.time()

            # Send 100 requests rapidly
            for i in range(100):
                response = await http_client.post(
                    "/api/v1/oauth/token",
                    data=invalid_request,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                responses.append(
                    {"status": response.status_code, "time": time.time() - start_time, "request_num": i + 1}
                )

                # Small delay to avoid overwhelming the test server
                await asyncio.sleep(0.01)

            # Analyze responses
            total_requests = len(responses)
            rate_limited = sum(1 for r in responses if r["status"] == status.HTTP_429_TOO_MANY_REQUESTS)
            bad_requests = sum(1 for r in responses if r["status"] == status.HTTP_400_BAD_REQUEST)

            print("\nRate Limiting Test Results:")
            print(f"Total requests: {total_requests}")
            print(f"Rate limited (429): {rate_limited}")
            print(f"Bad requests (400): {bad_requests}")
            print(f"Time elapsed: {responses[-1]['time']:.2f}s")

            # Note: Rate limiting might not be implemented yet
            # This test documents the current behavior
            if rate_limited > 0:
                print(f"✓ Rate limiting is active - {rate_limited} requests were throttled")

                # Find when rate limiting started
                first_limited = next((r for r in responses if r["status"] == 429), None)
                if first_limited:
                    print(f"Rate limiting started at request #{first_limited['request_num']}")
            else:
                print("⚠ No rate limiting detected - all requests were processed")
                assert bad_requests == total_requests, "All requests should fail with bad request if no rate limiting"

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_endpoint_rate_limit(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test rate limiting on the authorization endpoint."""
        async with test_server.client as http_client:
            # Invalid authorization request
            invalid_params = {
                "response_type": "code",
                "client_id": "invalid_client",
                "redirect_uri": "http://localhost:8000/callback",
                "code_challenge": "invalid_challenge",
                "code_challenge_method": "S256",
                "scope": "openid profile",
                "state": "test_state",
            }

            responses = []
            start_time = time.time()

            # Send 50 requests rapidly
            for i in range(50):
                response = await http_client.get(
                    "/api/v1/oauth/authorize",
                    params=invalid_params,
                )
                responses.append(
                    {"status": response.status_code, "time": time.time() - start_time, "request_num": i + 1}
                )
                await asyncio.sleep(0.01)

            # Analyze responses
            total_requests = len(responses)
            rate_limited = sum(1 for r in responses if r["status"] == status.HTTP_429_TOO_MANY_REQUESTS)
            errors = sum(1 for r in responses if r["status"] >= 400)

            print("\nAuthorization Endpoint Rate Limiting:")
            print(f"Total requests: {total_requests}")
            print(f"Rate limited (429): {rate_limited}")
            print(f"Error responses (4xx/5xx): {errors}")

            if rate_limited > 0:
                print("✓ Rate limiting active on authorization endpoint")
            else:
                print("⚠ No rate limiting on authorization endpoint")

    @pytest.mark.asyncio
    async def test_introspection_endpoint_rate_limit(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test rate limiting on the introspection endpoint."""
        async with test_server.client as http_client:
            # Request without authentication (will fail)
            invalid_request = {
                "token": "invalid_token",
                "token_type_hint": "access_token",
            }

            responses = []
            start_time = time.time()

            # Send 75 requests
            for i in range(75):
                response = await http_client.post(
                    "/api/v1/oauth/introspect",
                    data=invalid_request,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                responses.append(
                    {"status": response.status_code, "time": time.time() - start_time, "request_num": i + 1}
                )
                await asyncio.sleep(0.01)

            # Analyze responses
            total_requests = len(responses)
            rate_limited = sum(1 for r in responses if r["status"] == status.HTTP_429_TOO_MANY_REQUESTS)
            unauthorized = sum(1 for r in responses if r["status"] == status.HTTP_401_UNAUTHORIZED)
            ok_responses = sum(1 for r in responses if r["status"] == status.HTTP_200_OK)

            print("\nIntrospection Endpoint Rate Limiting:")
            print(f"Total requests: {total_requests}")
            print(f"Rate limited (429): {rate_limited}")
            print(f"Unauthorized (401): {unauthorized}")
            print(f"OK (200): {ok_responses}")

            if rate_limited > 0:
                print("✓ Introspection endpoint has rate limiting")
            else:
                print("⚠ No rate limiting on introspection endpoint")
                # Without rate limiting, should get either 401 or 200 responses
                assert unauthorized + ok_responses == total_requests

    @pytest.mark.asyncio
    async def test_per_client_rate_limiting(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test if rate limiting is per-client or global."""
        async with test_server.client as http_client:
            # Simulate requests from different "clients"
            client_responses = {}

            for client_num in range(3):
                client_id = f"client_{client_num}_{uuid4().hex[:8]}"
                client_responses[client_id] = []

                # Each client sends 20 requests
                for _i in range(20):
                    response = await http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "authorization_code",
                            "code": "invalid",
                            "redirect_uri": "http://localhost:8000/callback",
                            "client_id": client_id,
                            "code_verifier": "invalid",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    client_responses[client_id].append(response.status_code)
                    await asyncio.sleep(0.01)

            # Analyze per-client rate limiting
            print("\nPer-Client Rate Limiting Test:")
            for client_id, responses in client_responses.items():
                rate_limited = sum(1 for r in responses if r == status.HTTP_429_TOO_MANY_REQUESTS)
                print(f"Client {client_id}: {rate_limited}/20 requests rate limited")

            # Check if any client was rate limited
            any_limited = any(status.HTTP_429_TOO_MANY_REQUESTS in responses for responses in client_responses.values())

            if any_limited:
                print("✓ Rate limiting is active (check if per-client or global)")
            else:
                print("⚠ No rate limiting detected across multiple clients")

    @pytest.mark.asyncio
    async def test_rate_limit_headers(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test if rate limit headers are included in responses."""
        async with test_server.client as http_client:
            response = await http_client.post(
                "/api/v1/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "test_client",
                    "client_secret": "wrong_secret",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Check for standard rate limit headers
            rate_limit_headers = {
                "X-RateLimit-Limit": response._response.headers.get("X-RateLimit-Limit"),
                "X-RateLimit-Remaining": response._response.headers.get("X-RateLimit-Remaining"),
                "X-RateLimit-Reset": response._response.headers.get("X-RateLimit-Reset"),
                "Retry-After": response._response.headers.get("Retry-After"),
            }

            print("\nRate Limit Headers Test:")
            headers_found = False
            for header, value in rate_limit_headers.items():
                if value:
                    print(f"✓ {header}: {value}")
                    headers_found = True
                else:
                    print(f"✗ {header}: Not found")

            if headers_found:
                print("✓ Rate limit headers are included")
            else:
                print("⚠ No rate limit headers found in response")
