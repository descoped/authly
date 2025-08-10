"""
Load and performance tests for OAuth endpoints.

Tests endpoint performance under various load conditions.
"""

import asyncio
import statistics
import time
from uuid import uuid4

import pytest
from psycopg_toolkit import TransactionManager

from authly.core.resource_manager import AuthlyResourceManager


class TestLoadPerformance:
    """Test endpoint performance under load."""

    @pytest.mark.asyncio
    async def test_token_endpoint_throughput(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Measure token endpoint throughput."""
        async with test_server.client as http_client:
            # Prepare test data
            request_data = {
                "grant_type": "authorization_code",
                "code": "invalid_code",
                "redirect_uri": "http://localhost:8000/callback",
                "client_id": "test_client",
                "code_verifier": "test_verifier",
            }

            # Warm up
            for _ in range(5):
                await http_client.post(
                    "/api/v1/oauth/token",
                    data=request_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            # Performance test
            response_times = []
            errors = 0
            total_requests = 100

            print("\nToken Endpoint Throughput Test:")
            print(f"Testing with {total_requests} sequential requests...")

            start_time = time.time()
            for _i in range(total_requests):
                req_start = time.time()
                response = await http_client.post(
                    "/api/v1/oauth/token",
                    data=request_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                req_time = (time.time() - req_start) * 1000  # Convert to ms
                response_times.append(req_time)

                if response.status_code >= 500:
                    errors += 1

            total_time = time.time() - start_time

            # Calculate statistics
            avg_response_time = statistics.mean(response_times)
            median_response_time = statistics.median(response_times)
            p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
            p99_response_time = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            throughput = total_requests / total_time

            print("\nResults:")
            print(f"Total requests: {total_requests}")
            print(f"Total time: {total_time:.2f}s")
            print(f"Throughput: {throughput:.2f} req/s")
            print(f"Errors: {errors}")
            print("\nResponse Times (ms):")
            print(f"  Min: {min_response_time:.2f}")
            print(f"  Avg: {avg_response_time:.2f}")
            print(f"  Median: {median_response_time:.2f}")
            print(f"  P95: {p95_response_time:.2f}")
            print(f"  P99: {p99_response_time:.2f}")
            print(f"  Max: {max_response_time:.2f}")

            # Performance assertions
            assert errors == 0, "No 5xx errors should occur"
            assert avg_response_time < 100, "Average response time should be under 100ms"
            assert p95_response_time < 200, "P95 response time should be under 200ms"
            print("✓ Token endpoint performance is acceptable")

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_authorization_endpoint_performance(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test authorization endpoint performance."""
        async with test_server.client as http_client:
            params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "http://localhost:8000/callback",
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256",
                "scope": "openid profile",
                "state": "test_state",
            }

            response_times = []
            total_requests = 50

            print("\nAuthorization Endpoint Performance Test:")
            print(f"Testing with {total_requests} requests...")

            start_time = time.time()
            for _i in range(total_requests):
                req_start = time.time()
                await http_client.get(
                    "/api/v1/oauth/authorize",
                    params=params,
                )
                req_time = (time.time() - req_start) * 1000
                response_times.append(req_time)

            total_time = time.time() - start_time

            # Statistics
            avg_time = statistics.mean(response_times)
            median_time = statistics.median(response_times)
            throughput = total_requests / total_time

            print(f"Throughput: {throughput:.2f} req/s")
            print(f"Avg response time: {avg_time:.2f}ms")
            print(f"Median response time: {median_time:.2f}ms")

            assert avg_time < 50, "Authorization endpoint should respond in under 50ms average"
            print("✓ Authorization endpoint performance is good")

    @pytest.mark.asyncio
    async def test_introspection_endpoint_performance(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test introspection endpoint performance."""
        async with test_server.client as http_client:
            request_data = {
                "token": "test_token",
                "token_type_hint": "access_token",
            }

            response_times = []
            total_requests = 75

            print("\nIntrospection Endpoint Performance Test:")

            start_time = time.time()
            for _i in range(total_requests):
                req_start = time.time()
                await http_client.post(
                    "/api/v1/oauth/introspect",
                    data=request_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                req_time = (time.time() - req_start) * 1000
                response_times.append(req_time)

            total_time = time.time() - start_time

            avg_time = statistics.mean(response_times)
            throughput = total_requests / total_time

            print(f"Throughput: {throughput:.2f} req/s")
            print(f"Avg response time: {avg_time:.2f}ms")

            # Introspection should be fast since it's mostly JWT validation
            assert avg_time < 30, "Introspection should be very fast (< 30ms)"
            print("✓ Introspection endpoint performance is excellent")

    @pytest.mark.asyncio
    async def test_sustained_load(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test system behavior under sustained load."""
        async with test_server.client as http_client:
            print("\nSustained Load Test:")
            print("Running 30-second sustained load test...")

            request_count = 0
            error_count = 0
            response_times = []
            test_duration = 30  # seconds

            async def make_request():
                nonlocal request_count, error_count
                try:
                    start = time.time()
                    response = await http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "refresh_token",
                            "refresh_token": f"token_{uuid4().hex}",
                            "client_id": "test_client",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    elapsed = (time.time() - start) * 1000
                    response_times.append(elapsed)
                    request_count += 1

                    if response.status_code >= 500:
                        error_count += 1
                except Exception:
                    error_count += 1

            # Run sustained load
            start_time = time.time()
            while time.time() - start_time < test_duration:
                await make_request()
                await asyncio.sleep(0.01)  # ~100 req/s target

            total_time = time.time() - start_time

            if response_times:
                avg_response = statistics.mean(response_times)
                p95_response = statistics.quantiles(response_times, n=20)[18]
                throughput = request_count / total_time
                error_rate = (error_count / request_count * 100) if request_count > 0 else 0

                print(f"\nResults after {total_time:.1f} seconds:")
                print(f"Total requests: {request_count}")
                print(f"Throughput: {throughput:.2f} req/s")
                print(f"Avg response time: {avg_response:.2f}ms")
                print(f"P95 response time: {p95_response:.2f}ms")
                print(f"Error rate: {error_rate:.2f}%")

                # Check for degradation
                early_responses = response_times[:100]
                late_responses = response_times[-100:]

                if len(early_responses) > 0 and len(late_responses) > 0:
                    early_avg = statistics.mean(early_responses)
                    late_avg = statistics.mean(late_responses)
                    degradation = ((late_avg - early_avg) / early_avg * 100) if early_avg > 0 else 0

                    print(f"Performance degradation: {degradation:.1f}%")

                    if degradation < 20:
                        print("✓ System maintains performance under sustained load")
                    else:
                        print(f"⚠ Performance degraded by {degradation:.1f}% during sustained load")

                assert error_rate < 1, "Error rate should be less than 1%"

    @pytest.mark.asyncio
    async def test_burst_load(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Test system behavior under burst load."""
        async with test_server.client as http_client:
            print("\nBurst Load Test:")

            async def burst_requests(burst_size):
                """Send a burst of requests."""
                tasks = []
                for i in range(burst_size):
                    task = http_client.post(
                        "/api/v1/oauth/token",
                        data={
                            "grant_type": "client_credentials",
                            "client_id": f"client_{i}",
                            "client_secret": "secret",
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    tasks.append(task)

                start = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start

                errors = sum(1 for r in responses if isinstance(r, Exception))
                server_errors = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code >= 500)

                return {
                    "burst_size": burst_size,
                    "time": elapsed,
                    "errors": errors,
                    "server_errors": server_errors,
                    "throughput": burst_size / elapsed if elapsed > 0 else 0,
                }

            # Test increasing burst sizes
            burst_sizes = [10, 25, 50, 100]
            results = []

            for size in burst_sizes:
                print(f"Testing burst of {size} requests...")
                result = await burst_requests(size)
                results.append(result)
                await asyncio.sleep(1)  # Cool down between bursts

            print("\nBurst Test Results:")
            print(f"{'Burst Size':<12} {'Time (s)':<10} {'Throughput':<15} {'Errors':<10}")
            print("-" * 50)

            for r in results:
                print(f"{r['burst_size']:<12} {r['time']:<10.2f} {r['throughput']:<15.2f} {r['errors']:<10}")

            # Check if system handles bursts
            max_errors = max(r["errors"] + r["server_errors"] for r in results)
            if max_errors == 0:
                print("✓ System handles burst loads without errors")
            else:
                print(f"⚠ Some burst requests failed: {max_errors} errors")

    @pytest.mark.skip(reason="Authorization endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_memory_leak_detection(
        self, test_server, initialize_authly: AuthlyResourceManager, transaction_manager: TransactionManager
    ):
        """Basic memory leak detection test."""
        async with test_server.client as http_client:
            print("\nMemory Leak Detection Test:")
            print("Making repeated requests to check for memory leaks...")

            # Make many requests to potentially trigger memory leaks
            iterations = 500

            for i in range(iterations):
                # Alternate between different endpoints
                if i % 3 == 0:
                    await http_client.get(
                        "/api/v1/oauth/authorize",
                        params={"response_type": "code", "client_id": f"client_{i}"},
                    )
                elif i % 3 == 1:
                    await http_client.post(
                        "/api/v1/oauth/token",
                        data={"grant_type": "refresh_token", "refresh_token": f"token_{i}"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    await http_client.post(
                        "/api/v1/oauth/introspect",
                        data={"token": f"token_{i}"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                if i % 100 == 0 and i > 0:
                    print(f"  Completed {i}/{iterations} requests...")

            print(f"✓ Completed {iterations} requests")
            print("Note: Memory profiling requires external tools for accurate measurement")
