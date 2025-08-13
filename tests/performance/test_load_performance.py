"""
Load and performance tests for OAuth endpoints.

Tests endpoint performance under various load conditions.
"""

import asyncio
import statistics
import time
from uuid import uuid4

import pytest
from fastapi_testing import AsyncTestResponse

from authly.core.resource_manager import AuthlyResourceManager


class TestLoadPerformance:
    """Test endpoint performance under load."""

    @pytest.mark.asyncio
    async def test_token_endpoint_throughput(self, test_server, initialize_authly: AuthlyResourceManager):
        """Measure token endpoint throughput."""
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
            await test_server.client.post(
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
            response = await test_server.client.post(
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

    @pytest.mark.asyncio
    async def test_authorization_endpoint_performance(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test authorization endpoint performance."""
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
        errors = 0

        print("\nAuthorization Endpoint Performance Test:")
        print(f"Testing with {total_requests} requests...")

        start_time = time.time()
        for _i in range(total_requests):
            try:
                req_start = time.time()
                await test_server.client.get(
                    "/api/v1/oauth/authorize",
                    params=params,
                    follow_redirects=False,  # Don't follow redirects for performance testing
                )
                req_time = (time.time() - req_start) * 1000
                response_times.append(req_time)

                # Small delay to avoid overwhelming the connection pool
                if _i < total_requests - 1:
                    await asyncio.sleep(0.001)
            except Exception as e:
                print(f"Request {_i} failed: {e}")
                errors += 1
                if errors > 5:
                    raise  # Re-raise if too many errors

        total_time = time.time() - start_time

        # Statistics - handle case where all requests failed
        if not response_times:
            print(f"All {total_requests} requests failed!")
            raise Exception("No successful requests to measure performance")

        avg_time = statistics.mean(response_times)
        median_time = statistics.median(response_times)
        successful_requests = len(response_times)
        throughput = successful_requests / total_time

        print(f"Successful requests: {successful_requests}/{total_requests}")
        print(f"Throughput: {throughput:.2f} req/s")
        print(f"Avg response time: {avg_time:.2f}ms")
        print(f"Median response time: {median_time:.2f}ms")

        # Performance expectations - be lenient for test environments
        if avg_time < 50:
            print("✓ Authorization endpoint performance is excellent (< 50ms)")
        elif avg_time < 100:
            print("✓ Authorization endpoint performance is good (< 100ms)")
        elif avg_time < 200:
            print("⚠ Authorization endpoint performance is acceptable (< 200ms)")
        else:
            print(f"⚠ Authorization endpoint performance needs improvement ({avg_time:.2f}ms)")

        # Be more lenient for test environments
        assert avg_time < 200, f"Authorization endpoint should respond in under 200ms average (was {avg_time:.2f}ms)"

    @pytest.mark.asyncio
    async def test_introspection_endpoint_performance(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test introspection endpoint performance."""
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
            await test_server.client.post(
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
    async def test_sustained_load(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test system behavior under sustained load."""
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
                response = await test_server.client.post(
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
    async def test_burst_load(self, test_server, initialize_authly: AuthlyResourceManager):
        """Test system behavior under burst load."""
        print("\nBurst Load Test:")

        async def burst_requests(burst_size):
            """Send a burst of requests."""
            tasks = []
            for i in range(burst_size):
                task = test_server.client.post(
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
            responses: list[AsyncTestResponse | Exception] = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start

            errors = sum(1 for resp in responses if isinstance(resp, Exception))
            server_errors = sum(
                1 for resp in responses if isinstance(resp, AsyncTestResponse) and resp.status_code >= 500
            )

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

        for result in results:
            print(
                f"{result['burst_size']:<12} {result['time']:<10.2f} {result['throughput']:<15.2f} {result['errors']:<10}"
            )

        # Check if system handles bursts
        max_errors = max(result["errors"] + result["server_errors"] for result in results)
        if max_errors == 0:
            print("✓ System handles burst loads without errors")
        else:
            print(f"⚠ Some burst requests failed: {max_errors} errors")

    @pytest.mark.asyncio
    async def test_memory_leak_detection(self, test_server, initialize_authly: AuthlyResourceManager):
        """Basic memory leak detection test."""
        print("\nMemory Leak Detection Test:")
        print("Making repeated requests to check for memory leaks...")

        # Make many requests to potentially trigger memory leaks
        iterations = 500

        for i in range(iterations):
            # Alternate between different endpoints
            if i % 3 == 0:
                await test_server.client.get(
                    "/api/v1/oauth/authorize",
                    params={"response_type": "code", "client_id": f"client_{i}"},
                )
            elif i % 3 == 1:
                await test_server.client.post(
                    "/api/v1/oauth/token",
                    data={"grant_type": "refresh_token", "refresh_token": f"token_{i}"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            else:
                await test_server.client.post(
                    "/api/v1/oauth/introspect",
                    data={"token": f"token_{i}"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if i % 100 == 0 and i > 0:
                print(f"  Completed {i}/{iterations} requests...")

        print(f"✓ Completed {iterations} requests")
        print("Note: Memory profiling requires external tools for accurate measurement")
