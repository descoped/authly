#!/usr/bin/env python3
"""
Performance testing script for admin operations.

This script tests the performance of optimized CTE-based admin queries implemented
in Increment 5.1 and compares them against legacy methods to verify improvements.
Designed for Greenfield project performance validation.
"""

import asyncio
import logging
import statistics
import sys
import time
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authly.core.config import get_config
from authly.core.database import create_database_connection
from authly.users.repository import UserRepository

logger = logging.getLogger(__name__)


class PerformanceTester:
    """Performance testing for admin operations."""

    def __init__(self):
        self.results = {}

    async def time_operation(self, operation_name: str, operation_func, iterations: int = 5) -> dict:
        """Time an operation multiple times and return statistics."""
        times = []

        logger.info(f"Testing {operation_name} ({iterations} iterations)...")

        for i in range(iterations):
            start_time = time.perf_counter()
            try:
                await operation_func()
                end_time = time.perf_counter()
                duration = (end_time - start_time) * 1000  # Convert to milliseconds
                times.append(duration)

                logger.debug(f"  Iteration {i + 1}: {duration:.2f}ms")
            except Exception as e:
                logger.error(f"Error in iteration {i + 1}: {e}")
                continue

        if not times:
            return {"error": "All iterations failed"}

        stats = {
            "min": min(times),
            "max": max(times),
            "mean": statistics.mean(times),
            "median": statistics.median(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
            "iterations": len(times),
            "times": times,
        }

        logger.info(
            f"{operation_name} results: "
            f"mean={stats['mean']:.2f}ms, "
            f"median={stats['median']:.2f}ms, "
            f"min={stats['min']:.2f}ms, "
            f"max={stats['max']:.2f}ms"
        )

        return stats

    async def test_user_counting(self, user_repo: UserRepository) -> dict:
        """Test user counting performance."""

        async def count_all_users():
            return await user_repo.count_filtered({})

        async def count_active_users():
            return await user_repo.count_filtered({"is_active": True})

        async def count_admin_users():
            return await user_repo.count_filtered({"is_admin": True})

        results = {}
        results["count_all"] = await self.time_operation("Count All Users", count_all_users)
        results["count_active"] = await self.time_operation("Count Active Users", count_active_users)
        results["count_admin"] = await self.time_operation("Count Admin Users", count_admin_users)

        return results

    async def test_user_listing_legacy(self, user_repo: UserRepository) -> dict:
        """Test legacy user listing (separate queries)."""

        async def legacy_listing():
            # Simulate the old approach: separate queries for data and count
            users = await user_repo.get_filtered_paginated({}, skip=0, limit=25)
            count = await user_repo.count_filtered({})
            return len(users), count

        async def legacy_filtered_listing():
            # Test with filters
            filters = {"is_active": True}
            users = await user_repo.get_filtered_paginated(filters, skip=0, limit=25)
            count = await user_repo.count_filtered(filters)
            return len(users), count

        results = {}
        results["legacy_basic"] = await self.time_operation("Legacy Basic Listing", legacy_listing)
        results["legacy_filtered"] = await self.time_operation("Legacy Filtered Listing", legacy_filtered_listing)

        return results

    async def test_user_listing_optimized(self, user_repo: UserRepository) -> dict:
        """Test optimized user listing (CTE queries)."""

        async def optimized_listing():
            # Use the new optimized method
            users, total_count, active_count = await user_repo.get_optimized_admin_listing({}, skip=0, limit=25)
            return len(users), total_count, active_count

        async def optimized_filtered_listing():
            # Test with filters
            filters = {"is_active": True}
            users, total_count, active_count = await user_repo.get_optimized_admin_listing(filters, skip=0, limit=25)
            return len(users), total_count, active_count

        async def optimized_complex_filters():
            # Test with complex filters
            filters = {"is_active": True, "username": "user_", "locale": "en-US"}
            users, total_count, active_count = await user_repo.get_optimized_admin_listing(filters, skip=0, limit=25)
            return len(users), total_count, active_count

        results = {}
        results["optimized_basic"] = await self.time_operation("Optimized Basic Listing", optimized_listing)
        results["optimized_filtered"] = await self.time_operation(
            "Optimized Filtered Listing", optimized_filtered_listing
        )
        results["optimized_complex"] = await self.time_operation("Optimized Complex Listing", optimized_complex_filters)

        return results

    async def test_user_details(self, user_repo: UserRepository) -> dict:
        """Test user details retrieval with session counts."""
        # Get a sample user ID first
        users = await user_repo.get_paginated(skip=0, limit=1)
        if not users:
            logger.warning("No users found for detail testing")
            return {"error": "No users available"}

        user_id = users[0].id

        async def get_user_with_sessions():
            return await user_repo.get_user_with_session_count(user_id)

        results = {}
        results["user_details"] = await self.time_operation("User Details with Sessions", get_user_with_sessions)

        return results

    async def test_pagination_performance(self, user_repo: UserRepository) -> dict:
        """Test pagination performance at different scales."""

        async def page_1():
            return await user_repo.get_optimized_admin_listing({}, skip=0, limit=25)

        async def page_10():
            return await user_repo.get_optimized_admin_listing({}, skip=225, limit=25)

        async def page_100():
            return await user_repo.get_optimized_admin_listing({}, skip=2475, limit=25)

        results = {}
        results["page_1"] = await self.time_operation("Page 1 (0-25)", page_1)
        results["page_10"] = await self.time_operation("Page 10 (225-250)", page_10)
        results["page_100"] = await self.time_operation("Page 100 (2475-2500)", page_100)

        return results

    def print_comparison_report(self, legacy_results: dict, optimized_results: dict):
        """Print a comparison report between legacy and optimized queries."""
        logger.info("\n" + "=" * 60)
        logger.info("PERFORMANCE COMPARISON REPORT")
        logger.info("=" * 60)

        # Compare basic listing
        if "legacy_basic" in legacy_results and "optimized_basic" in optimized_results:
            legacy_time = legacy_results["legacy_basic"]["mean"]
            optimized_time = optimized_results["optimized_basic"]["mean"]
            improvement = ((legacy_time - optimized_time) / legacy_time) * 100

            logger.info("\nBasic User Listing:")
            logger.info(f"  Legacy approach:   {legacy_time:.2f}ms")
            logger.info(f"  Optimized approach: {optimized_time:.2f}ms")
            logger.info(f"  Improvement:       {improvement:.1f}% faster")

        # Compare filtered listing
        if "legacy_filtered" in legacy_results and "optimized_filtered" in optimized_results:
            legacy_time = legacy_results["legacy_filtered"]["mean"]
            optimized_time = optimized_results["optimized_filtered"]["mean"]
            improvement = ((legacy_time - optimized_time) / legacy_time) * 100

            logger.info("\nFiltered User Listing:")
            logger.info(f"  Legacy approach:   {legacy_time:.2f}ms")
            logger.info(f"  Optimized approach: {optimized_time:.2f}ms")
            logger.info(f"  Improvement:       {improvement:.1f}% faster")

        logger.info("\n" + "=" * 60)

    def check_performance_targets(self, results: dict) -> bool:
        """Check if performance targets are met."""
        target_ms = 500  # Target: under 500ms
        failures = []

        logger.info(f"\nChecking performance targets (< {target_ms}ms):")

        for category, category_results in results.items():
            if isinstance(category_results, dict):
                for test_name, test_results in category_results.items():
                    if isinstance(test_results, dict) and "mean" in test_results:
                        mean_time = test_results["mean"]
                        status = "✓ PASS" if mean_time < target_ms else "✗ FAIL"
                        logger.info(f"  {category}.{test_name}: {mean_time:.2f}ms {status}")

                        if mean_time >= target_ms:
                            failures.append(f"{category}.{test_name}: {mean_time:.2f}ms")

        if failures:
            logger.warning(f"\nPerformance target failures ({len(failures)}):")
            for failure in failures:
                logger.warning(f"  - {failure}")
            return False
        else:
            logger.info("\n✓ All tests passed performance targets!")
            return True

    async def run_full_performance_test(self):
        """Run the complete performance test suite."""
        config = get_config()

        logger.info("Starting comprehensive performance tests...")
        start_time = time.time()

        async with create_database_connection(config.database_url) as conn:
            user_repo = UserRepository(conn)

            # Test user counting
            logger.info("\n--- Testing User Counting ---")
            counting_results = await self.test_user_counting(user_repo)

            # Test legacy listing
            logger.info("\n--- Testing Legacy User Listing ---")
            legacy_results = await self.test_user_listing_legacy(user_repo)

            # Test optimized listing
            logger.info("\n--- Testing Optimized User Listing ---")
            optimized_results = await self.test_user_listing_optimized(user_repo)

            # Test user details
            logger.info("\n--- Testing User Details ---")
            details_results = await self.test_user_details(user_repo)

            # Test pagination
            logger.info("\n--- Testing Pagination Performance ---")
            pagination_results = await self.test_pagination_performance(user_repo)

        # Combine all results
        all_results = {
            "counting": counting_results,
            "legacy": legacy_results,
            "optimized": optimized_results,
            "details": details_results,
            "pagination": pagination_results,
        }

        # Print comparison report
        self.print_comparison_report(legacy_results, optimized_results)

        # Check performance targets
        targets_met = self.check_performance_targets(all_results)

        end_time = time.time()
        total_duration = end_time - start_time

        logger.info(f"\nPerformance testing completed in {total_duration:.2f} seconds")

        return all_results, targets_met


async def main():
    """Main function."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(description="Performance testing for admin operations")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tester = PerformanceTester()
    results, targets_met = await tester.run_full_performance_test()

    return 0 if targets_met else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
