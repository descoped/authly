#!/usr/bin/env python
"""Check test results summary."""

import subprocess
import sys


def run_tests():
    """Run tests and extract summary."""
    print("Running test suite...")
    result = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v", "--tb=no", "-q"], capture_output=True, text=True, timeout=400
    )

    # Get the last line with summary
    lines = result.stdout.strip().split("\n")
    for line in reversed(lines):
        if "passed" in line or "failed" in line:
            print(f"\nTest Summary: {line}")

            # Parse the summary
            if "failed" in line and "0 failed" not in line:
                print("\n⚠️  Some tests are still failing!")
                return 1
            elif "100%" in line or ("failed" not in line and "passed" in line):
                print("\n✅ All tests passing!")
                return 0
            break

    # If we get here, couldn't parse results
    print("\nCould not parse test results. Full output:")
    print(result.stdout[-500:])  # Last 500 chars
    return 1


if __name__ == "__main__":
    sys.exit(run_tests())
