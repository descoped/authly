"""
TCK (Test Conformance Kit) Tests

These tests are specifically for OIDC/OAuth conformance testing and require
the TCK docker-compose stack to be running. They are excluded from the main
test suite by default.

To run TCK tests:
1. Start the TCK stack: docker-compose -f tck/docker-compose.yml up -d
2. Run tests: pytest tests/tck/ -m tck
"""
