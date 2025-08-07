# Rename Integration Tests to E2E Tests

## Issue
Currently using "integration tests" for two different test types:
1. **Pytest integration tests** in `tests/` - Internal component testing
2. **Bash/curl integration tests** in `scripts/integration-tests/` - External API testing

This naming overlap causes confusion.

## Proposed Solution
Rename `scripts/integration-tests/` to `scripts/e2e-tests/` (End-to-End Tests)

## Rationale
- E2E tests clearly indicate testing from external client perspective
- Distinguishes from internal pytest integration tests
- Better describes what these tests do: complete flow testing via HTTP/curl

## Changes Required
1. Rename directory: `scripts/integration-tests/` → `scripts/e2e-tests/`
2. Update all script references to the new path
3. Update GitHub workflows that reference integration tests
4. Update documentation mentioning integration test scripts
5. Update `scripts/run-integration-tests.sh` → `scripts/run-e2e-tests.sh`

## Files to Update
- `.github/workflows/build-test-with-docker.yml`
- `.github/workflows/full-stack-test-with-docker.yml`
- `.github/workflows/release-pypi.yml`
- `scripts/run-integration-tests.sh`
- All scripts that source from `integration-tests/`
- Any documentation referencing the test scripts

## Priority
Medium - This is a clarity/maintenance improvement, not blocking functionality