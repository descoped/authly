# OAuth 2.1 Test Compliance Planning Document

## Scope

During the process of removing the password grant and client credentials for strict OAuth 2.1 compliance, we marked non-compliant test cases with `@pytest.mark.skip`. 

### Objectives
- Analyze each skipped test in pytest
- Follow rules and conventions for Authly `.claude/instructions/authly-development-practices.md`
- Always read the implementation under `src/` and follow Authly's coding standards
- Read source code for package dependencies under `.venv/lib/python3.11/site-packages/` when needed to fully understand contracts
- If a test is determined to be out of scope, remove the test after user confirmation

## Workflow

The workflow for each test must follow these steps:

1. **Evaluate** - Determine if the test is within the scope of Authly
2. **Adapt** - If in scope, modify the test to use OAuth 2.1 + PKCE compliant flow
3. **Test** - Verify that changes work correctly
4. **Update** - Update status in this document
5. **Confirm** - Ask the user for confirmation (user performs manual testing to read the code and verify correctness)
6. **Proceed** - Move on to the next task

## Todo List

The following tests need to be addressed. Each item must be processed according to the workflow above.

### Admin Portal Tests

#### Password Grant Removal
- [ ] `tests/admin_portal/test_admin_api_client.py:164` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/admin_portal/test_admin_api_client.py:205` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/admin_portal/test_admin_api_client.py:231` - Password grant removed for OAuth 2.1 compliance

#### Admin Access Token Fixture Dependencies
- [ ] `tests/admin_portal/test_admin_api_client.py:279` - Depends on admin_access_token fixture which uses password grant
- [ ] `tests/admin_portal/test_admin_api_client.py:309` - Depends on admin_access_token fixture which uses password grant

### Auth User Journey Tests

#### Password Grant Removal
- [ ] `tests/auth_user_journey/test_auth_api.py:96` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:110` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:129` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:143` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:171` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:192` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:223` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:261` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/auth_user_journey/test_auth_api.py:294` - Password grant removed for OAuth 2.1 compliance

#### Token Revocation Tests
- [ ] `tests/auth_user_journey/test_token_revocation.py:68` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:84` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:100` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:113` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:126` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:138` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:159` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:184` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:216` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:231` - valid_tokens fixture uses password grant - needs conversion to auth code flow
- [ ] `tests/auth_user_journey/test_token_revocation.py:245` - valid_tokens fixture uses password grant - needs conversion to auth code flow

### OAuth Flows Tests

#### Complete Auth Flows
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:30` - Password grant removed for OAuth 2.1 compliance - needs conversion to auth code flow
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:97` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:163` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:318` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:438` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:528` - Password grant removed for OAuth 2.1 compliance
- [ ] `tests/oauth_flows/test_complete_auth_flows.py:574` - Password grant removed for OAuth 2.1 compliance

#### OAuth Dependencies - Client Credentials Removal
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:63` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:82` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:99` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:119` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:139` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:213` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:234` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:251` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:298` - client_credentials grant type removed in OAuth 2.1
- [ ] `tests/oauth_flows/test_oauth_dependencies.py:349` - client_credentials grant type removed in OAuth 2.1

#### PKCE Compliance
- [ ] `tests/oauth_flows/test_pkce_compliance.py:229` - Password grant removed for OAuth 2.1 compliance

### OIDC Features Tests

- [ ] `tests/oidc_features/test_oidc_compliance.py:79` - Client credentials flow not available
- [ ] `tests/oidc_features/test_oidc_compliance.py:127` - Requires user auth - ID token validation covered by `test_jwt_security.py::test_id_token_validation`
- [ ] `tests/oidc_features/test_oidc_compliance.py:249` - Requires user auth - scope-based claims tested at service layer in other tests

### Security Tests

- [ ] `tests/security/test_pkce_security.py:76` - Requires user auth - covered by `test_oauth_authorization.py::test_exchange_authorization_code_invalid_pkce`
- [ ] `tests/security/test_pkce_security.py:145` - Requires user auth - PKCE security covered by `test_oauth_authorization.py` and `test_pkce_compliance.py`

## Status Tracking

### Summary
- **Total Tests to Review**: 46
- **Completed**: 0
- **In Progress**: 0
- **Pending**: 46

### Categories
- **Password Grant Removal**: 24 tests
- **Client Credentials Removal**: 10 tests
- **Fixture Dependencies**: 11 tests
- **Other Compliance Issues**: 5 tests

## Notes

- Do not change the `src/` implementation, only focus on test compliance
- Some tests may be duplicates or already covered by other tests (marked in descriptions)
- Tests that are out of scope should be removed only after user confirmation
- All modifications must maintain OAuth 2.1 + PKCE compliance
