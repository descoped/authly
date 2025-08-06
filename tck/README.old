# Authly OIDC Technology Compatibility Kit (TCK)

This directory contains the OpenID Connect conformance test suite for validating Authly's OIDC implementation against the official OpenID Foundation specifications.

## Overview

The TCK provides automated conformance testing for:
- OpenID Connect Core 1.0
- OpenID Connect Session Management 1.0
- OpenID Connect Front-Channel Logout 1.0
- OAuth 2.1 authorization flows with PKCE

## Directory Structure

```
tck/
├── config/          # Conformance suite configuration files
├── docker/          # Docker Compose setup for conformance suite
├── scripts/         # Automation scripts for running tests
├── tests/           # Integration tests and validation scripts
├── docs/            # Additional documentation and guides
└── results/         # Test results and conformance reports
```

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Python 3.11+ with uv package manager
- Git (for cloning conformance suite)
- 4GB+ available RAM (for conformance suite)

### Fastest Setup (Recommended) - Integrated Stack

Start Authly with the conformance suite in one command:
```bash
# From project root
./scripts/start-with-tck.sh
```

This script will:
1. Build the conformance suite JAR if needed
2. Start PostgreSQL, Redis, and Authly
3. Start the conformance suite (MongoDB, server, HTTPD)
4. Create the OIDC test client automatically
5. Wait for all services to be healthy
6. Display all service URLs and credentials

Access the services:
- **Authly API**: http://localhost:8000
- **Conformance Suite**: https://localhost:8443
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

### Manual Setup

### Running Conformance Tests

1. **Start Authly Server with Docker Compose**:
```bash
# From project root
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Wait for services to be healthy
sleep 10

# Verify Authly is running
curl -s http://localhost:8000/health | jq .
```

2. **Initialize Test Environment**:
```bash
cd tck
./scripts/init-tck.sh
```

3. **Create Test Client in Authly**:
```bash
# Using direct SQL (recommended for testing)
cat > /tmp/create_test_client.sql << 'EOF'
INSERT INTO oauth_clients (
    client_id, client_name, client_type, client_secret_hash,
    redirect_uris, grant_types, response_types, scope,
    require_pkce, is_active, application_type,
    token_endpoint_auth_method, id_token_signed_response_alg, subject_type
) VALUES (
    'oidc-conformance-test',
    'OIDC Conformance Test Client',
    'confidential',
    '$2b$12$K4Y4RR5YlF5uBN2H7fP3YuHj6FKThQBqQqZeD/YMBZZIxZLH2Ejha', -- 'conformance-test-secret'
    ARRAY['https://localhost:8443/test/a/authly/callback',
          'https://localhost:8443/test/a/authly/callback/implicit',
          'https://localhost:8443/test/a/authly/callback/hybrid']::text[],
    ARRAY['authorization_code', 'refresh_token', 'implicit']::text[],
    ARRAY['code', 'code id_token', 'code token', 'code id_token token', 
          'id_token', 'id_token token', 'token']::text[],
    'openid profile email phone address',
    true, true, 'web', 'client_secret_basic', 'RS256', 'public'
) ON CONFLICT (client_id) DO UPDATE SET
    redirect_uris = EXCLUDED.redirect_uris,
    grant_types = EXCLUDED.grant_types,
    response_types = EXCLUDED.response_types,
    scope = EXCLUDED.scope;
EOF

docker compose exec -T postgres psql -U authly -d authly < /tmp/create_test_client.sql
```

4. **Run Python Integration Tests**:
```bash
# From tck directory
pytest tests/test_oidc_conformance.py -v
```

5. **Build and Start Conformance Suite**:

The OpenID conformance suite needs to be built from source:

```bash
# Clone the conformance suite repository
git clone https://gitlab.com/openid/conformance-suite.git conformance-suite
cd conformance-suite

# Build the JAR using Maven in Docker
docker run --rm -v "$PWD":/usr/src/mymaven -v "$HOME/.m2":/root/.m2 \
  -w /usr/src/mymaven maven:3-eclipse-temurin-17 \
  mvn -B clean package -DskipTests=true

# Start the conformance suite containers
docker compose up -d

# Access the web UI at https://localhost:8443
open https://localhost:8443
```

The conformance suite will be available at:
- Web UI: https://localhost:8443
- MongoDB: localhost:27017 (internal)
- Server: Running on port 8080 (internal)

6. **View Results**:
```bash
# For Python tests
pytest tests/test_oidc_conformance.py -v --tb=short

# For conformance suite results
./scripts/view-results.sh
```

## Test Profiles

### Basic Certification Profile
- Authorization Code Flow with PKCE
- ID Token validation
- UserInfo endpoint verification
- JWKS key validation

### Advanced Profiles
- Implicit Flow (legacy compatibility)
- Hybrid Flow
- Session Management
- Front-Channel Logout

## Configuration

### Test Client Configuration
The default test client is configured in `config/test-client.json`:
- Client ID: `oidc-conformance-test`
- Client Type: Confidential
- Grant Types: authorization_code, refresh_token
- Response Types: code
- Scopes: openid, profile, email, phone, address

### Authly Server Configuration
Required Authly settings for conformance testing:
- CORS enabled for conformance suite URLs
- RS256 algorithm for JWT signing
- All OIDC endpoints accessible

## Test Execution

### Automated Testing
```bash
# Run all conformance tests
./scripts/run-all-tests.sh

# Run specific test profile
./scripts/run-test.sh --profile basic
./scripts/run-test.sh --profile session-management
```

### Manual Testing
1. Start conformance suite UI: `./scripts/start-suite.sh`
2. Access web interface: `https://localhost:8443`
3. Create test plan with Authly configuration
4. Execute tests and review results

## Results Analysis

### Conformance Reports
Versioned conformance reports are stored in `conformance-reports/`:
- Naming: `CONFORMANCE_STATUS_v{XXX}_{date}_{tag}.md`
- Fix summaries: `FIX_SUMMARY_v{XXX}_{date}.md`
- See [conformance-reports/README.md](./conformance-reports/README.md) for version history

### Test Results
Test results are stored in `results/` with timestamps:
- `results/YYYY-MM-DD/conformance-report.json`
- `results/YYYY-MM-DD/test-logs.txt`
- `results/YYYY-MM-DD/summary.md`

### Interpreting Results
- ✅ **PASS**: Authly fully complies with specification
- ⚠️ **WARNING**: Minor issues that don't affect compliance
- ❌ **FAIL**: Non-compliance requiring fixes

## Current Compliance Status

### Implemented and Passing ✅
- OpenID Connect Core 1.0
- Session Management 1.0
- Front-Channel Logout 1.0
- OAuth 2.1 with PKCE

### Not Yet Implemented ⚠️
- Back-Channel Logout 1.0
- Dynamic Client Registration

## Development Workflow

### Conformance Testing Workflow

**IMPORTANT**: Follow the standardized workflow for fixing conformance issues:

📋 **See [CONFORMANCE_WORKFLOW.md](./CONFORMANCE_WORKFLOW.md)** for the complete workflow including:
- Issue identification process
- Test-first development approach
- Unit test validation before TCK
- Documentation and versioning standards
- Fix patterns and best practices

**Key Workflow Steps**:
1. Generate conformance report to identify issues
2. Write tests for expected behavior FIRST
3. Implement fixes in code
4. Validate with unit tests (must be 100% passing)
5. Run TCK conformance verification
6. Document fixes with proper versioning

### Integrated Stack Management

**Start everything (Authly + Conformance Suite):**
```bash
./scripts/start-with-tck.sh
```

**Stop everything:**
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml down
```

**View logs:**
```bash
# All services
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml logs -f

# Just Authly
docker compose logs -f authly

# Just conformance suite
docker compose logs -f tck-server
```

**Restart a specific service:**
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml restart authly
```

### Testing Workflow

1. **Make Changes**: Implement OIDC features in Authly
2. **Restart Authly**: `docker compose restart authly`
3. **Run Tests**: Use conformance suite web UI or Python tests
4. **Review Results**: Analyze failures in the web UI
5. **Fix Issues**: Address non-compliance
6. **Repeat**: Until all tests pass
5. **Validate**: Re-run tests to confirm fixes

## Troubleshooting

### Common Issues

**CORS Errors**:
- Ensure Authly allows conformance suite origins
- Check `CORS_ORIGINS` configuration

**Discovery Failures**:
- Verify `/.well-known/openid_configuration` accessibility
- Check endpoint URLs are absolute

**Client Authentication Issues**:
- Confirm client credentials match
- Verify client_type configuration

**Token Validation Errors**:
- Check JWKS endpoint accessibility
- Verify RSA key format (RS256)

## Contributing

When adding new OIDC features:
1. Update test client configuration if needed
2. Add corresponding conformance test profiles
3. Document any special configuration requirements
4. Update this README with new test coverage

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Conformance Suite](https://gitlab.com/openid/conformance-suite)
- [Certification Process](https://openid.net/certification/)
- [Authly OIDC Documentation](../docs/oidc-implementation.md)

## Support

For issues or questions about the TCK:
- Check the [troubleshooting guide](docs/troubleshooting.md)
- Review [Authly OIDC implementation](../docs/oidc-implementation.md)
- Open an issue in the project repository