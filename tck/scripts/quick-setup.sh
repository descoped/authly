#!/bin/bash
# Quick setup script for OIDC TCK
# This script automates the entire setup process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Authly OIDC TCK Quick Setup             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Change to project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TCK_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$TCK_DIR")"

cd "$PROJECT_ROOT"

echo -e "${YELLOW}Step 1: Starting Authly with Docker Compose...${NC}"
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

echo -e "${YELLOW}Step 2: Waiting for services to be healthy...${NC}"
for i in {1..30}; do
    if curl -f -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Authly is healthy${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo -e "${YELLOW}Step 3: Creating test client in database...${NC}"
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
    '$2b$12$K4Y4RR5YlF5uBN2H7fP3YuHj6FKThQBqQqZeD/YMBZZIxZLH2Ejha',
    ARRAY['https://localhost:8443/test/a/authly/callback',
          'https://localhost:8443/test/a/authly/callback/implicit',
          'https://localhost:8443/test/a/authly/callback/hybrid']::text[],
    ARRAY['authorization_code', 'refresh_token', 'implicit']::text[],
    ARRAY['code', 'code id_token', 'code token', 'code id_token token', 
          'id_token', 'id_token token', 'token']::text[],
    'openid profile email phone address offline_access',
    true, true, 'web', 'client_secret_basic', 'RS256', 'public'
) ON CONFLICT (client_id) DO UPDATE SET
    redirect_uris = EXCLUDED.redirect_uris,
    grant_types = EXCLUDED.grant_types,
    response_types = EXCLUDED.response_types,
    scope = EXCLUDED.scope;
EOF

docker compose exec -T postgres psql -U authly -d authly < /tmp/create_test_client.sql > /dev/null 2>&1
echo -e "${GREEN}✓ Test client created${NC}"

echo -e "${YELLOW}Step 4: Initializing TCK environment...${NC}"
cd "$TCK_DIR"
if [ ! -f .env ]; then
    ./scripts/init-tck.sh
else
    echo -e "${GREEN}✓ TCK already initialized${NC}"
fi

echo -e "${YELLOW}Step 5: Running Python integration tests...${NC}"
if command -v pytest &> /dev/null; then
    pytest tests/test_oidc_conformance.py -v --tb=short || true
else
    echo -e "${YELLOW}pytest not found. Install with: pip install pytest httpx${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Setup Complete! 🎉                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Services running:"
echo "  • Authly: http://localhost:8000"
echo "  • PostgreSQL: localhost:5432"
echo "  • Redis: localhost:6379"
echo "  • pgAdmin: http://localhost:5050 (admin@authly.dev / admin)"
echo "  • Mailhog: http://localhost:8025"
echo ""
echo "Next steps:"
echo "1. Run Python tests: pytest tests/test_oidc_conformance.py -v"
echo "2. Start conformance suite: ./scripts/run-conformance.sh"
echo "3. Access web UI: https://localhost:8443"
echo ""
echo "Test client credentials:"
echo "  Client ID: oidc-conformance-test"
echo "  Client Secret: conformance-test-secret"
echo ""
echo "To stop all services:"
echo "  docker compose -f docker-compose.yml -f docker-compose.dev.yml down"