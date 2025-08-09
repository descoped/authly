#!/bin/bash

# Simple, clean service information display

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to check if a service is running
check_service() {
    local container_name=$1
    if docker ps --format "table {{.Names}}" | grep -q "^${container_name}$"; then
        echo "✅"
    else
        echo "❌"
    fi
}

# Main display
echo ""
echo "================================================================================"
echo "🚀 ${BOLD}AUTHLY STANDALONE SERVICES${NC}"
echo "================================================================================"
echo ""
echo "${BOLD}CORE SERVICES:${NC}"
echo "  • Authly API:        ${BLUE}http://localhost:8000${NC}"
echo "                       Username: ${YELLOW}admin${NC}"
echo "                       Password: ${YELLOW}${AUTHLY_ADMIN_PASSWORD:-admin}${NC}"
echo "  • API Documentation: ${BLUE}http://localhost:8000/docs${NC}"
echo "  • Health Check:      ${BLUE}http://localhost:8000/health${NC}"
echo ""
echo "${BOLD}DATABASE SERVICES:${NC}"
echo "  • PostgreSQL:        ${BLUE}postgresql://authly:authly@localhost:5432/authly${NC}"
echo "                       (Internal access only from container)"

if docker ps --format "table {{.Names}}" | grep -q "authly-pgadmin"; then
    echo "  • pgAdmin:           ${BLUE}http://localhost:5050${NC}"
    echo "                       Username: ${YELLOW}admin@example.com${NC}"
    echo "                       Password: ${YELLOW}authly${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy"; then
    echo "  • PG OAuth Proxy:    ${BLUE}localhost:5433${NC}"
    echo "                       (Requires OAuth token with database:read/write scopes)"
fi
echo ""
echo "${BOLD}CACHE SERVICES:${NC}"
echo "  • Redis/KeyDB:       ${BLUE}redis://localhost:6379${NC}"
echo "                       (No authentication required)"

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-commander"; then
    echo "  • Redis Commander:   ${BLUE}http://localhost:8081${NC}"
    echo "                       Username: ${YELLOW}admin${NC}"
    echo "                       Password: ${YELLOW}admin${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-proxy"; then
    echo "  • Redis OAuth Proxy: ${BLUE}localhost:6380${NC}"
    echo "                       (Requires OAuth token with cache:read/write scopes)"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-prometheus"; then
    echo ""
    echo "${BOLD}MONITORING SERVICES:${NC}"
    echo "  • Prometheus:        ${BLUE}http://localhost:9090${NC}"
    echo "                       (No authentication required)"
    echo "  • Targets Status:    ${BLUE}http://localhost:9090/targets${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-grafana"; then
    echo "  • Grafana:           ${BLUE}http://localhost:3000${NC}"
    echo "                       Username: ${YELLOW}admin${NC}"
    echo "                       Password: ${YELLOW}admin${NC}"
    echo "                       Dashboard: Authly Metrics"
fi

echo ""
echo "${BOLD}QUICK COMMANDS:${NC}"
echo "  ${GREEN}Get OAuth Token:${NC}"
echo "    curl -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}'"
echo ""
echo "  ${GREEN}Test with Token:${NC}"
echo "    TOKEN=\$(curl -s -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}' \\"
echo "      | jq -r '.access_token')"
echo "    curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8000/api/v1/users/me"
echo ""
echo "  ${GREEN}View Logs:${NC}"
echo "    docker logs authly-standalone -f"
echo ""
echo "  ${GREEN}Stop All Services:${NC}"
echo "    docker compose -f docker-compose.standalone.yml down"
echo ""
echo "================================================================================"

# Show running status summary
running_count=$(docker ps --format "{{.Names}}" | grep -c authly || echo 0)
echo "${BOLD}Status:${NC} ${GREEN}$running_count services running${NC}"

# List all running services with their status
echo "${BOLD}Services:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep authly | while read line; do
    echo "  • $line"
done

echo "================================================================================"
echo ""