#!/bin/bash

# Plain text service information display (no colors)

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
echo "🚀 AUTHLY STANDALONE SERVICES"
echo "================================================================================"
echo ""
echo "CORE SERVICES:"
echo "  • Authly API:        http://localhost:8000"
echo "                       Username: admin"
echo "                       Password: ${AUTHLY_ADMIN_PASSWORD:-admin}"
echo "  • API Documentation: http://localhost:8000/docs"
echo "  • Health Check:      http://localhost:8000/health"
echo ""
echo "DATABASE SERVICES:"
echo "  • PostgreSQL:        postgresql://authly:authly@localhost:5432/authly"
echo "                       (Internal access only from container)"

if docker ps --format "table {{.Names}}" | grep -q "authly-pgadmin"; then
    echo "  • pgAdmin:           http://localhost:5050"
    echo "                       Username: admin@example.com"
    echo "                       Password: authly"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-adminer"; then
    echo "  • Adminer (OAuth):   http://localhost:8082"
    echo "                       Auth: Use Authly Bearer Token"
    echo "                       (Lightweight DB management)"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy"; then
    echo "  • PG OAuth Proxy:    localhost:5433"
    echo "                       (Requires OAuth token with database:read/write scopes)"
fi
echo ""
echo "CACHE SERVICES:"
echo "  • Redis/KeyDB:       redis://localhost:6379"
echo "                       (No authentication required)"

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-commander"; then
    echo "  • Redis Commander:   http://localhost:8081"
    echo "                       Username: admin"
    echo "                       Password: admin"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-proxy"; then
    echo "  • Redis OAuth Proxy: localhost:6380"
    echo "                       (Requires OAuth token with cache:read/write scopes)"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-prometheus"; then
    echo ""
    echo "MONITORING SERVICES:"
    echo "  • Prometheus:        http://localhost:9090"
    echo "                       (No authentication required)"
    echo "  • Targets Status:    http://localhost:9090/targets"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-grafana"; then
    echo "  • Grafana:           http://localhost:3000"
    echo "                       Username: admin"
    echo "                       Password: admin"
    echo "                       Dashboard: Authly Metrics"
fi

echo ""
echo "QUICK COMMANDS:"
echo "  Get OAuth Token:"
echo "    curl -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}'"
echo ""
echo "  Test with Token:"
echo "    TOKEN=\$(curl -s -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}' \\"
echo "      | jq -r '.access_token')"
echo "    curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8000/api/v1/users/me"
echo ""
echo "  View Logs:"
echo "    docker logs authly-standalone -f"
echo ""
echo "  Stop All Services:"
echo "    docker compose -f docker-compose.standalone.yml down"
echo ""
echo "================================================================================"

# Show running status summary
running_count=$(docker ps --format "{{.Names}}" | grep -c authly || echo 0)
echo "Status: $running_count services running"

# List all running services with their status
echo "Services:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep authly | while read line; do
    echo "  • $line"
done

echo "================================================================================"
echo ""