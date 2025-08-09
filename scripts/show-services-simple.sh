#!/bin/bash

# Simple, clean service information display

# Colors - using printf-compatible format
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m' # No Color
BOLD=$'\033[1m'

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
printf "\n"
printf "================================================================================\n"
printf "🚀 %bAUTHLY STANDALONE SERVICES%b\n" "${BOLD}" "${NC}"
printf "================================================================================\n"
printf "\n"
printf "%bCORE SERVICES:%b\n" "${BOLD}" "${NC}"
printf "  • Authly API:        %bhttp://localhost:8000%b\n" "${BLUE}" "${NC}"
printf "                       Username: %badmin%b\n" "${YELLOW}" "${NC}"
printf "                       Password: %b${AUTHLY_ADMIN_PASSWORD:-admin}%b\n" "${YELLOW}" "${NC}"
printf "  • API Documentation: %bhttp://localhost:8000/docs%b\n" "${BLUE}" "${NC}"
printf "  • Health Check:      %bhttp://localhost:8000/health%b\n" "${BLUE}" "${NC}"
printf "\n"
printf "%bDATABASE SERVICES:%b\n" "${BOLD}" "${NC}"
printf "  • PostgreSQL:        %bpostgresql://authly:authly@localhost:5432/authly%b\n" "${BLUE}" "${NC}"
printf "                       (Internal access only from container)\n"

if docker ps --format "table {{.Names}}" | grep -q "authly-pgadmin"; then
    printf "  • pgAdmin:           %bhttp://localhost:5050%b\n" "${BLUE}" "${NC}"
    printf "                       Username: %badmin@example.com%b\n" "${YELLOW}" "${NC}"
    printf "                       Password: %bauthly%b\n" "${YELLOW}" "${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy"; then
    printf "  • PG OAuth Proxy:    %blocalhost:5433%b\n" "${BLUE}" "${NC}"
    printf "                       (Requires OAuth token with database:read/write scopes)\n"
fi
printf "\n"
printf "%bCACHE SERVICES:%b\n" "${BOLD}" "${NC}"
printf "  • Redis/KeyDB:       %bredis://localhost:6379%b\n" "${BLUE}" "${NC}"
printf "                       (No authentication required)\n"

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-commander"; then
    printf "  • Redis Commander:   %bhttp://localhost:8081%b\n" "${BLUE}" "${NC}"
    printf "                       Username: %badmin%b\n" "${YELLOW}" "${NC}"
    printf "                       Password: %badmin%b\n" "${YELLOW}" "${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-redis-proxy"; then
    printf "  • Redis OAuth Proxy: %blocalhost:6380%b\n" "${BLUE}" "${NC}"
    printf "                       (Requires OAuth token with cache:read/write scopes)\n"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-prometheus"; then
    printf "\n"
    printf "%bMONITORING SERVICES:%b\n" "${BOLD}" "${NC}"
    printf "  • Prometheus:        %bhttp://localhost:9090%b\n" "${BLUE}" "${NC}"
    printf "                       (No authentication required)\n"
    printf "  • Targets Status:    %bhttp://localhost:9090/targets%b\n" "${BLUE}" "${NC}"
fi

if docker ps --format "table {{.Names}}" | grep -q "authly-grafana"; then
    printf "  • Grafana:           %bhttp://localhost:3000%b\n" "${BLUE}" "${NC}"
    printf "                       Username: %badmin%b\n" "${YELLOW}" "${NC}"
    printf "                       Password: %badmin%b\n" "${YELLOW}" "${NC}"
    printf "                       Dashboard: Authly Metrics\n"
fi

printf "\n"
printf "%bQUICK COMMANDS:%b\n" "${BOLD}" "${NC}"
printf "  %bGet OAuth Token:%b\n" "${GREEN}" "${NC}"
printf "    curl -X POST http://localhost:8000/api/v1/oauth/token \\\n"
printf "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}'\n"
printf "\n"
printf "  %bTest with Token:%b\n" "${GREEN}" "${NC}"
printf "    TOKEN=\$(curl -s -X POST http://localhost:8000/api/v1/oauth/token \\\n"
printf "      -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}' \\\n"
printf "      | jq -r '.access_token')\n"
printf "    curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8000/api/v1/users/me\n"
printf "\n"
printf "  %bView Logs:%b\n" "${GREEN}" "${NC}"
printf "    docker logs authly-standalone -f\n"
printf "\n"
printf "  %bStop All Services:%b\n" "${GREEN}" "${NC}"
printf "    docker compose -f docker-compose.standalone.yml down\n"
printf "\n"
printf "================================================================================\n"

# Show running status summary
running_count=$(docker ps --format "{{.Names}}" | grep -c authly || echo 0)
printf "%bStatus:%b %b$running_count services running%b\n" "${BOLD}" "${NC}" "${GREEN}" "${NC}"

# List all running services with their status
printf "%bServices:%b\n" "${BOLD}" "${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep authly | while read line; do
    printf "  • %s\n" "$line"
done

printf "================================================================================\n"
printf "\n"