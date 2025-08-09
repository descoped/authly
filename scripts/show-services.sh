#!/bin/bash

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
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

# Function to print a separator line
print_separator() {
    echo "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to print section header
print_header() {
    echo ""
    print_separator
    echo "${BOLD}${WHITE}$1${NC}"
    print_separator
}

# Main display function
show_services() {
    clear
    echo ""
    echo "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo "${BOLD}${MAGENTA}║                     AUTHLY STANDALONE SERVICES                              ║${NC}"
    echo "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Core Services
    print_header "🔐 CORE SERVICES"
    echo ""
    echo "${BOLD}${GREEN}Authly API${NC} $(check_service authly-standalone)"
    echo "  📍 URL: ${BLUE}http://localhost:8000${NC}"
    echo "  📚 Docs: ${BLUE}http://localhost:8000/docs${NC}"
    echo "  🔑 Admin: ${YELLOW}admin / ${AUTHLY_ADMIN_PASSWORD:-admin}${NC}"
    echo ""
    echo "${BOLD}${GREEN}Health Check${NC}"
    echo "  📍 URL: ${BLUE}http://localhost:8000/health${NC}"
    echo ""
    echo "${BOLD}${GREEN}OAuth Token Endpoint${NC}"
    echo "  📍 URL: ${BLUE}POST http://localhost:8000/api/v1/oauth/token${NC}"
    echo "  📝 Grant Types: password, authorization_code, refresh_token"
    
    # Database Services
    print_header "🗄️ DATABASE SERVICES"
    echo ""
    echo "${BOLD}${GREEN}PostgreSQL${NC} $(check_service authly-standalone)"
    echo "  📍 Direct: ${BLUE}localhost:5432${NC}"
    echo "  🔑 Credentials: ${YELLOW}authly / (internal only)${NC}"
    echo "  📊 Database: ${YELLOW}authly${NC}"
    echo ""
    echo "${BOLD}${GREEN}pgAdmin${NC} $(check_service authly-pgadmin)"
    echo "  📍 URL: ${BLUE}http://localhost:5050${NC}"
    echo "  🔑 Login: ${YELLOW}admin@example.com / authly${NC}"
    echo "  💡 Tip: Server already configured as 'Authly Standalone'"
    
    # Cache Services
    print_header "💾 CACHE SERVICES"
    echo ""
    echo "${BOLD}${GREEN}Redis/KeyDB${NC} $(check_service authly-standalone)"
    echo "  📍 Direct: ${BLUE}localhost:6379${NC}"
    echo "  🔑 No authentication required"
    echo ""
    echo "${BOLD}${GREEN}Redis Commander${NC} $(check_service authly-redis-commander)"
    echo "  📍 URL: ${BLUE}http://localhost:8081${NC}"
    echo "  🔑 Login: ${YELLOW}admin / admin${NC}"
    
    # Monitoring Services
    print_header "📊 MONITORING SERVICES"
    echo ""
    echo "${BOLD}${GREEN}Prometheus${NC} $(check_service authly-prometheus)"
    echo "  📍 URL: ${BLUE}http://localhost:9090${NC}"
    echo "  🔑 No authentication required"
    echo "  📈 Targets: ${BLUE}http://localhost:9090/targets${NC}"
    echo ""
    echo "${BOLD}${GREEN}Grafana${NC} $(check_service authly-grafana)"
    echo "  📍 URL: ${BLUE}http://localhost:3000${NC}"
    echo "  🔑 Login: ${YELLOW}admin / admin${NC}"
    echo "  📊 Dashboard: Authly Metrics"
    
    # OAuth Proxy Services (if enabled)
    if docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy\|authly-redis-proxy"; then
        print_header "🔒 OAUTH PROXY SERVICES"
        echo ""
        
        if docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy"; then
            echo "${BOLD}${GREEN}PostgreSQL OAuth Proxy${NC} $(check_service authly-pg-proxy)"
            echo "  📍 URL: ${BLUE}localhost:5433${NC}"
            echo "  🔑 Use OAuth token with scope: ${YELLOW}database:read database:write${NC}"
        fi
        
        if docker ps --format "table {{.Names}}" | grep -q "authly-redis-proxy"; then
            echo ""
            echo "${BOLD}${GREEN}Redis OAuth Proxy${NC} $(check_service authly-redis-proxy)"
            echo "  📍 URL: ${BLUE}localhost:6380${NC}"
            echo "  🔑 Use OAuth token with scope: ${YELLOW}cache:read cache:write${NC}"
        fi
    fi
    
    # Quick Commands
    print_header "⚡ QUICK COMMANDS"
    echo ""
    echo "${BOLD}Get OAuth Token:${NC}"
    echo "  ${CYAN}curl -X POST http://localhost:8000/api/v1/oauth/token \\${NC}"
    echo "  ${CYAN}  -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}'${NC}"
    echo ""
    echo "${BOLD}View Logs:${NC}"
    echo "  ${CYAN}docker logs authly-standalone -f${NC}"
    echo ""
    echo "${BOLD}Stop All Services:${NC}"
    echo "  ${CYAN}docker compose -f docker-compose.standalone.yml down${NC}"
    
    # Status Summary
    print_header "📈 STATUS SUMMARY"
    echo ""
    
    # Count running services
    local total_services=0
    local running_services=0
    
    for service in authly-standalone authly-pgadmin authly-redis-commander authly-prometheus authly-grafana authly-pg-proxy authly-redis-proxy authly-postgres-exporter authly-redis-exporter; do
        total_services=$((total_services + 1))
        if docker ps --format "table {{.Names}}" | grep -q "^${service}$"; then
            running_services=$((running_services + 1))
        fi
    done
    
    echo "  ${GREEN}●${NC} Running Services: ${BOLD}${running_services}${NC}"
    echo "  ${YELLOW}●${NC} Total Configured: ${BOLD}${total_services}${NC}"
    
    # Check which profiles are active
    echo ""
    echo "${BOLD}Active Profiles:${NC}"
    docker ps --format "table {{.Names}}" | grep -q "authly-pgadmin\|authly-redis-commander" && echo "  ✅ tools"
    docker ps --format "table {{.Names}}" | grep -q "authly-prometheus\|authly-grafana" && echo "  ✅ monitoring"
    docker ps --format "table {{.Names}}" | grep -q "authly-pg-proxy\|authly-redis-proxy" && echo "  ✅ authz"
    
    print_separator
    echo ""
    echo "${BOLD}${GREEN}All services are ready! 🚀${NC}"
    echo "${YELLOW}Documentation:${NC} ${BLUE}docs/docker-standalone.md${NC}"
    echo ""
}

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
    echo "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Check if authly-standalone container exists
if ! docker ps -a --format "table {{.Names}}" | grep -q "authly-standalone"; then
    echo "${YELLOW}Warning: authly-standalone container not found${NC}"
    echo "Run: docker compose -f docker-compose.standalone.yml up -d"
    exit 1
fi

# Run the display
show_services