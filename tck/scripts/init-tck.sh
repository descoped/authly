#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Initializing Authly OIDC TCK Environment${NC}"
echo "========================================="

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi
echo "✓ Docker installed"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi
echo "✓ Docker Compose installed"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.11+.${NC}"
    exit 1
fi
echo "✓ Python installed"

# Check if Authly is accessible
echo -e "\n${YELLOW}Checking Authly server...${NC}"
AUTHLY_URL="${AUTHLY_URL:-http://localhost:8000}"

if curl -f -s "${AUTHLY_URL}/health" > /dev/null; then
    echo -e "✓ Authly server is running at ${AUTHLY_URL}"
else
    echo -e "${YELLOW}Authly server is not running at ${AUTHLY_URL}${NC}"
    read -p "Do you want to start Authly in Docker? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        USE_DOCKER_AUTHLY=true
    else
        echo -e "${RED}Please start Authly server manually and re-run this script.${NC}"
        exit 1
    fi
fi

# Create necessary directories
echo -e "\n${YELLOW}Creating directories...${NC}"
mkdir -p config scripts tests docker/nginx docs results
echo "✓ Directories created"

# Generate self-signed certificates for HTTPS
echo -e "\n${YELLOW}Generating SSL certificates...${NC}"
mkdir -p docker/nginx/certs

if [ ! -f docker/nginx/certs/server.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout docker/nginx/certs/server.key \
        -out docker/nginx/certs/server.crt \
        -subj "/C=US/ST=State/L=City/O=Authly/CN=localhost" \
        2>/dev/null
    echo "✓ SSL certificates generated"
else
    echo "✓ SSL certificates already exist"
fi

# Create nginx configuration
echo -e "\n${YELLOW}Creating nginx configuration...${NC}"
cat > docker/nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream conformance {
        server conformance-suite:8443;
    }

    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        location / {
            proxy_pass https://conformance;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

    server {
        listen 80;
        server_name localhost;
        return 301 https://$server_name$request_uri;
    }
}
EOF
echo "✓ Nginx configuration created"

# Create Python virtual environment for TCK scripts
echo -e "\n${YELLOW}Setting up Python environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip > /dev/null 2>&1
    pip install requests pyyaml pytest httpx > /dev/null 2>&1
    echo "✓ Python virtual environment created"
else
    echo "✓ Python virtual environment already exists"
fi

# Create .env file for Docker Compose
echo -e "\n${YELLOW}Creating environment configuration...${NC}"
if [ ! -f .env ]; then
    cat > .env << EOF
# Authly Configuration
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_REFRESH_SECRET_KEY=$(openssl rand -hex 32)
AUTHLY_ADMIN_PASSWORD=conformance_admin_pass
AUTHLY_URL=${AUTHLY_URL}

# Conformance Suite Configuration
CONFORMANCE_VERSION=latest
MONGODB_VERSION=7
POSTGRES_VERSION=16-alpine
EOF
    echo "✓ Environment configuration created"
else
    echo "✓ Environment configuration already exists"
fi

# Initialize test client in Authly
echo -e "\n${YELLOW}Initializing test client in Authly...${NC}"
source venv/bin/activate
python3 << 'PYTHON'
import json
import requests
import sys

authly_url = "${AUTHLY_URL:-http://localhost:8000}"
client_config_path = "config/test-client.json"

try:
    # Load test client configuration
    with open(client_config_path, 'r') as f:
        client_config = json.load(f)
    
    # TODO: Use Authly admin API to create client
    # This would require admin authentication
    print("✓ Test client configuration loaded")
    print("  Note: Manual client creation in Authly may be required")
    
except Exception as e:
    print(f"⚠ Could not initialize test client: {e}")
    print("  You may need to manually create the client in Authly")
PYTHON

# Pull Docker images
echo -e "\n${YELLOW}Pulling Docker images...${NC}"
docker-compose -f docker/docker-compose.yml pull 2>/dev/null || true
echo "✓ Docker images ready"

# Create helper scripts
echo -e "\n${YELLOW}Creating helper scripts...${NC}"

# Create run script
cat > scripts/run-conformance.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
docker-compose -f docker/docker-compose.yml up -d
echo "Conformance suite starting..."
echo "Access the web UI at: https://localhost:8443"
echo "Logs: docker-compose -f docker/docker-compose.yml logs -f conformance-suite"
EOF
chmod +x scripts/run-conformance.sh

# Create stop script
cat > scripts/stop-conformance.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
docker-compose -f docker/docker-compose.yml down
echo "Conformance suite stopped"
EOF
chmod +x scripts/stop-conformance.sh

# Create view results script
cat > scripts/view-results.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
latest_results=$(ls -t results/*/summary.md 2>/dev/null | head -1)
if [ -n "$latest_results" ]; then
    cat "$latest_results"
else
    echo "No test results found. Run tests first with ./scripts/run-conformance.sh"
fi
EOF
chmod +x scripts/view-results.sh

echo "✓ Helper scripts created"

# Summary
echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}TCK Environment Initialized Successfully!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Start the conformance suite:"
echo "   ./scripts/run-conformance.sh"
echo ""
echo "2. Access the web UI:"
echo "   https://localhost:8443"
echo ""
echo "3. Create a test plan with:"
echo "   - Issuer: ${AUTHLY_URL}"
echo "   - Client ID: oidc-conformance-test"
echo "   - Discovery URL: ${AUTHLY_URL}/.well-known/openid_configuration"
echo ""
echo "4. Run conformance tests through the web UI"
echo ""
echo "5. View results:"
echo "   ./scripts/view-results.sh"

if [ "$USE_DOCKER_AUTHLY" = true ]; then
    echo ""
    echo -e "${YELLOW}Note: To start Authly in Docker, run:${NC}"
    echo "   docker-compose -f docker/docker-compose.yml --profile with-authly up -d"
fi