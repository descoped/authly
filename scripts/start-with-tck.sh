#!/bin/bash

# Start Authly with OIDC Conformance Testing Suite
# This script starts the full development stack including the conformance suite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 Starting Authly with OIDC Conformance Testing Suite..."
echo "=================================================="

# Check if conformance suite JAR exists
if [ ! -f "$PROJECT_ROOT/tck/conformance-suite/target/fapi-test-suite.jar" ]; then
    echo "⚠️  Conformance suite JAR not found. Building it now..."
    echo ""
    
    # Check if conformance suite is cloned
    if [ ! -d "$PROJECT_ROOT/tck/conformance-suite/.git" ]; then
        echo "📦 Cloning conformance suite repository..."
        git clone https://gitlab.com/openid/conformance-suite.git "$PROJECT_ROOT/tck/conformance-suite"
    fi
    
    # Build the JAR
    echo "🔨 Building conformance suite JAR (this may take a few minutes)..."
    cd "$PROJECT_ROOT/tck/conformance-suite"
    docker run --rm \
        -v "$PWD":/usr/src/mymaven \
        -v "$HOME/.m2":/root/.m2 \
        -w /usr/src/mymaven \
        maven:3-eclipse-temurin-17 \
        mvn -B clean package -DskipTests=true
    
    if [ ! -f "target/fapi-test-suite.jar" ]; then
        echo "❌ Failed to build conformance suite JAR"
        exit 1
    fi
    
    echo "✅ Conformance suite JAR built successfully!"
    cd "$PROJECT_ROOT"
fi

# Stop any existing containers
echo ""
echo "🛑 Stopping existing containers..."
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml down

# Start all services
echo ""
echo "🚀 Starting services..."
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml up -d

# Wait for services to be healthy
echo ""
echo "⏳ Waiting for services to be healthy..."

# Function to check service health
check_health() {
    local service=$1
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml ps --format json | grep -q "\"Service\":\"$service\".*\"Health\":\"healthy\""; then
            echo "✅ $service is healthy"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo "⚠️  $service did not become healthy in time"
    return 1
}

# Check core services
check_health "postgres"
check_health "redis"
check_health "authly"

# Check TCK services (these might not have health checks)
sleep 5
if docker ps | grep -q tck-mongodb; then
    echo "✅ TCK MongoDB is running"
fi
if docker ps | grep -q tck-server; then
    echo "✅ TCK Server is running"
fi
if docker ps | grep -q tck-httpd; then
    echo "✅ TCK HTTPD is running"
fi

# Display service URLs
echo ""
echo "=================================================="
echo "🎉 Services are ready!"
echo "=================================================="
echo ""
echo "📍 Service URLs:"
echo "  • Authly API:           http://localhost:8000"
echo "  • Authly Admin:         http://localhost:8000/admin"
echo "  • Conformance Suite:    https://localhost:8443"
echo "  • PostgreSQL:           postgresql://localhost:5432/authly"
echo "  • Redis:                redis://localhost:6379"
echo ""
echo "🔑 Test Client Credentials:"
echo "  • Client ID:     oidc-conformance-test"
echo "  • Client Secret: conformance-test-secret"
echo ""
echo "📚 OIDC Endpoints:"
echo "  • Discovery:     http://localhost:8000/.well-known/openid-configuration"
echo "  • Authorization: http://localhost:8000/api/v1/oauth/authorize"
echo "  • Token:         http://localhost:8000/api/v1/auth/token"
echo "  • UserInfo:      http://localhost:8000/oidc/userinfo"
echo "  • JWKS:          http://localhost:8000/.well-known/jwks.json"
echo ""
echo "🧪 To run conformance tests:"
echo "  1. Open https://localhost:8443 in your browser"
echo "  2. Create a new test plan"
echo "  3. Configure with Authly endpoints above"
echo "  4. Run the tests"
echo ""
echo "💡 To run Python integration tests:"
echo "  cd tck && pytest tests/ -v"
echo ""
echo "🛑 To stop all services:"
echo "  docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml down"
echo ""