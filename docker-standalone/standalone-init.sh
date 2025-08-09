#!/bin/sh
# Authly Standalone Container Initialization
# Generates secure secrets if not provided via environment

set -e

# Function to generate a secure random secret
generate_secret() {
    # Generate 32 bytes (256 bits) of random data and encode as hex
    openssl rand -hex 32
}

# Create s6 environment directory for persistent environment variables
mkdir -p /run/s6/container_environment

# Check and set JWT_SECRET_KEY
if [ -z "$JWT_SECRET_KEY" ]; then
    if [ "$AUTHLY_STANDALONE" = "true" ]; then
        # For standalone dev/test use, generate a random secret
        JWT_SECRET_KEY=$(generate_secret)
        echo "$JWT_SECRET_KEY" > /run/s6/container_environment/JWT_SECRET_KEY
        echo "🔐 Generated random JWT_SECRET_KEY for standalone use"
    else
        echo "❌ ERROR: JWT_SECRET_KEY must be set for production use"
        echo "   Generate a secure key with: openssl rand -hex 32"
        exit 1
    fi
else
    echo "$JWT_SECRET_KEY" > /run/s6/container_environment/JWT_SECRET_KEY
fi

# Check and set JWT_REFRESH_SECRET_KEY
if [ -z "$JWT_REFRESH_SECRET_KEY" ]; then
    if [ "$AUTHLY_STANDALONE" = "true" ]; then
        # For standalone dev/test use, generate a random secret
        JWT_REFRESH_SECRET_KEY=$(generate_secret)
        echo "$JWT_REFRESH_SECRET_KEY" > /run/s6/container_environment/JWT_REFRESH_SECRET_KEY
        echo "🔐 Generated random JWT_REFRESH_SECRET_KEY for standalone use"
    else
        echo "❌ ERROR: JWT_REFRESH_SECRET_KEY must be set for production use"
        echo "   Generate a secure key with: openssl rand -hex 32"
        exit 1
    fi
else
    echo "$JWT_REFRESH_SECRET_KEY" > /run/s6/container_environment/JWT_REFRESH_SECRET_KEY
fi

# Check and set AUTHLY_ADMIN_PASSWORD
if [ -z "$AUTHLY_ADMIN_PASSWORD" ]; then
    if [ "$AUTHLY_STANDALONE" = "true" ]; then
        # For standalone dev/test use, use simple default
        AUTHLY_ADMIN_PASSWORD="admin"
        echo "$AUTHLY_ADMIN_PASSWORD" > /run/s6/container_environment/AUTHLY_ADMIN_PASSWORD
        echo "⚠️  Using default admin password 'admin' for standalone use"
        echo "   For production, set AUTHLY_ADMIN_PASSWORD environment variable"
    else
        echo "❌ ERROR: AUTHLY_ADMIN_PASSWORD must be set for production use"
        exit 1
    fi
else
    echo "$AUTHLY_ADMIN_PASSWORD" > /run/s6/container_environment/AUTHLY_ADMIN_PASSWORD
fi

# Export for immediate use
export JWT_SECRET_KEY JWT_REFRESH_SECRET_KEY AUTHLY_ADMIN_PASSWORD

# Display service information
echo ""
echo "================================================================================"
echo "🚀 All services are ready!"
echo "================================================================================"
echo ""
echo "Service URLs and Credentials:"
echo ""
echo "  • Authly API:        http://localhost:8000"
echo "                       Username: admin"
echo "                       Password: ${AUTHLY_ADMIN_PASSWORD}"
echo ""
echo "  • PostgreSQL:        postgresql://authly:authly@localhost:5432/authly"
echo "                       (Internal access only)"
echo ""
echo "  • KeyDB/Redis:       redis://localhost:6379"
echo "                       (No authentication required)"
echo ""
echo "  • API Documentation: http://localhost:8000/docs"
echo "  • Health Check:      http://localhost:8000/health"
echo ""
echo "Quick OAuth Token Test:"
echo "  curl -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "    -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD}'"
echo ""
echo "================================================================================"
echo ""

# Continue with normal startup
exec "$@"