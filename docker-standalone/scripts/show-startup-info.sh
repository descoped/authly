#!/bin/bash

# This script displays service information when the container starts

echo ""
echo "================================================================================"
echo "🚀 All services are ready!"
echo "================================================================================"
echo ""
echo "Service URLs and Credentials:"
echo ""
echo "  • Authly API:        http://localhost:8000"
echo "                       Username: admin"
echo "                       Password: ${AUTHLY_ADMIN_PASSWORD:-admin}"
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

# Check if additional services are enabled
if [ -n "$ENABLE_PGADMIN" ]; then
    echo "  • pgAdmin:           http://localhost:5050"
    echo "                       Username: admin@example.com"
    echo "                       Password: admin"
    echo ""
fi

if [ -n "$ENABLE_REDIS_COMMANDER" ]; then
    echo "  • Redis Commander:   http://localhost:8081"
    echo "                       Username: admin"
    echo "                       Password: admin"
    echo ""
fi

if [ -n "$ENABLE_GRAFANA" ]; then
    echo "  • Grafana:           http://localhost:3000"
    echo "                       Username: admin"
    echo "                       Password: admin"
    echo ""
fi

if [ -n "$ENABLE_PROMETHEUS" ]; then
    echo "  • Prometheus:        http://localhost:9090"
    echo "                       (No authentication required)"
    echo ""
fi

echo "Quick OAuth Token Test:"
echo "  curl -X POST http://localhost:8000/api/v1/oauth/token \\"
echo "    -d 'grant_type=password&username=admin&password=${AUTHLY_ADMIN_PASSWORD:-admin}'"
echo ""
echo "================================================================================"
echo ""