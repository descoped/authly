#!/bin/bash

# Development SSL Certificate Setup Script
# Generates self-signed certificates for local development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/docker-compose/nginx/ssl"

echo "🔐 Setting up development SSL certificates..."

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Check if certificates already exist
if [[ -f "$SSL_DIR/cert.pem" && -f "$SSL_DIR/key.pem" ]]; then
    echo "⚠️  SSL certificates already exist in $SSL_DIR"
    echo "   Remove them manually if you want to regenerate:"
    echo "   rm $SSL_DIR/*.pem"
    exit 0
fi

# Generate self-signed certificate
echo "📝 Generating self-signed SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" \
    -out "$SSL_DIR/cert.pem" \
    -subj "/C=US/ST=Development/L=Localhost/O=Authly/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:authly.localhost,IP:127.0.0.1"

# Set appropriate permissions
chmod 600 "$SSL_DIR"/*.pem

echo "✅ SSL certificates generated successfully!"
echo "   📄 Certificate: $SSL_DIR/cert.pem"
echo "   🔑 Private key: $SSL_DIR/key.pem"
echo ""
echo "🚀 You can now start the development environment:"
echo "   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d"