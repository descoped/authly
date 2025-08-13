#!/bin/bash
# Start Authly with HTTPS issuer URL for OIDC compliance testing

set -e

echo "🔐 Starting Authly with HTTPS configuration for OIDC compliance..."

# Stop existing Authly if running
echo "Stopping existing Authly containers..."
(cd .. && docker compose down 2>/dev/null) || true

# Start Authly with HTTPS issuer URL
echo "Starting Authly with HTTPS issuer URL..."
cd .. && DEFAULT_ISSUER_URL=https://localhost:8002 docker compose up -d

# Wait for Authly to be healthy
echo "Waiting for Authly to be healthy..."
for i in {1..30}; do
    if docker exec authly-app curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "✅ Authly is healthy"
        break
    fi
    echo -n "."
    sleep 1
done

# Start HTTPS proxy for Authly
echo "Starting HTTPS proxy for Authly..."
cd tck && docker compose --profile authly-https up -d authly-https

# Wait for HTTPS proxy to be ready
echo "Waiting for HTTPS proxy..."
sleep 3

# Test HTTPS access
echo "Testing HTTPS access..."
if curl -ks https://localhost:8002/.well-known/openid-configuration | grep -q issuer; then
    echo "✅ HTTPS proxy is working"
    echo ""
    echo "🎉 Authly is now accessible via HTTPS at: https://localhost:8002"
    echo ""
    echo "Discovery document:"
    curl -ks https://localhost:8002/.well-known/openid-configuration | python3 -m json.tool | grep -E "issuer|authorization_endpoint|token_endpoint" | head -3
else
    echo "❌ HTTPS proxy is not working"
    exit 1
fi

echo ""
echo "To run conformance tests with HTTPS:"
echo "  cd tck && make validate"