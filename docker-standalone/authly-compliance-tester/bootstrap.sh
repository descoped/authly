#!/bin/sh
set -e

echo "🔄 Running OAuth client bootstrap..."

# Find the authly-standalone container
AUTHLY_CONTAINER=$(docker ps --format "{{.Names}}" | grep "authly-standalone" | head -1)

if [ -z "$AUTHLY_CONTAINER" ]; then
    echo "⚠️  Authly container not found, skipping bootstrap"
    exit 0
fi

echo "📦 Found Authly container: $AUTHLY_CONTAINER"

# Check if tokens already exist
if [ -f /usr/share/nginx/html/data/admin-tokens.json ] && [ -s /usr/share/nginx/html/data/admin-tokens.json ]; then
    echo "✅ Admin tokens already exist, skipping bootstrap"
    exit 0
fi

echo "🔐 Running bootstrap to get admin tokens..."

# Login as admin and get tokens (with timeout to prevent hanging)
LOGIN_OUTPUT=$(timeout 10 docker exec "$AUTHLY_CONTAINER" authly admin auth login -u admin -p "${AUTHLY_ADMIN_PASSWORD:-admin}" --show-token 2>&1)

if echo "$LOGIN_OUTPUT" | grep -q "Successfully logged in"; then
    # Extract tokens
    ACCESS_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "Access token:" | sed 's/.*Access token: //')
    REFRESH_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "Refresh token:" | sed 's/.*Refresh token: //')
    
    if [ -n "$ACCESS_TOKEN" ] && [ -n "$REFRESH_TOKEN" ]; then
        # Save admin tokens
        cat > /usr/share/nginx/html/data/admin-tokens.json <<EOF
{
  "access_token": "$ACCESS_TOKEN",
  "refresh_token": "$REFRESH_TOKEN",
  "token_type": "Bearer",
  "scope": "admin:clients:read admin:clients:write admin:users:read admin:users:write"
}
EOF
        echo "✅ Admin tokens saved"
        
        # Create test client
        echo "🔧 Creating test client..."
        TEST_OUTPUT=$(timeout 10 docker exec "$AUTHLY_CONTAINER" authly admin client create \
            --name "Compliance Test Client" \
            --type public \
            --redirect-uri "http://localhost:8080/callback" \
            --scope "openid profile email" \
            --output json 2>&1)
        
        if echo "$TEST_OUTPUT" | grep -q '"client_id"'; then
            # Save test client
            echo "$TEST_OUTPUT" > /usr/share/nginx/html/data/test-client.json
            TEST_CLIENT_ID=$(echo "$TEST_OUTPUT" | jq -r .client_id 2>/dev/null || echo "unknown")
            echo "✅ Test client created: $TEST_CLIENT_ID"
        else
            echo "⚠️  Failed to create test client"
            echo "$TEST_OUTPUT"
        fi
    else
        echo "⚠️  Failed to extract tokens"
    fi
else
    echo "⚠️  Admin login failed"
    echo "$LOGIN_OUTPUT"
fi

echo "✅ Bootstrap complete"