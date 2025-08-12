#!/bin/sh
# Bootstrap admin authentication and test clients for compliance testing
# This script runs in the authly-standalone container

set -e

echo "🔧 Setting up Admin Authentication and Test Clients"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Login to authly CLI and get admin tokens
echo "🔐 Logging in as admin and retrieving tokens..."
LOGIN_OUTPUT=$(authly admin auth login -u admin -p "${AUTHLY_ADMIN_PASSWORD:-admin}" --show-token 2>&1)

if [ $? -ne 0 ]; then
    echo "❌ Failed to login to authly CLI"
    echo "$LOGIN_OUTPUT"
    exit 1
fi

# Extract access and refresh tokens from the output
ACCESS_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "Access token:" | sed 's/.*Access token: //')
REFRESH_TOKEN=$(echo "$LOGIN_OUTPUT" | grep "Refresh token:" | sed 's/.*Refresh token: //')

if [ -z "$ACCESS_TOKEN" ] || [ -z "$REFRESH_TOKEN" ]; then
    echo "❌ Failed to extract tokens"
    echo "Output: $LOGIN_OUTPUT"
    exit 1
fi

echo "✅ Successfully logged in and retrieved admin tokens"
echo ""

# Save admin tokens to shared volume for compliance tester
mkdir -p /app/tester-data
cat > /app/tester-data/admin-tokens.json <<EOF
{
  "access_token": "$ACCESS_TOKEN",
  "refresh_token": "$REFRESH_TOKEN",
  "token_type": "Bearer",
  "scope": "admin:clients:read admin:clients:write admin:users:read admin:users:write"
}
EOF

echo "📝 Admin tokens saved to /app/tester-data/admin-tokens.json"
echo ""

# Create a public test client for OAuth 2.1 compliance testing
echo "🔧 Creating Test Client for Compliance Testing..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create public client for OAuth 2.1 testing
TEST_RESULT=$(authly admin client create \
  --name "Compliance Test Client" \
  --type public \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --output json 2>&1)

TEST_CLIENT_ID=$(echo "$TEST_RESULT" | grep -o '"client_id": *"[^"]*"' | sed 's/.*: *"\(.*\)"/\1/')

if [ -z "$TEST_CLIENT_ID" ]; then
    echo "⚠️  Failed to create test client"
    echo "Output: $TEST_RESULT"
else
    echo "✅ Created test client: $TEST_CLIENT_ID"
    
    # Save test client config
    cat > /app/tester-data/test-client.json <<EOF
{
  "client_id": "$TEST_CLIENT_ID",
  "client_name": "Compliance Test Client",
  "client_type": "public",
  "redirect_uris": ["http://localhost:8080/callback"],
  "scope": "openid profile email"
}
EOF
    echo "📝 Test client config saved to /app/tester-data/test-client.json"
fi

echo ""
echo "✅ Bootstrap complete! The compliance tester can now:"
echo "   1. Use the admin tokens to call admin APIs"
echo "   2. Create additional test clients as needed"
echo "   3. Run OAuth 2.1 compliance tests with the test client"
echo ""