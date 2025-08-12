#!/bin/sh
# Setup OAuth test client for compliance testing
# This runs inside the authly-standalone container

set -e

echo "🔧 Creating OAuth test client for compliance testing..."

# Create the client using CLI
RESULT=$(AUTHLY_ADMIN_PASSWORD=admin python -m authly.admin.cli client create \
  --name "Compliance Tester" \
  --type public \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --grant-type authorization_code \
  --grant-type refresh_token \
  --output json 2>/dev/null | tail -1)

# Extract client_id
CLIENT_ID=$(echo "$RESULT" | grep -o '"client_id": *"[^"]*"' | sed 's/.*: *"\(.*\)"/\1/')

if [ -z "$CLIENT_ID" ]; then
    echo "❌ Failed to create client"
    exit 1
fi

# Create a JSON config file
cat > /tmp/test-client.json <<EOF
{
  "client_id": "$CLIENT_ID",
  "client_name": "Compliance Tester",
  "client_type": "public",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email"
}
EOF

echo "✅ Created test client: $CLIENT_ID"
echo "📝 Config saved to /tmp/test-client.json"

# Output the config
cat /tmp/test-client.json