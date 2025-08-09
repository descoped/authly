#!/bin/bash
# Add database and cache scopes using the Authly CLI

echo "Adding database and cache scopes..."

# First, login as admin to get a token
TOKEN=$(python -m authly admin auth login --api-url http://localhost:8000 --show-token 2>/dev/null | grep access_token | awk -F'"' '{print $4}')

if [ -z "$TOKEN" ]; then
    echo "Failed to get admin token. Please ensure admin user exists."
    exit 1
fi

# Add scopes using the admin CLI
echo "Creating scope: database:read"
python -m authly admin scope create --name "database:read" --description "Read access to database (SELECT queries)" 2>/dev/null || echo "  Scope may already exist"

echo "Creating scope: database:write"
python -m authly admin scope create --name "database:write" --description "Write access to database (INSERT, UPDATE, DELETE)" 2>/dev/null || echo "  Scope may already exist"

echo "Creating scope: cache:read"
python -m authly admin scope create --name "cache:read" --description "Read access to cache/Redis (GET operations)" 2>/dev/null || echo "  Scope may already exist"

echo "Creating scope: cache:write"
python -m authly admin scope create --name "cache:write" --description "Write access to cache/Redis (SET, DEL operations)" 2>/dev/null || echo "  Scope may already exist"

# List all scopes to verify
echo ""
echo "Current scopes:"
python -m authly admin scope list

echo ""
echo "✅ Database scopes setup complete!"