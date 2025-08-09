#!/bin/bash

echo "Checking OIDC Debugger Default Endpoints"
echo "========================================="

# Get the debugger.js file and check for Authly endpoints
echo -n "Checking authorization endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/oauth/authorize' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo -n "Checking token endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/api/v1/oauth/token' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo -n "Checking introspection endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/api/v1/oauth/introspect' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo -n "Checking redirect URI... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8083/callback' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to debugger port"
else
    echo "❌ Not set correctly"
fi

echo -n "Checking OIDC discovery endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/.well-known/openid-configuration' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo -n "Checking userinfo endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/api/v1/userinfo' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo -n "Checking JWKS endpoint... "
if docker exec authly-oidc-debugger grep -q 'http://localhost:8000/.well-known/jwks.json' /usr/src/app/client/public/js/debugger.js; then
    echo "✅ Set to Authly"
else
    echo "❌ Not set to Authly"
fi

echo ""
echo "You can now test at http://localhost:8083"
echo "The form fields should be pre-populated with Authly endpoints!"