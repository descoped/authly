#!/bin/bash

echo "Testing OIDC Debugger Integration with Authly"
echo "=============================================="

# Test 1: Check UI is accessible
echo -n "1. Testing UI accessibility... "
if curl -s http://localhost:8083/ | grep -q "IDPTools"; then
    echo "✅ Pass"
else
    echo "❌ Fail"
    exit 1
fi

# Test 2: Check API is accessible
echo -n "2. Testing API accessibility... "
if curl -s http://localhost:8084/ >/dev/null 2>&1; then
    echo "✅ Pass"
else
    echo "❌ Fail"
    exit 1
fi

# Test 3: Check Authly is accessible
echo -n "3. Testing Authly accessibility... "
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo "✅ Pass"
else
    echo "❌ Fail"
    exit 1
fi

# Test 4: Check OIDC discovery endpoint
echo -n "4. Testing Authly OIDC discovery... "
if curl -s http://localhost:8000/.well-known/openid-configuration | grep -q "issuer"; then
    echo "✅ Pass"
else
    echo "❌ Fail"
    exit 1
fi

echo ""
echo "All tests passed! You can now access the OIDC Debugger at:"
echo "  UI: http://localhost:8083"
echo "  API: http://localhost:8084"
echo ""
echo "To test OAuth/OIDC flows with Authly:"
echo "1. Go to http://localhost:8083"
echo "2. Use these Authly endpoints:"
echo "   - Authorization: http://localhost:8000/oauth/authorize"
echo "   - Token: http://localhost:8000/api/v1/oauth/token"
echo "   - UserInfo: http://localhost:8000/api/v1/userinfo"
echo "   - JWKS: http://localhost:8000/.well-known/jwks.json"
echo "   - Discovery: http://localhost:8000/.well-known/openid-configuration"
echo "3. Use client credentials from Authly (create via admin CLI if needed)"