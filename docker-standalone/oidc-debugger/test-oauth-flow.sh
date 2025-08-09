#!/bin/bash

echo "Testing OAuth Flow Directly"
echo "============================"
echo ""

# Test 1: Check if Authly authorization endpoint works
echo "1. Testing Authly authorization endpoint..."
AUTH_URL="http://localhost:8000/oauth/authorize?client_id=client_q5IkUufL0c6CvzglVVZcIw&redirect_uri=http://localhost:8083/callback&response_type=code&scope=openid%20profile&state=test123"
echo "   URL: $AUTH_URL"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$AUTH_URL")
echo "   Response code: $RESPONSE"
if [ "$RESPONSE" = "302" ] || [ "$RESPONSE" = "200" ]; then
    echo "   ✅ Authorization endpoint is accessible"
else
    echo "   ❌ Authorization endpoint returned unexpected code"
fi

echo ""
echo "2. Testing OIDC Discovery..."
DISCOVERY=$(curl -s http://localhost:8000/.well-known/openid-configuration | jq -r '.authorization_endpoint' 2>/dev/null)
if [ ! -z "$DISCOVERY" ]; then
    echo "   ✅ Discovery endpoint works: $DISCOVERY"
else
    echo "   ❌ Discovery endpoint not working"
fi

echo ""
echo "3. Testing if debugger callback endpoint works..."
CALLBACK_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8083/callback?code=test&state=test")
echo "   Response code: $CALLBACK_RESPONSE"
if [ "$CALLBACK_RESPONSE" = "302" ]; then
    echo "   ✅ Callback endpoint redirects properly"
else
    echo "   ❌ Callback endpoint issue"
fi

echo ""
echo "4. Checking if the issue is with the debugger UI..."
echo "   Try this manual test:"
echo "   a) Open: http://localhost:8083/debugger.html"
echo "   b) Open Browser DevTools Console (F12)"
echo "   c) Type: debug.authorize()"
echo "   d) Check for any JavaScript errors"
echo ""
echo "   Or paste this in console to test:"
echo "   localStorage.setItem('authorization_endpoint', 'http://localhost:8000/oauth/authorize');"
echo "   localStorage.setItem('client_id', 'client_q5IkUufL0c6CvzglVVZcIw');"
echo "   localStorage.setItem('redirect_uri', 'http://localhost:8083/callback');"
echo "   localStorage.setItem('authorization_grant_type', 'authorization_code');"
echo "   location.reload();"