#!/bin/bash

echo "Testing OIDC Debugger with fresh browser session"
echo "================================================"
echo ""
echo "The OIDC Debugger stores values in browser localStorage."
echo "If you've used it before, it may be showing old values."
echo ""
echo "To see the new Authly defaults, try one of these:"
echo ""
echo "1. Open in Incognito/Private browsing mode:"
echo "   Chrome: Command+Shift+N (Mac) or Ctrl+Shift+N (Windows/Linux)"
echo "   Firefox: Command+Shift+P (Mac) or Ctrl+Shift+P (Windows/Linux)"
echo "   Safari: Command+Shift+N"
echo ""
echo "2. Clear localStorage for this site:"
echo "   - Open Developer Tools (F12)"
echo "   - Go to Application/Storage tab"
echo "   - Find localStorage for http://localhost:8083"
echo "   - Right-click and Clear"
echo ""
echo "3. Use this command to clear localStorage via console:"
echo "   localStorage.clear(); location.reload();"
echo ""
echo "Testing what the server actually serves..."
echo ""

# Fetch the debugger page and check for Authly endpoints
echo -n "Checking served HTML for Authly endpoints... "
RESPONSE=$(curl -s http://localhost:8083/debugger.html)

# The JavaScript should have our Authly endpoints
if curl -s http://localhost:8083/js/debugger.js | grep -q "http://localhost:8000/oauth/authorize"; then
    echo "✅ Authly endpoints are in the JavaScript!"
else
    echo "❌ Default endpoints still present"
fi

echo ""
echo "Current endpoints in the built JavaScript:"
echo "==========================================="
docker exec authly-oidc-debugger grep "localStorage.setItem.*endpoint.*http" /usr/src/app/client/public/js/debugger.js | grep -v '//' | head -7

echo ""
echo "Please try opening http://localhost:8083 in an incognito/private window"
echo "to see the new default values!"