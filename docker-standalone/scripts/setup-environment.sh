#!/bin/sh
# Setup shell environment for interactive use
set -e

echo "Setting up shell environment..."

# Configure shell environment for authly user
cat >> /home/authly/.bashrc << 'EOF'
export PATH="/opt/venv/bin:/usr/local/bin:$PATH"
export PYTHONPATH="/app:/opt/venv/lib/python3.13/site-packages"
export PS1="authly> "
cd /app

# Get Authly version
AUTHLY_VERSION=$(python -c "from authly._version import __version__; print(__version__)" 2>/dev/null || echo "unknown")

echo "================================================================================"
echo "Welcome to Authly Standalone v${AUTHLY_VERSION}"
echo "================================================================================"
echo "⚠️  WARNING: This container uses insecure default secrets for development/testing only!"
echo "   For production, always provide your own secure JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY"
echo ""
echo "Services: PostgreSQL 17, KeyDB (Redis-compatible), and Authly are running"
echo ""
echo "Available commands:"
echo "  • authly --help                   # Main CLI: authly admin client create --name MyApp"
echo "  • authly-admin --help             # Admin shortcuts: authly-admin login (admin/admin), authly-admin client list"
echo "  • simple-auth-flow --help         # Full test: simple-auth-flow"
echo "  • run-end-to-end-test --help      # Full test: run-end-to-end-test comprehensive"
echo "  • unlock-admin-account            # Unlock admin account if locked out"
echo ""
EOF

echo "✅ Shell environment configured"