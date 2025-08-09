#!/bin/sh
# Setup S6 overlay services for Authly standalone container
set -e

echo "Setting up S6 overlay services..."

# Create directory structure
mkdir -p /etc/s6-overlay/s6-rc.d/user/contents.d \
    /etc/s6-overlay/s6-rc.d/postgres/dependencies.d \
    /etc/s6-overlay/s6-rc.d/keydb/dependencies.d \
    /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d \
    /etc/s6-overlay/s6-rc.d/authly/dependencies.d \
    /etc/s6-overlay/s6-rc.d/services-ready/dependencies.d

# Setup user service bundle
touch /etc/s6-overlay/s6-rc.d/user/contents.d/postgres \
      /etc/s6-overlay/s6-rc.d/user/contents.d/keydb \
      /etc/s6-overlay/s6-rc.d/user/contents.d/authly-init \
      /etc/s6-overlay/s6-rc.d/user/contents.d/authly \
      /etc/s6-overlay/s6-rc.d/user/contents.d/services-ready

# Configure service types
echo "longrun" > /etc/s6-overlay/s6-rc.d/postgres/type
echo "longrun" > /etc/s6-overlay/s6-rc.d/keydb/type
echo "oneshot" > /etc/s6-overlay/s6-rc.d/authly-init/type
echo "longrun" > /etc/s6-overlay/s6-rc.d/authly/type
echo "oneshot" > /etc/s6-overlay/s6-rc.d/services-ready/type

# Setup dependencies
touch /etc/s6-overlay/s6-rc.d/postgres/dependencies.d/base \
      /etc/s6-overlay/s6-rc.d/keydb/dependencies.d/base \
      /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d/postgres \
      /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d/keydb \
      /etc/s6-overlay/s6-rc.d/authly/dependencies.d/authly-init \
      /etc/s6-overlay/s6-rc.d/services-ready/dependencies.d/authly

# Create PostgreSQL run script
cat > /etc/s6-overlay/s6-rc.d/postgres/run << 'EOF'
#!/command/execlineb -P
foreground {
    if { test ! -d /data/postgres/base }
    if { s6-setuidgid authly mkdir -p /data/postgres }
    if { s6-setuidgid authly initdb -D /data/postgres --auth-local=trust --auth-host=md5 }
    s6-setuidgid authly sh -c "echo 'host all all 0.0.0.0/0 md5' >> /data/postgres/pg_hba.conf"
}
s6-setuidgid authly postgres -D /data/postgres -c listen_addresses=* -c shared_buffers=128MB -c max_connections=50 -c unix_socket_directories=/run/postgresql
EOF

# Create KeyDB run script
cat > /etc/s6-overlay/s6-rc.d/keydb/run << 'EOF'
#!/command/execlineb -P
s6-setuidgid authly
keydb-server --dir /data/redis --bind 0.0.0.0 --port 6379 --save "" --appendonly no --protected-mode no --server-threads 2
EOF

# Create Authly init script
cat > /etc/s6-overlay/s6-rc.d/authly-init/up << 'EOF'
#!/command/execlineb -P
foreground { s6-sleep 3 }
foreground {
    s6-setuidgid authly
    sh -c "
    # Create database if it doesn't exist (use local socket with trust auth)
    createdb -h /run/postgresql -U authly authly 2>/dev/null || true
    # Set the authly user password to match DATABASE_URL
    psql -h /run/postgresql -U authly -d authly -c \"ALTER USER authly WITH PASSWORD 'authly';\" 2>/dev/null || true
    # Run the initialization SQL (it has IF NOT EXISTS checks, so safe to run multiple times)
    psql -h /run/postgresql -U authly -d authly -f /docker-entrypoint-initdb.d/init.sql 2>/dev/null || true
    echo 'Database initialized and schema ready'
    "
}
EOF

# Create Authly run script
cat > /etc/s6-overlay/s6-rc.d/authly/run << 'EOF'
#!/command/execlineb -P
cd /app
s6-setuidgid authly
exec python -m authly serve --host 0.0.0.0 --port 8000
EOF

# Create services-ready notification script
cat > /etc/s6-overlay/s6-rc.d/services-ready/up << 'EOF'
#!/command/execlineb -P
foreground { s6-sleep 2 }
foreground {
    sh -c "
    # Wait for Authly to be ready
    timeout 30 sh -c 'until curl -s http://localhost:8000/health >/dev/null 2>&1; do sleep 1; done'
    
    # Get container's hostname/IP
    CONTAINER_IP=$(hostname -i 2>/dev/null | awk '{print $1}' || echo 'container')
    
    # Print service URLs
    echo ''
    echo '================================================================================'
    echo '🚀 All services are ready!'
    echo '================================================================================'
    echo ''
    echo '📦 CORE SERVICES:'
    echo '  • Authly API:        http://localhost:8000'
    echo '                       Username: admin'
    echo \"                       Password: \${AUTHLY_ADMIN_PASSWORD:-admin}\"
    echo '  • API Documentation: http://localhost:8000/docs'
    echo '  • Health Check:      http://localhost:8000/health'
    echo ''
    echo '🗄️ DATABASE SERVICES:'
    echo '  • PostgreSQL:        postgresql://authly:authly@localhost:5432/authly'
    echo '                       (Internal access from container)'
    
    echo ''
    echo '💾 CACHE SERVICES:'
    echo '  • Redis/KeyDB:       redis://localhost:6379'
    echo '                       (No authentication required)'
    
    echo ''
    echo '🛠️ MANAGEMENT TOOLS (if running with --profile tools):'
    echo '  • pgAdmin:           http://localhost:5050'
    echo '                       Username: admin@example.com'
    echo '                       Password: authly'
    echo '  • Redis Commander:   http://localhost:8081'
    echo '                       Username: admin'
    echo '                       Password: admin'
    
    echo ''
    echo '📊 MONITORING SERVICES (if running with --profile monitoring):'
    echo '  • Prometheus:        http://localhost:9090'
    echo '                       (No authentication required)'
    echo '  • Targets:           http://localhost:9090/targets'
    echo '  • Grafana:           http://localhost:3000'
    echo '                       Username: admin'
    echo '                       Password: admin'
    echo '                       Dashboard: Authly Metrics'
    
    echo ''
    echo '🔒 OAUTH PROXY SERVICES (if running with --profile authz):'
    echo '  • PG OAuth Proxy:    localhost:5433'
    echo '                       (Requires OAuth token with database:read/write scopes)'
    echo '  • Redis OAuth Proxy: localhost:6380'
    echo '                       (Requires OAuth token with cache:read/write scopes)'
    
    echo ''
    echo '⚡ QUICK COMMANDS:'
    echo '  Get OAuth Token:'
    echo \"    curl -X POST http://localhost:8000/api/v1/oauth/token \\\\\"
    echo \"      -d 'grant_type=password&username=admin&password=\${AUTHLY_ADMIN_PASSWORD:-admin}'\"
    echo ''
    echo '  Stop All Services:'
    echo '    docker compose -f docker-compose.standalone.yml down'
    echo '================================================================================'
    echo ''
    "
}
EOF

# Make all scripts executable
chmod +x /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/up

echo "✅ S6 overlay services configured"