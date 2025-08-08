#!/bin/sh
# Setup S6 overlay services for Authly standalone container
set -e

echo "Setting up S6 overlay services..."

# Create directory structure
mkdir -p /etc/s6-overlay/s6-rc.d/user/contents.d \
    /etc/s6-overlay/s6-rc.d/postgres/dependencies.d \
    /etc/s6-overlay/s6-rc.d/keydb/dependencies.d \
    /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d \
    /etc/s6-overlay/s6-rc.d/authly/dependencies.d

# Setup user service bundle
touch /etc/s6-overlay/s6-rc.d/user/contents.d/postgres \
      /etc/s6-overlay/s6-rc.d/user/contents.d/keydb \
      /etc/s6-overlay/s6-rc.d/user/contents.d/authly-init \
      /etc/s6-overlay/s6-rc.d/user/contents.d/authly

# Configure service types
echo "longrun" > /etc/s6-overlay/s6-rc.d/postgres/type
echo "longrun" > /etc/s6-overlay/s6-rc.d/keydb/type
echo "oneshot" > /etc/s6-overlay/s6-rc.d/authly-init/type
echo "longrun" > /etc/s6-overlay/s6-rc.d/authly/type

# Setup dependencies
touch /etc/s6-overlay/s6-rc.d/postgres/dependencies.d/base \
      /etc/s6-overlay/s6-rc.d/keydb/dependencies.d/base \
      /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d/postgres \
      /etc/s6-overlay/s6-rc.d/authly-init/dependencies.d/keydb \
      /etc/s6-overlay/s6-rc.d/authly/dependencies.d/authly-init

# Create PostgreSQL run script
cat > /etc/s6-overlay/s6-rc.d/postgres/run << 'EOF'
#!/command/execlineb -P
foreground {
    if { test ! -d /data/postgres/base }
    if { s6-setuidgid authly mkdir -p /data/postgres }
    s6-setuidgid authly initdb -D /data/postgres --auth-local=trust --auth-host=trust
}
s6-setuidgid authly postgres -D /data/postgres -c listen_addresses=localhost -c shared_buffers=128MB -c max_connections=50 -c unix_socket_directories=/run/postgresql
EOF

# Create KeyDB run script
cat > /etc/s6-overlay/s6-rc.d/keydb/run << 'EOF'
#!/command/execlineb -P
s6-setuidgid authly
keydb-server --dir /data/redis --bind 127.0.0.1 --port 6379 --save "" --appendonly no --protected-mode no --server-threads 2
EOF

# Create Authly init script
cat > /etc/s6-overlay/s6-rc.d/authly-init/up << 'EOF'
#!/command/execlineb -P
foreground { s6-sleep 3 }
foreground {
    s6-setuidgid authly
    sh -c "
    # Create database if it doesn't exist
    createdb -h localhost -U authly authly 2>/dev/null || true
    # Run the initialization SQL (it has IF NOT EXISTS checks, so safe to run multiple times)
    psql -h localhost -U authly -d authly -f /docker-entrypoint-initdb.d/init.sql 2>/dev/null || true
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

# Make all scripts executable
chmod +x /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/up

echo "✅ S6 overlay services configured"