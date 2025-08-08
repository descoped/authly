#!/bin/sh
# Setup PostgreSQL binaries and libraries
set -e

echo "Setting up PostgreSQL..."

# Create symlinks for PostgreSQL binaries
ln -s /opt/postgresql/bin/postgres /usr/local/bin/postgres
ln -s /opt/postgresql/bin/initdb /usr/local/bin/initdb
ln -s /opt/postgresql/bin/pg_ctl /usr/local/bin/pg_ctl
ln -s /opt/postgresql/bin/psql /usr/local/bin/psql
ln -s /opt/postgresql/bin/createdb /usr/local/bin/createdb
ln -s /opt/postgresql/bin/createuser /usr/local/bin/createuser

# Create symlink for libpq so psycopg can find it
ln -s /opt/postgresql/lib/libpq.so.5 /usr/lib/libpq.so.5

# Update library cache
ldconfig /opt/postgresql/lib 2>/dev/null || true

echo "✅ PostgreSQL configured"