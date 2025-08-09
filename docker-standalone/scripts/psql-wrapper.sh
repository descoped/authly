#!/bin/sh
# Wrapper script for psql to connect directly to authly database
exec /opt/postgresql/bin/psql -h /run/postgresql -U authly -d authly "$@"