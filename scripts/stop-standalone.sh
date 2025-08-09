#!/bin/bash

# Script to stop Authly standalone services

set -e

COMPOSE_FILE="docker-compose.standalone.yml"

# Function to print colored output
print_status() {
    echo -e "\033[1;36m==>\033[0m $1"
}

print_success() {
    echo -e "\033[1;32m✓\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m✗\033[0m $1"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all|-a)
            STOP_ALL=true
            shift
            ;;
        --volumes|-v)
            REMOVE_VOLUMES=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --all, -a         Stop all services (including tools, monitoring, authz)"
            echo "  --volumes, -v     Remove volumes (deletes all data)"
            echo "  --help, -h        Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running."
    exit 1
fi

# Check if services are running
if ! docker ps | grep -q authly; then
    print_status "No Authly services are running."
    exit 0
fi

# Show current services
print_status "Current running services:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep authly || true
echo ""

# Stop services
if [ "$STOP_ALL" = true ]; then
    print_status "Stopping ALL Authly services (standalone + tools + monitoring + authz)..."
    # Include all profiles to ensure all services are stopped
    PROFILES="--profile tools --profile monitoring --profile authz"
else
    print_status "Stopping Authly standalone service (core only)..."
    # No profiles - just the main standalone service
    PROFILES=""
fi

if [ "$REMOVE_VOLUMES" = true ]; then
    print_status "Removing containers and volumes (all data will be deleted)..."
    if docker compose -f $COMPOSE_FILE $PROFILES down -v; then
        print_success "Services stopped and volumes removed!"
        print_status "All data has been deleted."
    else
        print_error "Failed to stop services"
        exit 1
    fi
else
    if docker compose -f $COMPOSE_FILE $PROFILES down; then
        print_success "Services stopped successfully!"
        echo ""
        if [ "$STOP_ALL" != true ]; then
            echo "Note: Only core service stopped. Use --all to stop all services."
        fi
        echo "Note: Data volumes are preserved. Use --volumes to remove them."
    else
        print_error "Failed to stop services"
        exit 1
    fi
fi