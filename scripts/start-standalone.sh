#!/bin/bash

# Script to start Authly standalone with service information display

set -e

# Default values
COMPOSE_FILE="docker-compose.standalone.yml"
PROFILES=""
SHOW_INFO=true
FOLLOW_LOGS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            if [ -z "$PROFILES" ]; then
                PROFILES="--profile $2"
            else
                PROFILES="$PROFILES --profile $2"
            fi
            shift 2
            ;;
        --no-info)
            SHOW_INFO=false
            shift
            ;;
        --logs|-l)
            FOLLOW_LOGS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --profile NAME    Enable a profile (tools, monitoring, authz)"
            echo "                    Can be specified multiple times"
            echo "  --no-info         Don't show service information after startup"
            echo "  --logs, -l        Follow logs after startup"
            echo "  --help, -h        Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Start core services only"
            echo "  $0 --profile tools                   # Start with tools (pgAdmin, Redis Commander)"
            echo "  $0 --profile tools --profile monitoring  # Start with tools and monitoring"
            echo "  $0 --profile tools --profile monitoring --profile authz  # Start everything"
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

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Build the docker-compose command
COMPOSE_CMD="docker compose -f $COMPOSE_FILE"
if [ -n "$PROFILES" ]; then
    COMPOSE_CMD="$COMPOSE_CMD $PROFILES"
fi

# Start services
print_status "Starting Authly standalone services..."
echo "Command: $COMPOSE_CMD up -d"
echo ""

if $COMPOSE_CMD up -d; then
    print_success "Services started successfully!"
else
    print_error "Failed to start services"
    exit 1
fi

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 5

# Check health of main service
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec authly-standalone curl -f http://localhost:8000/health > /dev/null 2>&1; then
        print_success "Authly API is healthy!"
        break
    fi
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        print_error "Authly API health check failed after $max_attempts attempts"
        exit 1
    fi
    echo -n "."
    sleep 2
done
echo ""

# Show service information if requested
if [ "$SHOW_INFO" = true ]; then
    if [ -f "./scripts/show-services-simple.sh" ]; then
        echo ""
        ./scripts/show-services-simple.sh
    else
        echo ""
        print_status "Service URLs and Credentials:"
        echo ""
        echo "  Authly API:       http://localhost:8000"
        echo "  API Docs:         http://localhost:8000/docs"
        echo "  Admin Login:      admin / ${AUTHLY_ADMIN_PASSWORD:-admin}"
        echo ""
        
        if docker ps | grep -q authly-pgadmin; then
            echo "  pgAdmin:          http://localhost:5050"
            echo "                    admin@example.com / authly"
        fi
        
        if docker ps | grep -q authly-redis-commander; then
            echo "  Redis Commander:  http://localhost:8081"
            echo "                    admin / admin"
        fi
        
        if docker ps | grep -q authly-prometheus; then
            echo "  Prometheus:       http://localhost:9090"
        fi
        
        if docker ps | grep -q authly-grafana; then
            echo "  Grafana:          http://localhost:3000"
            echo "                    admin / admin"
        fi
        echo ""
    fi
fi

# Follow logs if requested
if [ "$FOLLOW_LOGS" = true ]; then
    print_status "Following logs (Ctrl+C to stop)..."
    docker logs authly-standalone -f
fi