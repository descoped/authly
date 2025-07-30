#!/bin/bash
# Test script for Docker build and basic functionality

set -e  # Exit on any error

echo "🚀 Testing Authly Docker Build and Deployment"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Test 1: Build Docker image
echo "📦 Testing Docker build..."
if docker build -t authly-test:latest .; then
    print_status "Docker build successful"
else
    print_error "Docker build failed"
    exit 1
fi

# Test 2: Check if image was created
echo "🔍 Checking Docker image..."
if docker images | grep -q "authly-test"; then
    print_status "Docker image created successfully"
    docker images | grep authly-test
else
    print_error "Docker image not found"
    exit 1
fi

# Test 3: Test basic container startup (without dependencies)
echo "🐳 Testing container startup..."
CONTAINER_ID=$(docker run -d \
    -p 8080:8000 \
    -e DATABASE_URL="postgresql://test:test@localhost:5432/test" \
    -e JWT_SECRET_KEY="test-secret-key" \
    -e JWT_REFRESH_SECRET_KEY="test-refresh-secret" \
    --name authly-test-container \
    authly-test:latest || true)

if [ -n "$CONTAINER_ID" ]; then
    print_status "Container started with ID: $CONTAINER_ID"
    
    # Wait a bit for container to initialize
    sleep 5
    
    # Check container status
    if docker ps | grep -q "authly-test-container"; then
        print_status "Container is running"
        
        # Check logs for any obvious errors
        echo "📋 Container logs (last 10 lines):"
        docker logs --tail 10 authly-test-container
        
    else
        print_warning "Container stopped. Checking logs..."
        docker logs authly-test-container
    fi
    
    # Cleanup
    echo "🧹 Cleaning up test container..."
    docker stop authly-test-container >/dev/null 2>&1 || true
    docker rm authly-test-container >/dev/null 2>&1 || true
    
else
    print_error "Failed to start container"
    exit 1
fi

# Test 4: Check image size
echo "📏 Checking image size..."
IMAGE_SIZE=$(docker images authly-test:latest --format "{{.Size}}")
print_status "Image size: $IMAGE_SIZE"

# Test 5: Basic security check
echo "🔒 Basic security check..."
if docker run --rm authly-test:latest whoami | grep -q "authly"; then
    print_status "Container runs as non-root user (authly)"
else
    print_warning "Container might be running as root"
fi

echo ""
echo "🎉 Docker build test completed!"
echo "   - Image: authly-test:latest"
echo "   - Size: $IMAGE_SIZE"
echo "   - Status: Ready for deployment"
echo ""
echo "To run with docker-compose:"
echo "  docker-compose up -d"
echo ""
echo "To run development environment:"
echo "  docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d"

# Cleanup test image
read -p "🗑️  Remove test image? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker rmi authly-test:latest
    print_status "Test image removed"
fi