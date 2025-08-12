# Authly Makefile
.PHONY: help build start stop clean logs test

# Default target
help:
	@echo "Authly - OAuth 2.1 Authorization Server"
	@echo ""
	@echo "Commands:"
	@echo "  build     - Build Docker images"
	@echo "  start     - Start Authly with compliance tester"
	@echo "  stop      - Stop all services"
	@echo "  clean     - Stop and clean all containers/volumes"
	@echo "  logs      - Follow logs"
	@echo "  test      - Run test suite"

# Build Docker images
build:
	@echo "🔨 Building Docker images..."
	@docker compose -f docker-compose.standalone.yml build
	@echo "✅ Build complete!"

# Start/run authly-standalone with compliance tester (build first)
start: build
	@echo "🚀 Starting Authly standalone with compliance tester..."
	@docker stop $$(docker ps -q) 2>/dev/null || true
	@docker rm $$(docker ps -aq) 2>/dev/null || true
	@echo "🔧 Starting Authly server..."
	@AUTHLY_ADMIN_PASSWORD=admin docker compose -f docker-compose.standalone.yml up -d authly-standalone
	@echo "⏳ Waiting for Authly to be ready..."
	@sleep 15
	@echo "🧪 Starting compliance tester (will auto-configure OAuth client)..."
	@AUTHLY_ADMIN_PASSWORD=admin docker compose -f docker-compose.standalone.yml up -d compliance-tester
	@echo "✅ Services started!"
	@echo "📍 Authly: http://localhost:8000"
	@echo "📍 Compliance Tester: http://localhost:8080 (auto-configured)"
	@echo "📍 Admin: admin / admin"

# Alias for start command 
run: start

# Stop all services
stop:
	@echo "⏸️  Stopping services..."
	@docker compose -f docker-compose.standalone.yml down --remove-orphans
	@docker system prune -f --volumes
	@echo "✅ Services stopped and cleaned!"

# Clean everything
clean:
	@echo "🧹 Cleaning all containers and volumes..."
	@docker stop $$(docker ps -q) 2>/dev/null || true
	@docker rm $$(docker ps -aq) 2>/dev/null || true
	@docker compose -f docker-compose.standalone.yml down -v
	@docker system prune -f
	@echo "✅ Cleanup complete!"

# Follow logs
logs:
	@docker logs authly-standalone -f

# Test suite
test:
	uv run pytest