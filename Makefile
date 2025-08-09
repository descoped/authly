# Authly Makefile
.PHONY: help standalone-start standalone-stop standalone-info standalone-logs standalone-full test build clean

# Default target
help:
	@echo "Authly - OAuth 2.1 Authorization Server"
	@echo ""
	@echo "Available targets:"
	@echo "  standalone-start    - Start standalone container (core services only)"
	@echo "  standalone-full     - Start with all services (tools, monitoring, authz)"
	@echo "  standalone-stop     - Stop all standalone services"
	@echo "  standalone-info     - Show service URLs and credentials"
	@echo "  standalone-logs     - Follow standalone container logs"
	@echo "  test               - Run test suite"
	@echo "  build              - Build the package"
	@echo "  clean              - Clean build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make standalone-full   # Start everything"
	@echo "  make standalone-info   # Show all service URLs"
	@echo "  make standalone-stop   # Stop everything"

# Standalone targets
standalone-start:
	@./scripts/start-standalone.sh

standalone-full:
	@./scripts/start-standalone.sh --profile tools --profile monitoring --profile authz

standalone-stop:
	@./scripts/stop-standalone.sh

standalone-info:
	@./scripts/show-services-simple.sh

standalone-logs:
	@docker logs authly-standalone -f

# Development targets
test:
	uv run pytest

build:
	uv build

clean:
	rm -rf dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Docker management
docker-build:
	docker compose -f docker-compose.standalone.yml build

docker-clean:
	docker compose -f docker-compose.standalone.yml down -v
	docker system prune -f