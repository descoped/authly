# Authly Makefile
.PHONY: help standalone-start standalone-start-all standalone-stop standalone-stop-all standalone-clean standalone-info standalone-logs standalone-full test build clean

# Default target
help:
	@echo "Authly - OAuth 2.1 Authorization Server"
	@echo ""
	@echo "Available targets:"
	@echo "  standalone-start     - Start standalone container (core services only)"
	@echo "  standalone-start-all - Start ALL services (core + tools + monitoring + authz)"
	@echo "  standalone-stop      - Stop core standalone service only"
	@echo "  standalone-stop-all  - Stop ALL services (core + tools + monitoring + authz)"
	@echo "  standalone-clean     - Stop all services and remove all data volumes"
	@echo "  standalone-info      - Show service URLs and credentials"
	@echo "  standalone-logs      - Follow standalone container logs"
	@echo "  test                - Run test suite"
	@echo "  build               - Build the package"
	@echo "  clean               - Clean build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make standalone-start-all # Start everything"
	@echo "  make standalone-info      # Show all service URLs"
	@echo "  make standalone-stop      # Stop core only"
	@echo "  make standalone-stop-all  # Stop everything (keep data)"
	@echo "  make standalone-clean     # Stop all and remove data"
	@echo ""
	@echo "Legacy targets:"
	@echo "  standalone-full      - Same as standalone-start-all (deprecated)"

# Standalone targets
standalone-start:
	@./scripts/start-standalone.sh

standalone-start-all:
	@./scripts/start-standalone.sh --profile tools --profile monitoring --profile authz

# Legacy alias for backward compatibility
standalone-full: standalone-start-all

standalone-stop:
	@./scripts/stop-standalone.sh

standalone-stop-all:
	@./scripts/stop-standalone.sh --all

standalone-clean:
	@./scripts/stop-standalone.sh --all --volumes

standalone-info:
	@./scripts/show-services-plain.sh

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