# OIDC Conformance Testing Makefile
# Properly handles external dependencies without modifying them

.PHONY: help init clone build start stop test clean status

# Configuration
CONFORMANCE_REPO := https://gitlab.com/openid/conformance-suite.git
CONFORMANCE_DIR := conformance-suite
CONFORMANCE_VERSION := master  # Pin to specific version in production
BUILD_DIR := conformance-suite-build

help:
	@echo "OIDC Conformance Testing Commands"
	@echo "================================="
	@echo ""
	@echo "Setup:"
	@echo "  make init     - Initialize conformance suite (clone + build)"
	@echo "  make clone    - Clone conformance suite repository"
	@echo "  make build    - Build conformance suite from source"
	@echo "  make start    - Start all services"
	@echo "  make stop     - Stop all services"
	@echo ""
	@echo "Testing:"
	@echo "  make test     - Run automated conformance tests"
	@echo "  make quick    - Run quick validation tests"
	@echo ""
	@echo "Management:"
	@echo "  make status   - Check service status"
	@echo "  make logs     - View service logs"
	@echo "  make clean    - Clean up everything"
	@echo "  make reset    - Reset conformance suite to upstream"

# Initialize everything
init: build
	@echo "✅ Conformance suite initialized"

# Clone conformance suite if not exists (optional for local reference)
clone:
	@if [ ! -d "$(CONFORMANCE_DIR)/.git" ]; then \
		echo "📦 Cloning conformance suite for reference..."; \
		git clone $(CONFORMANCE_REPO) $(CONFORMANCE_DIR); \
		cd $(CONFORMANCE_DIR) && git checkout $(CONFORMANCE_VERSION); \
	else \
		echo "✅ Conformance suite already cloned"; \
	fi

# Build conformance suite using Docker (no local dependencies)
build:
	@echo "🔨 Building conformance suite with Docker..."
	@cd $(BUILD_DIR) && docker compose build tck-server
	@echo "✅ Conformance suite built"

# Start services using our build configuration
start: build
	@echo "🚀 Starting services..."
	@cd $(BUILD_DIR) && docker compose up -d
	@echo "✅ Services started"
	@echo "   Conformance Suite: https://localhost:9443"

# Stop services
stop:
	@echo "🛑 Stopping services..."
	@cd $(BUILD_DIR) && docker compose down
	@echo "✅ Services stopped"

# Run conformance tests
test:
	@echo "🧪 Running conformance tests..."
	@python3 scripts/run-conformance-tests.py

# Quick validation
quick:
	@echo "⚡ Running quick tests..."
	@python3 scripts/quick-test.py

# Check status
status:
	@echo "📊 Service Status:"
	@docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "tck-" || echo "No TCK services running"

# View logs
logs:
	@cd $(BUILD_DIR) && docker compose logs -f

# Clean everything
clean: stop
	@echo "🧹 Cleaning up..."
	@rm -rf $(CONFORMANCE_DIR)/target
	@cd $(BUILD_DIR) && docker compose down -v
	@rm -rf results/*
	@echo "✅ Cleaned"

# Reset conformance suite to upstream (removes local changes)
reset:
	@echo "🔄 Resetting conformance suite to upstream..."
	@if [ -d "$(CONFORMANCE_DIR)/.git" ]; then \
		cd $(CONFORMANCE_DIR) && \
		git stash && \
		git checkout $(CONFORMANCE_VERSION) && \
		git reset --hard origin/$(CONFORMANCE_VERSION) && \
		git clean -fd; \
		echo "✅ Reset complete"; \
	else \
		echo "❌ Conformance suite not cloned"; \
	fi

# Update to latest upstream
update:
	@echo "📥 Updating conformance suite..."
	@if [ -d "$(CONFORMANCE_DIR)/.git" ]; then \
		cd $(CONFORMANCE_DIR) && \
		git fetch origin && \
		git checkout $(CONFORMANCE_VERSION) && \
		git pull origin $(CONFORMANCE_VERSION); \
		echo "✅ Updated to latest"; \
	else \
		make clone; \
	fi

# Check for local modifications
check-modifications:
	@echo "🔍 Checking for local modifications..."
	@if [ -d "$(CONFORMANCE_DIR)/.git" ]; then \
		cd $(CONFORMANCE_DIR) && \
		if git diff --quiet && git diff --cached --quiet; then \
			echo "✅ No local modifications"; \
		else \
			echo "⚠️  Local modifications detected:"; \
			git status --short; \
		fi \
	fi

# Development: Open conformance suite in browser
browse:
	@echo "🌐 Opening conformance suite..."
	@open https://localhost:8443 || xdg-open https://localhost:8443