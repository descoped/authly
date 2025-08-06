# OIDC Conformance Testing Makefile
# Provides convenient commands for running conformance tests

.PHONY: help build start stop test report clean all

# Default target
help:
	@echo "OIDC Conformance Testing Commands"
	@echo "================================="
	@echo ""
	@echo "Setup:"
	@echo "  make build    - Build conformance suite JAR"
	@echo "  make start    - Start all services (Authly + conformance suite)"
	@echo "  make stop     - Stop all services"
	@echo ""
	@echo "Testing:"
	@echo "  make test     - Run automated conformance tests"
	@echo "  make basic    - Run basic certification tests"
	@echo "  make pkce     - Run PKCE enforcement tests"
	@echo "  make report   - Generate test report from latest results"
	@echo ""
	@echo "Management:"
	@echo "  make logs     - View service logs"
	@echo "  make status   - Check service status"
	@echo "  make clean    - Clean up test results and containers"
	@echo ""
	@echo "Shortcuts:"
	@echo "  make all      - Build, start, and run all tests"

# Build conformance suite JAR
build:
	@echo "🔨 Building conformance suite JAR..."
	@if [ ! -f "conformance-suite/target/fapi-test-suite.jar" ]; then \
		if [ ! -d "conformance-suite/.git" ]; then \
			git clone https://gitlab.com/openid/conformance-suite.git conformance-suite; \
		fi; \
		cd conformance-suite && \
		docker run --rm \
			-v "$$PWD":/usr/src/mymaven \
			-v "$$HOME/.m2":/root/.m2 \
			-w /usr/src/mymaven \
			maven:3-eclipse-temurin-17 \
			mvn -B clean package -DskipTests=true; \
	else \
		echo "✅ JAR already built"; \
	fi

# Start all services
start: build
	@echo "🚀 Starting all services..."
	@cd .. && ./scripts/start-with-tck.sh

# Stop all services
stop:
	@echo "🛑 Stopping all services..."
	@cd .. && docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml down

# Run automated tests
test:
	@echo "🧪 Running automated conformance tests..."
	@./scripts/run-automated-tests.sh

# Run basic certification tests
basic:
	@echo "📋 Running basic certification tests..."
	@python3 scripts/conformance_client.py --plan basic-certification.json

# Run PKCE tests
pkce:
	@echo "🔐 Running PKCE enforcement tests..."
	@python3 scripts/conformance_client.py --plan pkce-certification.json

# Generate report from latest results
report:
	@echo "📄 Generating report..."
	@if [ -f "results/conformance_report_*.md" ]; then \
		latest=$$(ls -t results/conformance_report_*.md | head -1); \
		echo "Latest report: $$latest"; \
		cat "$$latest"; \
	else \
		echo "No reports found. Run 'make test' first."; \
	fi

# View logs
logs:
	@echo "📜 Viewing service logs..."
	@cd .. && docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml logs -f

# Check status
status:
	@echo "📊 Service Status:"
	@echo "=================="
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(authly|tck-)" || echo "No services running"

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	@rm -rf results/*
	@cd .. && docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.tck.yml down -v

# Run everything
all: build start test report

# Install Python dependencies
deps:
	@echo "📦 Installing Python dependencies..."
	@pip3 install requests urllib3

# Open conformance suite in browser
browse:
	@echo "🌐 Opening conformance suite..."
	@open https://localhost:8443 || xdg-open https://localhost:8443 || echo "Please open https://localhost:8443 in your browser"

# Quick test (minimal tests for CI)
quick-test:
	@echo "⚡ Running quick conformance tests..."
	@python3 scripts/run-conformance-tests.py --quick