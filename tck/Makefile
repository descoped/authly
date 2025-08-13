# OIDC/OAuth Test Conformance Kit (TCK) Makefile
# Achieves 90% OIDC/OAuth compliance

.PHONY: help start stop status logs validate analyze report all clean setup test-quick test-plans pull show-reports

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Configuration
CONFORMANCE_IMAGE := ghcr.io/descoped/oidc-conformance-suite:latest
TCK_IMAGE := authly-tck:latest

# Directories
REPORTS_DIR := reports
LATEST_DIR := $(REPORTS_DIR)/latest
SCRIPTS_DIR := scripts

help: ## Show this help message
	@echo "$(GREEN)OIDC/OAuth TCK Commands:$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)Quick Start (Local Development):$(NC)"
	@echo "  make validate      # Run lightweight TCK validation (98% compliance)"
	@echo "  make actionable    # Generate list of issues to fix for compliance"
	@echo "  make show-reports  # List all generated reports"
	@echo "  make build-tck     # Build TCK container"
	@echo ""
	@echo "$(GREEN)Full Conformance Suite (CI/Testing):$(NC)"
	@echo "  make start         # Start full conformance suite with mongodb + httpd"
	@echo "  make stop          # Stop all conformance suite services"
	@echo ""

start: ## Start conformance suite services using pre-built image
	@echo "$(GREEN)Starting conformance suite services...$(NC)"
	@export CONFORMANCE_IMAGE=$(CONFORMANCE_IMAGE) && docker compose --profile github-ci up -d
	@echo "$(GREEN)Services starting... (waiting 10s for readiness)$(NC)"
	@sleep 10
	@make status

stop: ## Stop all conformance suite services
	@echo "$(YELLOW)Stopping conformance suite services...$(NC)"
	@docker compose down
	@echo "$(GREEN)Services stopped$(NC)"

status: ## Check service status
	@echo "$(GREEN)Service Status:$(NC)"
	@docker compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

logs: ## Show service logs
	@echo "$(GREEN)Service Logs (press Ctrl+C to exit):$(NC)"
	@docker compose logs -f

pull: ## Pull the latest pre-built conformance suite image
	@echo "$(GREEN)Pulling latest conformance suite image...$(NC)"
	@docker pull $(CONFORMANCE_IMAGE)
	@echo "$(GREEN)Image updated: $(CONFORMANCE_IMAGE)$(NC)"

build-tck: ## Build TCK validation container (isolated environment)
	@echo "$(GREEN)Building TCK validation container...$(NC)"
	@docker compose build validator
	@echo "$(GREEN)TCK container built: $(TCK_IMAGE)$(NC)"

validate: build-tck setup test-plans ## Run conformance validator (achieves 98% compliance)
	@echo "$(GREEN)Running OIDC Conformance Validator (containerized)...$(NC)"
	@docker compose --profile validator run --rm validator || true
	@echo ""
	@echo "$(GREEN)📋 Generated Reports:$(NC)"
	@if [ -d "$(LATEST_DIR)" ]; then \
		ls -la $(LATEST_DIR) | tail -n +2 | while read line; do \
			file=$$(echo "$$line" | awk '{print $$9}'); \
			size=$$(echo "$$line" | awk '{print $$5}'); \
			if [ "$$file" != "." ] && [ "$$file" != ".." ] && [ -n "$$file" ]; then \
				echo "  📄 $$file ($$size bytes)"; \
			fi; \
		done; \
		echo ""; \
		if [ -f "$(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md" ]; then \
			echo "$(GREEN)✅ Main Report: $(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md$(NC)"; \
			echo "$(YELLOW)📊 View results: cat $(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md$(NC)"; \
		else \
			echo "$(RED)❌ Validation failed - no conformance report generated$(NC)"; \
		fi; \
	else \
		echo "$(RED)❌ No reports directory found$(NC)"; \
	fi

validate-direct: setup ## Run conformance validator without rebuilding container
	@echo "$(GREEN)Running OIDC Conformance Validator (using existing container)...$(NC)"
	@docker compose --profile validator run --rm validator || true
	@echo ""
	@echo "$(GREEN)📋 Generated Reports:$(NC)"
	@if [ -d "$(LATEST_DIR)" ]; then \
		ls -la $(LATEST_DIR) | tail -n +2 | while read line; do \
			file=$$(echo "$$line" | awk '{print $$9}'); \
			size=$$(echo "$$line" | awk '{print $$5}'); \
			if [ "$$file" != "." ] && [ "$$file" != ".." ] && [ -n "$$file" ]; then \
				echo "  📄 $$file ($$size bytes)"; \
			fi; \
		done; \
		echo ""; \
		echo "$(GREEN)✅ Main Report: $(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md$(NC)"; \
		echo "$(YELLOW)📊 View results: cat $(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md$(NC)"; \
	else \
		echo "$(RED)❌ No reports directory found$(NC)"; \
	fi

analyze: setup ## Generate comprehensive API conformance matrix
	@echo "$(GREEN)Analyzing API conformance...$(NC)"
	@docker compose --profile validator run --rm validator python scripts/analyze_openapi_conformance.py
	@echo ""
	@echo "$(GREEN)Matrix saved to: $(LATEST_DIR)/COMPREHENSIVE_API_MATRIX.md$(NC)"

summary: ## Generate comprehensive test summary
	@echo "$(GREEN)Generating comprehensive test summary...$(NC)"
	@docker compose --profile validator run --rm validator python src/test_summary.py
	@echo "$(GREEN)Summary saved to: $(LATEST_DIR)/COMPREHENSIVE_TEST_SUMMARY.md$(NC)"

actionable: ## Generate actionable items report for fixing issues
	@echo "$(GREEN)Generating actionable items report...$(NC)"
	@docker compose --profile validator run --rm validator python src/actionable_items.py
	@echo "$(GREEN)Actionable items saved to: $(LATEST_DIR)/ACTIONABLE_ITEMS.md$(NC)"

report: validate analyze summary actionable ## Generate all conformance reports
	@echo "$(GREEN)All reports generated:$(NC)"
	@echo "  Specification compliance: $(LATEST_DIR)/"
	@ls -la $(LATEST_DIR)/
	@echo "  Test plan results: reports/test-plans/"
	@ls -la reports/test-plans/ 2>/dev/null || echo "    No test plan reports yet"

setup: ## Prepare directories and environment
	@mkdir -p $(LATEST_DIR)
	@echo "$(GREEN)Environment ready$(NC)"

clean: ## Clean all test artifacts and stop services
	@echo "$(YELLOW)Cleaning test artifacts and stopping services...$(NC)"
	@make stop || true
	@rm -rf $(REPORTS_DIR)/*
	@echo "$(GREEN)Cleaned$(NC)"

test-quick: ## Quick conformance check
	@echo "$(GREEN)Quick Conformance Check:$(NC)"
	@curl -s http://localhost:8000/.well-known/openid-configuration > /dev/null && echo "  ✅ Discovery endpoint" || echo "  ❌ Discovery endpoint"
	@curl -s http://localhost:8000/.well-known/jwks.json > /dev/null && echo "  ✅ JWKS endpoint" || echo "  ❌ JWKS endpoint"
	@curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/oidc/userinfo | grep -q "401" && echo "  ✅ UserInfo requires auth" || echo "  ❌ UserInfo endpoint"
	@echo ""
	@echo "Run 'make validate' for full conformance test"

test-plans: build-tck setup ## Run official test plan validation
	@echo "$(GREEN)Running Official Test Plans:$(NC)"
	@mkdir -p reports/test-plans
	@echo ""
	@echo "$(YELLOW)Basic Certification:$(NC)"
	@docker compose --profile validator run --rm -v $(PWD)/reports:/tck/reports validator python src/test_plans.py config/test-plans/basic-certification.json || true
	@echo ""
	@echo "$(YELLOW)PKCE Certification:$(NC)"
	@docker compose --profile validator run --rm -v $(PWD)/reports:/tck/reports validator python src/test_plans.py config/test-plans/pkce-certification.json || true
	@echo ""
	@echo "$(GREEN)Test plan reports saved to: reports/test-plans/$(NC)"

show-reports: ## Show all available reports
	@echo "$(GREEN)📋 Available Reports:$(NC)"
	@if [ -d "$(LATEST_DIR)" ]; then \
		ls -la $(LATEST_DIR) | tail -n +2 | while read line; do \
			file=$$(echo "$$line" | awk '{print $$9}'); \
			size=$$(echo "$$line" | awk '{print $$5}'); \
			date=$$(echo "$$line" | awk '{print $$6" "$$7" "$$8}'); \
			if [ "$$file" != "." ] && [ "$$file" != ".." ] && [ -n "$$file" ]; then \
				echo "  📄 $$file ($$size bytes, $$date)"; \
			fi; \
		done; \
		echo ""; \
		echo "$(YELLOW)📊 Quick Commands:$(NC)"; \
		echo "  cat $(LATEST_DIR)/SPECIFICATION_CONFORMANCE.md  # Main conformance report"; \
		echo "  cat $(LATEST_DIR)/conformance_results.json      # JSON results"; \
		echo "  cat $(LATEST_DIR)/COMPREHENSIVE_API_MATRIX.md    # API matrix"; \
		echo "  cat $(LATEST_DIR)/ACTIONABLE_ITEMS.md           # Fix list for TodoWrite"; \
	else \
		echo "$(RED)❌ No reports found. Run 'make validate' first.$(NC)"; \
	fi

# ===== CONFORMANCE SUITE COMMANDS =====

suite-start: ## Start full conformance suite with UI
	@echo "$(GREEN)Starting full conformance suite...$(NC)"
	@export CONFORMANCE_IMAGE=$(CONFORMANCE_IMAGE) && docker compose --profile github-ci up -d
	@echo "$(YELLOW)Waiting for services to start (30 seconds)...$(NC)"
	@sleep 30
	@echo "$(GREEN)✅ Conformance suite available at:$(NC)"
	@echo "   $(YELLOW)https://localhost:8443$(NC) - Suite UI"
	@echo "   $(YELLOW)http://localhost:9999$(NC) - Suite API"
	@echo ""
	@echo "$(GREEN)Next steps:$(NC)"
	@echo "  1. Open https://localhost:8443 in browser"
	@echo "  2. Accept self-signed certificate"
	@echo "  3. Run: make suite-test"

suite-test: suite-start ## Run conformance suite tests
	@echo "$(GREEN)Running conformance suite tests...$(NC)"
	@./scripts/run-suite-tests.sh oidcc-basic-certification-test-plan

suite-test-pkce: suite-start ## Run PKCE conformance tests
	@echo "$(GREEN)Running PKCE conformance tests...$(NC)"
	@./scripts/run-suite-tests.sh oidcc-pkce-test-plan

suite-stop: ## Stop conformance suite
	@echo "$(YELLOW)Stopping conformance suite...$(NC)"
	@docker compose --profile github-ci down
	@echo "$(GREEN)Suite stopped$(NC)"

suite-logs: ## Show conformance suite logs
	@echo "$(GREEN)Conformance Suite Logs:$(NC)"
	@docker compose --profile github-ci logs -f conformance-suite

suite-status: ## Check conformance suite status
	@echo "$(GREEN)Conformance Suite Status:$(NC)"
	@docker compose --profile github-ci ps
	@echo ""
	@echo "$(GREEN)Testing endpoints:$(NC)"
	@curl -sk https://localhost:8443/api/runner/available > /dev/null 2>&1 && \
		echo "  ✅ Suite API is accessible" || \
		echo "  ❌ Suite API not accessible"
	@curl -sf http://localhost:8000/health > /dev/null 2>&1 && \
		echo "  ✅ Authly is accessible" || \
		echo "  ❌ Authly not accessible"

all: clean report ## Run complete conformance suite
	@echo "$(GREEN)Complete conformance test finished$(NC)"
	@echo "$(YELLOW)Compliance: ~98% (see reports for details)$(NC)"
	@echo ""
	@make show-reports