APP_NAME := auth-service
DOCKER_IMAGE := $(APP_NAME)
DOCKER_TAG := latest
GO_VERSION := 1.21
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m

.PHONY: help build run test clean docker-build docker-run docker-stop deps lint format check-deps

help:
	@echo "$(BLUE)Auth Service - Available commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

deps:
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	go mod download
	go mod tidy

build:
	@echo "$(YELLOW)Building application...$(NC)"
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/$(APP_NAME) ./cmd/server
	@echo "$(GREEN)Build completed: bin/$(APP_NAME)$(NC)"

run:
	@echo "$(YELLOW)Starting application...$(NC)"
	go run ./cmd/server/main.go

test:
	@echo "$(YELLOW)Running tests...$(NC)"
	go test -v ./...

test-coverage:
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

lint:
	@echo "$(YELLOW)Running linter...$(NC)"
	golangci-lint run

format:
	@echo "$(YELLOW)Formatting code...$(NC)"
	go fmt ./...
	goimports -w .

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean

docker-build:
	@echo "$(YELLOW)Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(NC)"

docker-run:
	@echo "$(YELLOW)Starting services with Docker Compose...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Services started. Check logs with: make docker-logs$(NC)"

docker-stop:
	@echo "$(YELLOW)Stopping Docker Compose services...$(NC)"
	docker-compose down
	@echo "$(GREEN)Services stopped$(NC)"

docker-logs:
	docker-compose logs -f

docker-clean:
	@echo "$(YELLOW)Cleaning Docker resources...$(NC)"
	docker-compose down -v --rmi all --remove-orphans
	docker system prune -f

# Database commands
db-migrate: ## Run database migrations (legacy - use db-migrate-up)
	@echo "$(YELLOW)Running database migrations...$(NC)"
	go run ./cmd/server/main.go -migrate-only

db-migrate-up: ## Run versioned database migrations
	@echo "$(YELLOW)Running versioned database migrations...$(NC)"
	go run ./cmd/migrate/main.go

db-migrate-status:
	@echo "$(YELLOW)Checking migration status...$(NC)"
	@if [ -z "$(DATABASE_URL)" ]; then \
		echo "$(RED)DATABASE_URL environment variable is not set$(NC)"; \
		exit 1; \
	fi
	@psql "$(DATABASE_URL)" -c "SELECT version, description, applied_at FROM schema_migrations ORDER BY version;" 2>/dev/null || \
		echo "$(YELLOW)No migrations table found. Run 'make db-migrate-up' first.$(NC)"

db-migrate-create:
	@if [ -z "$(NAME)" ]; then \
		echo "$(RED)Usage: make db-migrate-create NAME=description$(NC)"; \
		exit 1; \
	fi
	@NEXT_VERSION=$$(printf "%03d" $$(($$(ls migrations/ | grep -E '^[0-9]+_' | sed 's/^0*//' | sed 's/_.*$$//' | sort -n | tail -1) + 1))); \
	FILENAME="migrations/$${NEXT_VERSION}_$(NAME).sql"; \
	echo "-- Migration: $${NEXT_VERSION}_$(NAME).sql" > $$FILENAME; \
	echo "-- Description: $(NAME)" >> $$FILENAME; \
	echo "-- Created: $$(date +%Y-%m-%d)" >> $$FILENAME; \
	echo "-- Dependencies: Previous migrations" >> $$FILENAME; \
	echo "" >> $$FILENAME; \
	echo "-- Add your SQL here" >> $$FILENAME; \
	echo "" >> $$FILENAME; \
	echo "-- Record this migration" >> $$FILENAME; \
	echo "INSERT INTO schema_migrations (version, description)" >> $$FILENAME; \
	echo "VALUES ('$${NEXT_VERSION}', '$(NAME)')" >> $$FILENAME; \
	echo "ON CONFLICT (version) DO NOTHING;" >> $$FILENAME; \
	echo "$(GREEN)Created migration file: $$FILENAME$(NC)"

db-reset: ## Reset database (WARNING: This will delete all data)
	@echo "$(RED)WARNING: This will delete all data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose exec postgres psql -U postgres -d auth_service -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"; \
		echo "$(GREEN)Database reset completed$(NC)"; \
	else \
		echo "$(YELLOW)Database reset cancelled$(NC)"; \
	fi

# Development tools
dev-setup:
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	@if ! command -v go >/dev/null 2>&1; then \
		echo "$(RED)Go is not installed. Please install Go $(GO_VERSION) or later.$(NC)"; \
		exit 1; \
	fi
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "$(RED)Docker is not installed. Please install Docker.$(NC)"; \
		exit 1; \
	fi
	@if ! command -v docker-compose >/dev/null 2>&1; then \
		echo "$(RED)Docker Compose is not installed. Please install Docker Compose.$(NC)"; \
		exit 1; \
	fi
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	cp env.example .env
	@echo "$(GREEN)Development environment setup completed!$(NC)"
	@echo "$(YELLOW)Don't forget to configure your .env file with OAuth credentials$(NC)"

check-deps:
	@echo "$(YELLOW)Checking dependencies...$(NC)"
	@command -v go >/dev/null 2>&1 || (echo "$(RED)Go is not installed$(NC)" && exit 1)
	@command -v docker >/dev/null 2>&1 || (echo "$(RED)Docker is not installed$(NC)" && exit 1)
	@command -v docker-compose >/dev/null 2>&1 || (echo "$(RED)Docker Compose is not installed$(NC)" && exit 1)
	@echo "$(GREEN)All dependencies are installed$(NC)"

# Production commands
prod-build:
	@echo "$(YELLOW)Building for production...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-w -s -X main.version=$(shell git describe --tags --always)" \
		-o bin/$(APP_NAME) ./cmd/server
	@echo "$(GREEN)Production build completed$(NC)"

prod-docker:
	@echo "$(YELLOW)Building production Docker image...$(NC)"
	docker build -f Dockerfile.prod -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(GREEN)Production Docker image built$(NC)"

# Utility commands
logs:
	docker-compose logs -f auth-service

health:
	@echo "$(YELLOW)Checking service health...$(NC)"
	@curl -s http://localhost:8080/health | jq . || echo "$(RED)Service is not responding$(NC)"

api-docs:
	@echo "$(YELLOW)Generating API documentation...$(NC)"
	@if command -v swag >/dev/null 2>&1; then \
		swag init -g cmd/server/main.go -o docs/; \
		echo "$(GREEN)API documentation generated in docs/$(NC)"; \
	else \
		echo "$(RED)swag is not installed. Install with: go install github.com/swaggo/swag/cmd/swag@latest$(NC)"; \
	fi

# Git hooks
install-hooks:
	@echo "$(YELLOW)Installing git hooks...$(NC)"
	@mkdir -p .git/hooks
	@echo '#!/bin/sh\nmake format lint test' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(GREEN)Git hooks installed$(NC)"

# Release commands
tag:
	@if [ -z "$(VERSION)" ]; then \
		echo "$(RED)VERSION is required. Usage: make tag VERSION=v1.0.0$(NC)"; \
		exit 1; \
	fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "$(GREEN)Tag $(VERSION) created and pushed$(NC)"

release: prod-build prod-docker
	@echo "$(GREEN)Release build completed$(NC)"
