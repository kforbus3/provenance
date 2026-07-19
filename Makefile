# Fleet Terminal — developer entrypoints.
# Everything runs through Docker so no local Go/Postgres toolchain is required.

# NOTE: --env-file .env is REQUIRED. Compose otherwise loads .env from the
# compose file's directory (deploy/compose/), not the repo root where our .env
# lives — silently ignoring all FLEET_* settings and falling back to defaults.
COMPOSE        := docker compose --env-file .env -f deploy/compose/docker-compose.yml
COMPOSE_FABRIC := $(COMPOSE) -f deploy/compose/docker-compose.testfabric.yml
COMPOSE_SINGLE := $(COMPOSE) -f deploy/compose/docker-compose.jumphost.yml

# Version stamped into the binary (compose passes it as the VERSION build arg).
# Derived from the nearest git tag so a tagged deploy shows e.g. "v0.6.1" instead
# of "dev"; falls back to a short SHA, then "dev" outside a git checkout. Override
# by setting FLEET_VERSION in the environment. Exported so the compose subprocess
# sees it during --build.
FLEET_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
export FLEET_VERSION

# State that the database backup does NOT capture: the jump host's WireGuard
# keypair/peers + SSH host key, and on-disk session recordings & scan reports.
# PROJECT matches `name:` in docker-compose.yml (the Docker volume-name prefix).
PROJECT        := fleet-terminal
STATE_VOLUMES  := jump_wg jump_ssh recordings scans
VOL_BACKUP_DIR ?= ./volume-backups

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "created .env")

.PHONY: up
up: env ## Build & start the full stack + test fabric
	$(COMPOSE_FABRIC) up -d --build

.PHONY: up-app
up-app: env ## Start only the application stack (no test fabric)
	$(COMPOSE) up -d --build

.PHONY: up-single
up-single: env ## Single-server production: (re)build & start the WHOLE stack incl. the jump host
	$(COMPOSE_SINGLE) up -d --build
	@echo "Single-server stack up. Set FLEET_WG_JUMP_ENDPOINT to the host's address:port"
	@echo "(public IP/DNS, or LAN IP if managed hosts are internal) and open that UDP port."
	@echo "NOTE: this recreated the jump host, so the WireGuard overlay re-establishes and"
	@echo "hosts may show offline for a minute or two. For code-only updates use 'make redeploy-single'."

.PHONY: redeploy-single
redeploy-single: env ## Update app code (backend/frontend/scanner) in place, leaving the jump host + WireGuard overlay UP (no host-offline blip)
	$(COMPOSE_SINGLE) up -d --build backend frontend grype-scanner
	@echo "App services updated. The jump host and overlay were left running, so hosts stay reachable."

.PHONY: ps-single
ps-single: ## Single-server: show running services
	$(COMPOSE_SINGLE) ps

.PHONY: logs-single
logs-single: ## Single-server: tail logs
	$(COMPOSE_SINGLE) logs -f --tail=100

.PHONY: down-single
down-single: ## Single-server: stop the stack (data volumes preserved)
	$(COMPOSE_SINGLE) down

.PHONY: backup-volumes
backup-volumes: ## Archive jump-host + recordings/scans volumes to $(VOL_BACKUP_DIR) (complements the DB backup)
	@mkdir -p $(VOL_BACKUP_DIR)
	@for v in $(STATE_VOLUMES); do \
	  if docker volume inspect $(PROJECT)_$$v >/dev/null 2>&1; then \
	    echo "archiving $(PROJECT)_$$v -> $(VOL_BACKUP_DIR)/$$v.tar.gz"; \
	    docker run --rm -v $(PROJECT)_$$v:/v:ro -v $(abspath $(VOL_BACKUP_DIR)):/backup busybox \
	      tar czf /backup/$$v.tar.gz -C /v . ; \
	  else echo "skip $$v ($(PROJECT)_$$v does not exist yet)"; fi ; \
	done
	@echo "Done. Store $(VOL_BACKUP_DIR)/ off-host alongside your encrypted DB backup."
	@echo "Tip: run 'make down-single' first for a fully consistent snapshot."

.PHONY: restore-volumes
restore-volumes: ## Restore jump-host + recordings/scans volumes from $(VOL_BACKUP_DIR) (stack should be down)
	@for v in $(STATE_VOLUMES); do \
	  if [ -f $(VOL_BACKUP_DIR)/$$v.tar.gz ]; then \
	    echo "restoring $(VOL_BACKUP_DIR)/$$v.tar.gz -> $(PROJECT)_$$v"; \
	    docker volume create $(PROJECT)_$$v >/dev/null; \
	    docker run --rm -v $(PROJECT)_$$v:/v -v $(abspath $(VOL_BACKUP_DIR)):/backup busybox \
	      sh -c 'rm -rf /v/* /v/.[!.]* /v/..?* 2>/dev/null; tar xzf /backup/'"$$v"'.tar.gz -C /v' ; \
	  else echo "skip $$v (no $(VOL_BACKUP_DIR)/$$v.tar.gz)"; fi ; \
	done
	@echo "Done. Now restore the database, then: make up-single"

.PHONY: trust
trust: ## Seed the test-fabric nodes with the backend's CA (run once after `make up`)
	@bash scripts/install-ca.sh

.PHONY: down
down: ## Stop the stack
	$(COMPOSE_FABRIC) down

.PHONY: clean
clean: ## Stop the stack and remove volumes (DESTROYS DATA)
	$(COMPOSE_FABRIC) down -v

.PHONY: logs
logs: ## Tail logs
	$(COMPOSE_FABRIC) logs -f --tail=100

.PHONY: ps
ps: ## Show running services
	$(COMPOSE_FABRIC) ps

.PHONY: build
build: ## Build all images
	$(COMPOSE_FABRIC) build

.PHONY: backend-build
backend-build: ## Compile the backend in a throwaway Go container
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.23-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go build ./..."

.PHONY: enroll-agent
enroll-agent: ## Build the SSH-agent enrollment bridge for this machine's platform
	docker run --rm -v $(PWD)/backend:/src -w /src -e CGO_ENABLED=0 golang:1.23-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go build -o /src/bin/fleet-enroll-agent ./cmd/fleet-enroll-agent"
	@echo "Built backend/bin/fleet-enroll-agent — distribute to operators."

.PHONY: enroll-agent-all
enroll-agent-all: ## Cross-compile the bridge for macOS/Linux/Windows (operators' laptops)
	docker run --rm -v $(PWD)/backend:/src -w /src -e CGO_ENABLED=0 golang:1.23-alpine sh -c '\
	  apk add --no-cache git >/dev/null; \
	  set -e; \
	  for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	    os=$${t%/*}; arch=$${t#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	    out=/src/bin/fleet-enroll-agent-$$os-$$arch$$ext; \
	    echo "building $$out"; \
	    GOOS=$$os GOARCH=$$arch GOFLAGS=-mod=mod go build -trimpath -ldflags "-s -w" -o $$out ./cmd/fleet-enroll-agent; \
	  done'
	@echo "Built backend/bin/fleet-enroll-agent-* — distribute the right one per operator:"
	@echo "  macOS Apple Silicon: fleet-enroll-agent-darwin-arm64"
	@echo "  macOS Intel:         fleet-enroll-agent-darwin-amd64"
	@echo "  Linux x86_64:        fleet-enroll-agent-linux-amd64"
	@echo "  Linux ARM64:         fleet-enroll-agent-linux-arm64"
	@echo "  Windows x86_64:      fleet-enroll-agent-windows-amd64.exe"

.PHONY: test
test: backend-test frontend-test ## Run all tests

.PHONY: backend-test
backend-test: ## Run Go unit + integration tests
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.23-alpine \
	  sh -c "apk add --no-cache git gcc musl-dev openssh-client >/dev/null && GOFLAGS=-mod=mod go test ./..."

.PHONY: frontend-test
frontend-test: ## Run frontend unit tests
	docker run --rm -v $(PWD)/frontend:/app -w /app node:22-alpine \
	  sh -c "npm ci && npm run test -- --run"

.PHONY: lint
lint: ## Run Go vet
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.23-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go vet ./..."

.PHONY: tidy
tidy: ## Run go mod tidy and write go.sum back to the repo
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.23-alpine \
	  sh -c "apk add --no-cache git >/dev/null && go mod tidy"

.PHONY: e2e
e2e: ## Run Playwright end-to-end tests against the running stack
	-$(COMPOSE_FABRIC) exec -T backend fleetctl create-admin e2euser 'E2e-Pass-12345!' 2>/dev/null
	docker run --rm --network host -v $(PWD)/frontend:/app -w /app \
	  -e E2E_BASE=$${E2E_BASE:-http://localhost:5173} \
	  -e E2E_USER=e2euser -e E2E_PASS='E2e-Pass-12345!' \
	  mcr.microsoft.com/playwright:v1.48.2-jammy \
	  sh -c "npm install >/dev/null 2>&1 && npx playwright test"

.PHONY: load
load: ## Run the k6 load smoke test against the running stack (override USER/PASS)
	docker run --rm --network host -v $(PWD)/deploy/load:/load \
	  -e BASE=$${BASE:-http://localhost:8080} \
	  -e USER=$${FLEET_LOAD_USER:-admin} \
	  -e PASS=$${FLEET_LOAD_PASS:-Sup3r-Secret-Pass!} \
	  grafana/k6 run /load/k6-smoke.js

.PHONY: assistant-docs
assistant-docs: ## Regenerate the assistant's embedded documentation index from docs/
	docker run --rm -v $(PWD):/repo -w /repo/backend/internal/assistant golang:1.23-alpine \
	  go run gendocs.go -docs /repo/docs -out docs_generated.go
