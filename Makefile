# Provenance — developer entrypoints.
# Everything runs through Docker so no local Go/Postgres toolchain is required.

# NOTE: --env-file .env is REQUIRED. Compose otherwise loads .env from the
# compose file's directory (deploy/compose/), not the repo root where our .env
# lives — silently ignoring all PROV_* settings and falling back to defaults.
COMPOSE        := docker compose --env-file .env -f deploy/compose/docker-compose.yml
COMPOSE_FABRIC := $(COMPOSE) -f deploy/compose/docker-compose.testfabric.yml
COMPOSE_SINGLE := $(COMPOSE) -f deploy/compose/docker-compose.jumphost.yml

# Version stamped into the binary (compose passes it as the VERSION build arg).
# Derived from the nearest git tag so a tagged deploy shows e.g. "v0.6.1" instead
# of "dev"; falls back to a short SHA, then "dev" outside a git checkout. Override
# by setting PROV_VERSION in the environment. Exported so the compose subprocess
# sees it during --build.
PROV_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
export PROV_VERSION

# State that the database backup does NOT capture: the jump host's WireGuard
# keypair/peers + SSH host key, and on-disk session recordings & scan reports.
# PROJECT matches `name:` in docker-compose.yml (the Docker volume-name prefix).
PROJECT        := provenance
STATE_VOLUMES  := jump_wg jump_ssh recordings scans
VOL_BACKUP_DIR ?= ./volume-backups

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && chmod 600 .env && echo "created .env (mode 0600)")
	@# .env holds every master secret — keep it unreadable by other local users.
	@chmod 600 .env 2>/dev/null || true

.PHONY: up
up: env ## Build & start the full stack + test fabric
	$(COMPOSE_FABRIC) up -d --build

.PHONY: up-app
up-app: env ## Start only the application stack (no test fabric)
	$(COMPOSE) up -d --build

.PHONY: up-imaging
up-imaging: env ## Start the app stack WITH the image builder (privileged; needs the Docker socket)
	$(COMPOSE) --profile imaging up -d --build
	@echo "Builder up. It holds the Docker socket so the backend does not, and it reaches"
	@echo "that socket through the allowlisting proxy -- building an image means starting a"
	@echo "PRIVILEGED container, so this is deliberately not part of the default stack."
	@echo "Set PROV_BUILDER_RUNNER_URL=http://builder-runner:8000 and a matching"
	@echo "PROV_BUILDER_RUNNER_TOKEN on both services, or the build routes answer 501."

.PHONY: up-single
up-single: env ## Single-server production: (re)build & start the WHOLE stack incl. the jump host
	$(COMPOSE_SINGLE) up -d --build
	@echo "Single-server stack up. Set PROV_WG_JUMP_ENDPOINT to the host's address:port"
	@echo "(public IP/DNS, or LAN IP if managed hosts are internal) and open that UDP port."
	@echo "NOTE: this recreated the jump host, so the WireGuard overlay re-establishes and"
	@echo "hosts may show offline for a minute or two. For code-only updates use 'make redeploy-single'."

.PHONY: redeploy-single
redeploy-single: env ## Update every locally built app service in place, leaving the jump host + overlay UP (no host-offline blip)
	@# EVERY service with a `build:` stanza except the jump host, which is excluded
	@# on purpose (recreating it drops the overlay and takes hosts offline).
	@#
	@# builder-runner and dockerproxy were missing from this list, and the symptom is
	@# the worst kind: a fix to the imaging runner or to the socket proxy's rules is
	@# committed, deployed, reported as deployed -- and the old code keeps running,
	@# because nothing rebuilt it. That is how a sidecar-cleanup fix shipped to a
	@# 27-hour-old container. If a service is built here, it belongs in this list.
	$(COMPOSE_SINGLE) up -d --build backend frontend grype-scanner ansible-runner prov-updater builder-runner dockerproxy
	@echo "App services updated. The jump host and overlay were left running, so hosts stay reachable."
	@# This target deliberately does not touch the jump host — which means a release
	@# that changes its ports, volumes or entrypoint (e.g. publishing the OpenVPN port)
	@# is NOT applied here, and the symptom is a feature that silently does not work
	@# rather than an error. Say so when the compose file is newer than the running
	@# container. Best-effort: any tool missing (non-GNU date, no docker) just skips.
	@started=$$(docker inspect -f '{{.State.StartedAt}}' provenance-jumphost-1 2>/dev/null); \
	 if [ -n "$$started" ]; then \
	   s=$$(date -u -d "$$started" +%s 2>/dev/null || echo 0); \
	   f=$$(stat -c %Y deploy/compose/docker-compose.jumphost.yml 2>/dev/null || echo 0); \
	   if [ "$$s" -gt 0 ] && [ "$$f" -gt "$$s" ]; then \
	     echo ""; \
	     echo "WARNING: the jump host predates deploy/compose/docker-compose.jumphost.yml."; \
	     echo "         Its ports, volumes and entrypoint are NOT updated by this target,"; \
	     echo "         so changes there (e.g. the OpenVPN port) are not in effect."; \
	     echo "         Run 'make up-single' to recreate it (brief overlay re-establish)."; \
	   fi; \
	 fi

# --- Release bundling (in-UI upgrade system) -------------------------------------
# Produce a single signed .provup file that operators upload (or later pull) to
# upgrade in place through the UI. Requires a release private key from
# `provctl release keygen` — keep it OFFLINE. Override BUNDLE_VERSION/BUNDLE_FROM.
# BUNDLE_FROM defaults to 0.0.0 — policy: every bundle is full-stack and
# installable from ANY older version (no stepping-stone installs); downgrades are
# still refused by the version check itself. Raise it only for a release that
# genuinely cannot upgrade an old install in one hop (e.g. a destructive
# migration that requires an intermediate version).
BUNDLE_VERSION ?= $(PROV_VERSION)
BUNDLE_FROM    ?= 0.0.0
BUNDLE_KEY     ?= release.key
# The signing step runs from backend/, so the key path has to be resolved before
# the directory changes under it. abspath resolves a relative path against the
# repo root and leaves an already-absolute one alone — the key normally lives
# OUTSIDE the repo (~/prov-release/release.key), which a bare ../ prefix
# silently turned into a nonexistent path.
BUNDLE_KEY_ABS := $(abspath $(BUNDLE_KEY))
BUNDLE_OUT     ?= provenance-$(BUNDLE_VERSION).provup
# Same resolution as BUNDLE_KEY, and for the same reason: the build step runs from
# backend/, so a bare ../ prefix turns an ABSOLUTE output path into ..//Users/... and
# the whole build is thrown away at the final write. The signing key lives outside the
# repo and so, usually, does the bundle.
BUNDLE_OUT_ABS := $(abspath $(BUNDLE_OUT))
BUNDLE_COMPONENTS ?= backend,frontend,grype-scanner,ansible-runner,prov-updater
# Bundles deploy to servers, so pin the image platform regardless of the build
# host's architecture (an Apple Silicon Mac otherwise emits arm64 images that
# crash-loop with 'exec format error' on an amd64 host and get rolled back).
# Override for arm64 deployment targets.
BUNDLE_PLATFORM ?= linux/amd64

.PHONY: bundle
bundle: ## Build + sign a .provup upgrade bundle (needs BUNDLE_VERSION, BUNDLE_FROM, BUNDLE_KEY)
	@test -f $(BUNDLE_KEY_ABS) || (echo "missing $(BUNDLE_KEY_ABS) — run: docker run --rm -v \$$PWD/backend:/app -w /app golang:1.26 go run ./cmd/provctl release keygen"; exit 1)
	PROV_VERSION=$(BUNDLE_VERSION) DOCKER_DEFAULT_PLATFORM=$(BUNDLE_PLATFORM) $(COMPOSE_SINGLE) build $(subst $(comma), ,$(BUNDLE_COMPONENTS))
	@for c in $(subst $(comma), ,$(BUNDLE_COMPONENTS)); do \
	  docker tag $(PROJECT)-$$c $(PROJECT)-$$c:$(BUNDLE_VERSION); \
	done
	cd backend && go run ./cmd/provctl release build \
	  --version $(BUNDLE_VERSION) --from $(BUNDLE_FROM) \
	  --key $(BUNDLE_KEY_ABS) --out $(BUNDLE_OUT_ABS) --components $(BUNDLE_COMPONENTS)
	@echo "Built $(BUNDLE_OUT_ABS). Upload it in the UI (Settings -> Updates) to upgrade in place."

.PHONY: test-upgrade-schema
test-upgrade-schema: ## Verify an OLD database upgrades to the same schema as a fresh install
	@deploy/scripts/upgrade-schema-check.sh $(FROM_TAG)

.PHONY: test-db
test-db: ## Run the database-backed tests against a throwaway PostgreSQL
	@# Why this exists: a query shipped that could not run at all — an ungrouped
	@# column in a GROUP BY — and `go test ./...` was green throughout, because no
	@# test in the suite executes SQL. The update checker silently returned nothing
	@# and the Updates page went empty in production.
	@#
	@# postgresql-client-16 specifically, matching the server below and the version the
	@# backend image ships. A NEWER pg_dump writes settings an older server rejects —
	@# "unrecognized configuration parameter transaction_timeout" — so a mismatched
	@# client produces backups that cannot be restored onto their own server.
	@#
	@# Run INSIDE a container, not on the host: these tests need pg_dump, psql and
	@# openssl as well as a database, and on a machine without them the backup tests
	@# skip — which reads as a pass. A skipped test that looks green is the thing this
	@# whole target exists to stop.
	@set -e; \
	net=prov-testdb-net-$$$$; db=prov-testdb-$$$$; \
	trap "docker rm -f $$db >/dev/null 2>&1 || true; docker network rm $$net >/dev/null 2>&1 || true" EXIT; \
	docker network create $$net >/dev/null; \
	docker run -d --name $$db --network $$net -e POSTGRES_PASSWORD=test -e POSTGRES_USER=prov \
	  -e POSTGRES_DB=prov postgres:16-alpine -c max_connections=200 >/dev/null; \
	echo "waiting for postgres"; \
	for i in $$(seq 1 60); do docker exec $$db pg_isready -U prov >/dev/null 2>&1 && break; sleep 1; done; \
	url="postgres://prov:test@$$db:5432/prov?sslmode=disable"; \
	docker run --rm --network $$net -v "$$PWD/backend:/src" -w /src \
	  -e PROV_TEST_DATABASE_URL="$$url" -e GOFLAGS=-buildvcs=false golang:1.26-bookworm \
	  sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq curl gnupg openssl >/dev/null && \
	         install -d /usr/share/postgresql-common/pgdg && \
	         curl -sS -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc && \
	         echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
	         apt-get update -qq >/dev/null && apt-get install -y -qq postgresql-client-16 >/dev/null && \
	         go run ./cmd/provctl migrate-db "$$PROV_TEST_DATABASE_URL" && \
	         go test ./internal/store/ -run "EverySQLStatement|StoreQueriesParse|AssigningARoleThatDoesNotExist" -v && \
	         go test ./internal/backup/ -run RestoreOverAMigratedDatabase -v'

comma := ,

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
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.26-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go build ./..."

.PHONY: enroll-agent
enroll-agent: ## Build the SSH-agent enrollment bridge for this machine's platform
	docker run --rm -v $(PWD)/backend:/src -w /src -e CGO_ENABLED=0 golang:1.26-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go build -o /src/bin/prov-enroll-agent ./cmd/prov-enroll-agent"
	@echo "Built backend/bin/prov-enroll-agent — distribute to operators."

.PHONY: enroll-agent-all
enroll-agent-all: ## Cross-compile the bridge for macOS/Linux/Windows (operators' laptops)
	docker run --rm -v $(PWD)/backend:/src -w /src -e CGO_ENABLED=0 golang:1.26-alpine sh -c '\
	  apk add --no-cache git >/dev/null; \
	  set -e; \
	  for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	    os=$${t%/*}; arch=$${t#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	    out=/src/bin/prov-enroll-agent-$$os-$$arch$$ext; \
	    echo "building $$out"; \
	    GOOS=$$os GOARCH=$$arch GOFLAGS=-mod=mod go build -trimpath -ldflags "-s -w" -o $$out ./cmd/prov-enroll-agent; \
	  done'
	@echo "Built backend/bin/prov-enroll-agent-* — distribute the right one per operator:"
	@echo "  macOS Apple Silicon: prov-enroll-agent-darwin-arm64"
	@echo "  macOS Intel:         prov-enroll-agent-darwin-amd64"
	@echo "  Linux x86_64:        prov-enroll-agent-linux-amd64"
	@echo "  Linux ARM64:         prov-enroll-agent-linux-arm64"
	@echo "  Windows x86_64:      prov-enroll-agent-windows-amd64.exe"

.PHONY: test
test: backend-test frontend-typecheck frontend-test scanner-test imaging-test container-e2e store-queries ## Run all tests

.PHONY: smoke
smoke: ## Build a real initramfs + bootloader and check what is actually in them (rpm, ~8 min)
	# The gate the static checks cannot be. `make imaging-test` reads the build
	# scripts; this one RUNS the part of them that has produced every expensive
	# bug in the RHEL work, and asks the artefact what it contains.
	#
	# An initramfs missing a hook, a module or its crypttab builds cleanly,
	# produces a valid image, and fails at boot on a machine that is no longer in
	# front of you. A full image build takes half an hour, so those bugs were
	# being found one per build. This reproduces just the initramfs assembly --
	# same bootstrap, same overlay files, same dracut invocation, in a chroot as
	# the real build does -- in a few minutes, with no loop device, no LUKS and
	# no bootloader.
	#
	# Not in GitHub Actions: these are private repos with metered Actions turned
	# off, so CI here is a target you run before pushing, like `make lint`.
	#
	# --privileged for the bind mounts the chroot needs. linux/amd64 because the
	# rpm family's packages are, and an emulated bootstrap would take longer than
	# the thing it is checking.
	docker run --rm --privileged --platform=linux/amd64 \
	  --ulimit nofile=65536:65536 \
	  -v $(PWD)/builder:/builder:ro almalinux:9 \
	  bash /builder/smoke/initramfs-smoke.sh $(SMOKE_SUITE)
	# The bootloader is the LAST step of a full build, so a mistake there costs
	# the whole thirty minutes to find. It is also where the two families differ
	# most: Red Hat patches grub2-install to refuse EFI outright, because the
	# signed bootloader ships in the package rather than being generated.
	docker run --rm --privileged --platform=linux/amd64 \
	  --ulimit nofile=65536:65536 \
	  -v $(PWD)/builder:/builder:ro almalinux:9 \
	  bash /builder/smoke/bootloader-smoke.sh $(SMOKE_SUITE)
	# The imager on a machine whose first NIC faces nothing. One missing udhcpc
	# flag made that hang forever, and every test that had a single NIC — or the
	# live one first — passed while it did.
	@if [ -f output/imager/vmlinuz ]; then \
	  imager/test-multi-nic.sh output/imager; \
	else \
	  echo "[smoke] no netboot imager built; skipping the multi-NIC test"; \
	fi
	# The state-manifest engine, run for real against a loopback ext4 and a fake
	# root slot -- 108 assertions over every directive combination, about a
	# second each. This is the detailed test of ab-overlay, which is the riskiest
	# script here: it runs before there is a system to log into and its failures
	# reach only the kernel log.
	#
	# It was dead for months and nothing said so. Its default pointed at
	# etc/initramfs-tools/scripts/local-bottom/ab-overlay -- where build-image.sh
	# INSTALLS the script inside an image, not where it lives in the repo -- so
	# from the moment the source moved to usr/lib/ab/initramfs/ it could only
	# print HARNESS-FAIL. Nothing ran it, so nothing reported that.
	#
	# Named here rather than left to be run by hand, because "a harness exists"
	# and "a harness runs" turned out to be very different claims.
	docker run --rm --privileged --platform=linux/amd64 \
	  -v $(PWD):/repo:ro ubuntu:24.04 \
	  bash /repo/scripts/imaging/test-state-directives.sh

SMOKE_SUITE ?= 9

.PHONY: backend-test
backend-test: ## Run Go unit + integration tests
	# Mount the REPO ROOT, not backend/. Several tests assert that committed
	# artefacts outside the module have not drifted from the code (the enrollment
	# teardown tests read ../../../scripts/prov-unenroll.sh). With only backend/
	# mounted those paths do not exist, so the tests failed here while passing under
	# a native `go test` — a gate that fails for a reason unrelated to the change is
	# a gate people learn to ignore.
	docker run --rm -v $(PWD):/src -w /src/backend golang:1.26-alpine \
	  sh -c "apk add --no-cache git gcc musl-dev openssh-client >/dev/null && GOFLAGS=-mod=mod go test ./..."

.PHONY: frontend-typecheck
frontend-typecheck: ## Typecheck the frontend exactly as the production image build does
	# The gate that was missing. `npm run build` in frontend/Dockerfile runs
	# `tsc -b` before vite, and nothing here ran it -- so a test file importing
	# node:fs passed both vitest and a hand-run `tsc --noEmit`, and then failed
	# the IMAGE BUILD during a deploy. A type error that only the deploy can
	# find is a type error found at the worst possible moment.
	#
	# This is `tsc -b`, the same invocation the image uses, rather than
	# `--noEmit`: they read the same config but not necessarily the same way,
	# and the point of this target is to be identical to the thing that broke.
	@# node_modules on a volume, not in the bind mount: see frontend-test.
	docker run --rm -v $(PWD)/frontend:/app -v prov-frontend-node-modules:/app/node_modules \
	  -w /app node:22-alpine \
	  sh -c "npm ci --silent && npx tsc -b"

.PHONY: frontend-test
frontend-test: ## Run frontend unit tests
	@# npm ci writes node_modules INTO the mounted directory, so running this on a
	@# Mac replaces the host's native binaries (rollup, esbuild) with Linux ones and
	@# the next `npm run build` on the host dies with MODULE_NOT_FOUND from
	@# rollup/dist/native.js. node_modules is therefore kept inside the container,
	@# on a volume of its own, and the host's is left alone.
	docker run --rm -v $(PWD)/frontend:/app -v prov-frontend-node-modules:/app/node_modules \
	  -w /app node:22-alpine \
	  sh -c "npm ci && npm run test -- --run"

.PHONY: scanner-test
scanner-test: ## Run grype-scanner sidecar unit tests (parsing only; no grype/DB needed)
	docker run --rm -v $(PWD)/deploy/grype-scanner:/src -w /src python:3.13-alpine \
	  sh -c "pip install -q pytest fastapi && python -m pytest -q"

.PHONY: imaging-test
imaging-test: ## Run the imaging sidecars' unit tests (socket-proxy rules, runner auth, preflight)
	# These existed and nothing ran them. The proxy's rules in particular are only
	# worth having if each refusal is still a refusal, and that quietly stops being
	# true when somebody widens a pattern to make a build work again.
	docker run --rm -v $(PWD)/deploy/dockerproxy:/src -w /src python:3.13-alpine \
	  sh -c "python test_rules.py"
	# Mount the REPO ROOT, not deploy/builder-runner. test_builder_image.py checks
	# that the orchestrator's list of RPM distributions still agrees with
	# build-image.sh's own FAMILY case -- they disagree only when somebody adds a
	# distribution to one and not the other, which is exactly how the Rocky build
	# came to run in a builder with no dnf in it. With only the sidecar mounted
	# the script is not there to compare against, and a cross-check that cannot
	# see the other side is a test that cannot fail.
	docker run --rm -v $(PWD):/src -w /src/deploy/builder-runner python:3.13-alpine \
	  sh -c "pip install -q pydantic pydantic-settings fastapi httpx >/dev/null 2>&1 && \
	         python test_auth.py && python test_preflight.py && python test_dhcp_preflight.py && python test_image_size.py && python test_client_lastseen.py && python test_binfmt.py && python test_overlay.py && python test_builder_image.py && python test_keybackup.py && python test_nofile.py && python test_family_guards.py && python test_reachable.py && python test_initramfs_deps.py && python test_playbook_template.py && python test_nav_routes.py && python test_compose_env.py && python test_rauc_runtime.py && python test_docs_lists.py && python test_documented_settings.py && python test_spelling.py && python test_state_model_guards.py && python test_slot_reset.py && python test_route_collisions.py && python test_sidecar_cleanup.py"

.PHONY: store-queries
store-queries: ## Execute every store read query against a real PostgreSQL
	# The gate the unit tests cannot be, for SQL.
	#
	# A Go compile error is caught in milliseconds. SQL lives in a string and
	# gets none of that: DiscoveredProjects shipped with a comma where it needed
	# CROSS JOIN LATERAL, could not parse AT ALL, and failed on every call from
	# the release that introduced the screen it feeds -- while that screen said
	# "no compose projects found yet", which reads as a fact about the fleet.
	# The package has no database in its tests and the panel's test mocks the
	# API, so it passed the whole gate twice over.
	#
	# This runs each query against a real server. Nothing asserts what comes
	# back; an empty database is the point.
	@if docker version >/dev/null 2>&1; then 	  $(MAKE) -s store-queries-run; 	else 	  echo "SKIPPED store-queries: docker is not usable here"; 	fi

.PHONY: store-queries-run
store-queries-run:
	@name=provenance-store-queries-$$$$; 	docker run -d --rm --name $$name -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test 	  -e POSTGRES_DB=test -p 0:5432 postgres:16-alpine >/dev/null; 	trap "docker rm -f $$name >/dev/null 2>&1 || true" EXIT; 	port=$$(docker port $$name 5432/tcp | head -1 | sed 's/.*://'); 	for i in $$(seq 1 60); do 	  docker exec $$name pg_isready -U test -d test >/dev/null 2>&1 && break; sleep 1; 	done; 	cd backend && PROVENANCE_TEST_DB_URL="postgres://test:test@127.0.0.1:$$port/test?sslmode=disable" 	  go test ./internal/store/ -run TestStoreQueriesParse -count=1

.PHONY: container-e2e
container-e2e: ## Run the container-update end-to-end tests against the local Docker
	# The gate the unit tests cannot be.
	#
	# Every bug this feature shipped lived in the space between three things that
	# are only correct TOGETHER: the script sent to a host, the shell that runs it,
	# and the parser that reads it back. A unit test feeding the parser a
	# hand-written string cannot see `echo "$$_i\t$$_d"` failing on bash, a script
	# assuming it runs as root, or a compose file already at the target tag. Each
	# of those reached production and was found by an operator.
	#
	# So these run the real scripts and the real engine against a real daemon.
	# Skipped, loudly, where Docker is not usable -- a machine without it is not a
	# reason to pretend the tests passed.
	@if docker compose version >/dev/null 2>&1; then \
	  PROVENANCE_E2E_DOCKER=1 $(MAKE) -s container-e2e-run; \
	else \
	  echo "SKIPPED container-e2e: docker compose is not usable here"; \
	fi

.PHONY: container-e2e-run
container-e2e-run:
	cd backend && PROVENANCE_E2E_DOCKER=1 go test ./internal/containerupdate/ -run E2E -count=1

.PHONY: lint
lint: fmt-check ## Run gofmt check + Go vet
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.26-alpine \
	  sh -c "apk add --no-cache git >/dev/null && GOFLAGS=-mod=mod go vet ./..."

.PHONY: fmt-check
fmt-check: ## Fail if any Go file needs gofmt (CI enforces this; catch it before pushing)
	@unformatted=$$(gofmt -l backend/cmd backend/internal sdk 2>/dev/null); \
	if [ -n "$$unformatted" ]; then \
	  echo "these files need gofmt (run: make fmt):"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: fmt
fmt: ## Rewrite Go files with gofmt
	gofmt -w backend/cmd backend/internal sdk

.PHONY: tidy
tidy: ## Run go mod tidy and write go.sum back to the repo
	docker run --rm -v $(PWD)/backend:/src -w /src golang:1.26-alpine \
	  sh -c "apk add --no-cache git >/dev/null && go mod tidy"

.PHONY: e2e
e2e: ## Run Playwright end-to-end tests against the running stack
	-$(COMPOSE_FABRIC) exec -T backend provctl create-admin e2euser 'E2e-Pass-12345!' 2>/dev/null
	docker run --rm --network host -v $(PWD)/frontend:/app -w /app \
	  -e E2E_BASE=$${E2E_BASE:-http://localhost:5173} \
	  -e E2E_USER=e2euser -e E2E_PASS='E2e-Pass-12345!' \
	  mcr.microsoft.com/playwright:v1.48.2-jammy \
	  sh -c "npm install >/dev/null 2>&1 && npx playwright test"

.PHONY: load
load: ## Run the k6 load smoke test against the running stack (override USER/PASS)
	docker run --rm --network host -v $(PWD)/deploy/load:/load \
	  -e BASE=$${BASE:-http://localhost:8080} \
	  -e USER=$${PROV_LOAD_USER:-admin} \
	  -e PASS=$${PROV_LOAD_PASS:-Sup3r-Secret-Pass!} \
	  grafana/k6 run /load/k6-smoke.js

.PHONY: assistant-docs
assistant-docs: ## Regenerate the assistant's embedded documentation index from docs/
	docker run --rm -v $(PWD):/repo -w /repo/backend/internal/assistant golang:1.26-alpine \
	  go run gendocs.go -docs /repo/docs -out docs_generated.go
