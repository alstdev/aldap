SHELL := /bin/bash
.DEFAULT_GOAL := help

MODULE      ?= github.com/alstdev/aldap
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
GOFLAGS     := -trimpath -buildvcs=false
# Binaries are static (CGO_ENABLED=0); tests need cgo for -race.

DIST        := dist
PLATFORMS   := linux/amd64 linux/arm64 windows/amd64
COVER_MIN   ?= 80

GOLANGCI    := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# govulncheck is pinned (docs/DECISIONS.md); v1.8.0+ requires Go >= 1.26.
GOVULN_VERSION ?= v1.9.0
GOVULN      := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION)
# go-licenses is built for the host and run with GOOS=linux and GOOS=windows
# (scripts/licenses.sh); `go run` would build it for the target GOOS.
GOLICENSES_BIN := artifacts/bin/go-licenses
# gotestsum is pinned (docs/DECISIONS.md). On GitHub Actions the output is
# grouped per test and failed tests are annotated (scripts/ci-annotate.sh).
GOTESTSUM_VERSION ?= v1.13.0
GOTESTSUM   := go run gotest.tools/gotestsum@$(GOTESTSUM_VERSION)
GOTESTSUM_FLAGS ?=
ifdef GITHUB_ACTIONS
GOTESTSUM_FLAGS += --format github-actions --post-run-command scripts/ci-annotate.sh
endif

ALLOWED_LICENSES := MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0,Zlib,MPL-2.0,Unlicense

.PHONY: help
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build binaries for all platforms into dist/
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/aldap_$${os}_$${arch}$$ext ./cmd/aldap || exit 1; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/aldapctl_$${os}_$${arch}$$ext ./cmd/aldapctl || exit 1; \
	done

.PHONY: windows-ctl
windows-ctl: ## Cross-compile and vet aldapctl for windows/amd64 (tests compiled too)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o /dev/null ./cmd/aldapctl
	GOOS=windows GOARCH=amd64 go vet ./cmd/aldapctl/ ./internal/api/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o /dev/null ./cmd/aldapctl/

.PHONY: build-local
build-local: ## Build for current platform into dist/
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/aldap ./cmd/aldap
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/aldapctl ./cmd/aldapctl

.PHONY: test
test: ## Unit tests with race detector and coverage gate
	@mkdir -p artifacts
	CGO_ENABLED=1 $(GOTESTSUM) $(GOTESTSUM_FLAGS) --junitfile artifacts/junit.xml --jsonfile artifacts/test.json -- -race -coverprofile=artifacts/coverage.out -covermode=atomic ./...
	@go tool cover -func=artifacts/coverage.out | tail -1 | awk -v min=$(COVER_MIN) '{gsub("%","",$$3); if ($$3+0 < min) {printf "coverage %s%% < %s%%\n",$$3,min; exit 1} else printf "coverage %s%%\n",$$3}'
	@go tool cover -html=artifacts/coverage.out -o artifacts/coverage.html

.PHONY: integration
integration: ## Integration tests against in-memory LDAP and e2e clients
	@mkdir -p artifacts
	CGO_ENABLED=1 $(GOTESTSUM) $(GOTESTSUM_FLAGS) --junitfile artifacts/junit-integration.xml --jsonfile artifacts/integration.json -- -race -tags integration -timeout 20m ./...

.PHONY: integration-samba
# Samba AD bench (deploy/samba-dc, docs/samba.md): init.sh generates the passwords
# and the LDAPS CA into deploy/samba-dc/secrets/ (git-ignored) and exports the CA
# to testdata/samba-ca.pem; two DCs on 127.0.0.1:6636 and :6637.
SAMBA_COMPOSE := $(CURDIR)/deploy/samba-dc/compose.yml
SAMBA_SECRETS := $(CURDIR)/deploy/samba-dc/secrets
integration-samba: ## Integration tests against Samba AD DC in Docker
	@mkdir -p artifacts
	deploy/samba-dc/init.sh
	docker compose -f $(SAMBA_COMPOSE) up -d --wait --wait-timeout 300
	ALDAP_TEST_SAMBA_URL=ldaps://127.0.0.1:6636,ldaps://127.0.0.1:6637 \
	ALDAP_TEST_SAMBA_BIND_DN="CN=svc-aldap,CN=Users,DC=test,DC=aldap" \
	ALDAP_TEST_SAMBA_BIND_PASSWORD_FILE=$(SAMBA_SECRETS)/svc_pass \
	ALDAP_TEST_SAMBA_USER_PASSWORD_FILE=$(SAMBA_SECRETS)/user_pass \
	ALDAP_TEST_SAMBA_ADMIN_PASSWORD_FILE=$(SAMBA_SECRETS)/admin_pass \
	ALDAP_TEST_SAMBA_CA=$(CURDIR)/testdata/samba-ca.pem \
	ALDAP_TEST_SAMBA_COMPOSE=$(SAMBA_COMPOSE) \
	CGO_ENABLED=1 $(GOTESTSUM) $(GOTESTSUM_FLAGS) --junitfile artifacts/junit-samba.xml --jsonfile artifacts/samba.json -- -race -tags integration_samba -run '^TestSamba_' -timeout 10m ./cmd/aldap/ ; rc=$$?; \
	docker compose -f $(SAMBA_COMPOSE) logs --no-color > artifacts/samba.log 2>&1 || true; \
	docker compose -f $(SAMBA_COMPOSE) down -v; exit $$rc

.PHONY: fuzz
fuzz: ## Fuzz parsers for 2 minutes each
	go test -run=^$$ -fuzz=FuzzParseFilter -fuzztime=2m ./internal/ldapfilter/
	go test -run=^$$ -fuzz=FuzzParseDN -fuzztime=2m ./internal/ldapfilter/
	go test -run=^$$ -fuzz=FuzzParseMessage -fuzztime=2m ./internal/listener/

.PHONY: lint
lint: ## golangci-lint
	$(GOLANGCI) run ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: vuln
vuln: ## govulncheck
	$(GOVULN) ./...

.PHONY: licenses
licenses: ## Check dependency licenses and regenerate THIRD_PARTY_LICENSES.md
	@mkdir -p artifacts/bin
	GOBIN=$(abspath artifacts/bin) go install github.com/google/go-licenses@latest
	scripts/licenses.sh $(GOLICENSES_BIN) scripts/licenses.tpl $(ALLOWED_LICENSES) > THIRD_PARTY_LICENSES.md.tmp
	mv THIRD_PARTY_LICENSES.md.tmp THIRD_PARTY_LICENSES.md

.PHONY: shellcheck
shellcheck: ## shellcheck all scripts
	shellcheck -x build.sh $(wildcard scripts/*.sh) $(wildcard deploy/samba-dc/*.sh)

.PHONY: ci
ci: lint vet vuln licenses windows-ctl test integration shellcheck ## Everything except Samba

.PHONY: docker-plain
docker-plain: ## Build container with public golang/scratch images (local testing)
	./build.sh --plain

.PHONY: docker-dhi
docker-dhi: ## Build container with Docker Hardened Images (requires docker login dhi.io)
	./build.sh --dhi

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST) artifacts
