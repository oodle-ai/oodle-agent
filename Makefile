ECR_ALIAS   := oodle-ai
IMAGE_REPO  := oodle/oodle-agent
CHART_DIR   := helm/oodle-agent
REGISTRY    := public.ecr.aws/$(ECR_ALIAS)
IMAGE       := $(REGISTRY)/$(IMAGE_REPO)
TAG         ?= latest

.DEFAULT_GOAL := all

.PHONY: all
all: image ## Build+push image

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' \
		$(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "  %-20s %s\n", $$1, $$2}'

# ── Auth ─────────────────────────────────────────

.PHONY: ecr-login
ecr-login: ## Authenticate Docker + Helm to ECR Public
	aws ecr-public get-login-password \
		--region us-east-1 | \
		docker login \
		--username AWS \
		--password-stdin \
		$(REGISTRY)

# ── Docker Image ─────────────────────────────────

.PHONY: image-build
image-build: ## Build Docker image (multi-arch)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE):$(TAG) \
		.

.PHONY: image-push
image-push: ## Build and push Docker image (multi-arch)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE):$(TAG) \
		--push \
		.

.PHONY: image-sign
image-sign: ## Sign the pushed image with cosign
	cosign sign --yes $(IMAGE):$(TAG)

# ── Shorthand Targets ────────────────────────────

.PHONY: image
image: image-push ## Build and push Docker image

# ── Build / Test ─────────────────────────────────

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -X github.com/oodle-ai/oodle-agent/pkg/version.Version=$(VERSION) \
              -X github.com/oodle-ai/oodle-agent/pkg/version.GitCommit=$(GIT_COMMIT) \
              -X github.com/oodle-ai/oodle-agent/pkg/version.BuildTime=$(BUILD_TIME)

.PHONY: build
build: ## Build the Go binary
	CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o oodle-agent ./cmd/oodle-agent

.PHONY: test
test: ## Run tests
	go test ./...

.PHONY: scan
scan: ## Run vulnerability and dependency scanning
	govulncheck ./...
	trivy image --severity HIGH,CRITICAL \
		$(IMAGE):$(TAG) 2>/dev/null || true

.PHONY: clean
clean: ## Remove build artifacts
	rm -f oodle-agent oodle-agent-*.tgz
