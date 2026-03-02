ECR_ALIAS   := oodle-ai
IMAGE_REPO  := oodle/oodle-agent
CHART_DIR   := helm/oodle-agent
REGISTRY    := public.ecr.aws/$(ECR_ALIAS)
IMAGE       := $(REGISTRY)/$(IMAGE_REPO)
TAG         := $(shell awk '/^appVersion:/ {print $$2}' $(CHART_DIR)/Chart.yaml)

VERSION    := $(TAG)
GIT_COMMIT := $(shell \
	git rev-parse --short HEAD 2>/dev/null \
	|| echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := \
	-X github.com/oodle-ai/oodle-agent/pkg/version.Version=$(VERSION) \
	-X github.com/oodle-ai/oodle-agent/pkg/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/oodle-ai/oodle-agent/pkg/version.BuildTime=$(BUILD_TIME)

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

.PHONY: check-tag
check-tag: ## Fail if TAG already exists in ECR
	@if aws ecr-public describe-images \
		--region us-east-1 \
		--repository-name $(IMAGE_REPO) \
		--image-ids imageTag=$(TAG) \
		>/dev/null 2>&1; then \
		echo "ERROR: tag $(TAG) already exists" \
			"in ECR. Bump appVersion in $(CHART_DIR)/Chart.yaml."; \
		exit 1; \
	fi

.PHONY: image-build
image-build: ## Build Docker image (multi-arch)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE):$(TAG) \
		.

.PHONY: image-push
image-push: check-tag ## Build and push Docker image (multi-arch)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
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
