FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/oodle-ai/oodle-agent/pkg/version.Version=${VERSION} \
              -X github.com/oodle-ai/oodle-agent/pkg/version.GitCommit=${GIT_COMMIT} \
              -X github.com/oodle-ai/oodle-agent/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /oodle-agent ./cmd/oodle-agent

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /oodle-agent /oodle-agent
ENTRYPOINT ["/oodle-agent"]
