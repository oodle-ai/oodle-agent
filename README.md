# Oodle Agent

Lightweight reverse proxy agent that connects your
infrastructure to Oodle via secure WebSocket tunnels.

## Overview

The Oodle Agent runs in your Kubernetes cluster (or any
environment) and establishes persistent WebSocket
connections to the Oodle Gateway. This enables Oodle to
securely access your internal services without requiring
inbound network access.

### Features

- **High Availability**: Connects to 2 gateway pods
  simultaneously for failover
- **Auto-Reconnect**: Automatically reconnects on
  connection loss
- **Multi-Protocol**: Supports HTTP, TCP, UDP, Postgres
- **K8s Metadata**: Fetches Kubernetes resource YAMLs
  (pods, deployments, services, etc.)
- **Secure**: mTLS with client certificates signed by
  the Oodle Agent CA

## Installation

### Via Helm (Recommended)

When you create an agent in the Oodle UI
(Settings > Agents), you'll get a helm command with all
the required values pre-filled:

```bash
helm repo add oodle-ai https://oodle-ai.github.io/helm-charts
helm repo update

helm upgrade --install oodle-agent oodle-ai/oodle-agent \
  --namespace oodle-monitoring \
  --create-namespace \
  --wait \
  --set oodle.instance=<INSTANCE_ID> \
  --set oodle.agentId=<AGENT_ID> \
  --set oodle.agentName=<AGENT_NAME> \
  --set existingSecret=oodle-agent-<AGENT_ID> \
  --set oodle.gatewayUrls="wss://gw-0.oodle.ai/ws,wss://gw-1.oodle.ai/ws"
```

> The Kubernetes secret is created separately with the
> one-time registration token (see the Oodle UI for the
> pre-filled command). On first connect, the agent uses
> the token to obtain a client certificate via mTLS.

### Via Docker

```bash
docker run public.ecr.aws/oodle-ai/oodle/oodle-agent:latest \
  --instance=<INSTANCE_ID> \
  --agent-id=<AGENT_ID> \
  --agent-name=<AGENT_NAME> \
  --tls-cert-file=/certs/client.pem \
  --tls-key-file=/certs/client-key.pem \
  --ca-cert-file=/certs/ca.pem \
  --gateway-urls="wss://gw-0.oodle.ai/ws,wss://gw-1.oodle.ai/ws"
```

### Binary

```bash
go install github.com/oodle-ai/oodle-agent/cmd/oodle-agent@latest

oodle-agent \
  --instance=<INSTANCE_ID> \
  --agent-id=<AGENT_ID> \
  --agent-name=<AGENT_NAME> \
  --tls-cert-file=certs/client.pem \
  --tls-key-file=certs/client-key.pem \
  --ca-cert-file=certs/ca.pem \
  --gateway-urls="wss://gw-0.oodle.ai/ws,wss://gw-1.oodle.ai/ws"
```

## Configuration

All configuration can be set via flags or environment
variables:

| Flag | Env Var | Description |
|------|---------|-------------|
| --instance | OODLE_INSTANCE | Oodle instance ID |
| --agent-id | OODLE_AGENT_ID | Unique agent ID |
| --agent-name | OODLE_AGENT_NAME | Display name |
| --gateway-urls | OODLE_GATEWAY_URLS | Comma-separated gateway WSS URLs |
| --tls-cert-file | OODLE_TLS_CERT_FILE | Client TLS cert (mTLS) |
| --tls-key-file | OODLE_TLS_KEY_FILE | Client TLS private key (mTLS) |
| --ca-cert-file | OODLE_CA_CERT_FILE | CA cert for gateway verification |
| --pinned-ca-cert-file | OODLE_PINNED_CA_CERT_FILE | Pinned Amazon CA cert |
| --policy-file | OODLE_POLICY_FILE | YAML policy file |
| --kubeconfig | KUBECONFIG | Path to kubeconfig (optional) |
| --reconnect-interval | - | Reconnect interval (default: 5s) |

## Helm Chart Values

| Value | Default | Description |
|-------|---------|-------------|
| replicaCount | 1 | Number of agent replicas |
| image.repository | public.ecr.aws/oodle-ai/oodle/oodle-agent | Image |
| image.tag | latest | Image tag |
| oodle.instance | "" | Instance ID (required) |
| oodle.agentId | "" | Agent ID (required) |
| oodle.agentName | "" | Agent name |
| oodle.gatewayUrls | "" | Gateway URLs (required) |
| existingSecret | "" | K8s secret with registration token |
| rbac.create | true | Create RBAC for K8s access |
| serviceAccount.create | true | Create SA |

## Kubernetes RBAC

When `rbac.create=true` (default), the helm chart
creates a ClusterRole with read-only access to common
Kubernetes resources. This enables the K8s metadata
feature.

Resources accessible (read-only):
- Pods, Services, ConfigMaps, Secrets
- Deployments, StatefulSets, DaemonSets, ReplicaSets
- Jobs, CronJobs
- Ingresses, Namespaces, Nodes

Additionally, the agent needs **update** permission on
its own Secret in the `oodle-monitoring` namespace to
persist mTLS certificates. This ensures certs survive
pod rescheduling without a PersistentVolume:

```yaml
# Role (namespace-scoped)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: oodle-agent-cert
  namespace: oodle-monitoring
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["oodle-agent-<AGENT_ID>"]
    verbs: ["get", "update"]
```

## Supported Protocols

### HTTP
Forward HTTP requests to services in your cluster.

### TCP
Raw TCP tunneling for any TCP-based protocol.

### UDP
UDP packet forwarding.

### Postgres
Postgres wire protocol forwarding for database
monitoring.

### Kubernetes Metadata
Fetch Kubernetes resource definitions (equivalent to
`kubectl get <resource> -o json`).

## Development

```bash
# Build
go build -o oodle-agent ./cmd/oodle-agent

# Run locally
./oodle-agent \
  --instance=test \
  --agent-id=test-agent \
  --agent-name=test \
  --tls-cert-file=certs/client.pem \
  --tls-key-file=certs/client-key.pem \
  --ca-cert-file=certs/ca.pem \
  --gateway-urls=wss://localhost:9030/ws \
  --kubeconfig=$HOME/.kube/config

# Run tests
go test ./...
```

## Publishing

### Docker Image (ECR Public)

Docker images are published to AWS ECR Public.

```bash
# Set variables
ECR_ALIAS=oodle-ai
REPO_NAME=oodle/oodle-agent
TAG=latest

# Authenticate Docker to ECR Public
aws ecr-public get-login-password \
  --region us-east-1 \
  | docker login \
  --username AWS \
  --password-stdin \
  public.ecr.aws/${ECR_ALIAS}

# Build the image (multi-arch)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t public.ecr.aws/${ECR_ALIAS}/${REPO_NAME}:${TAG} \
  --push .

# Or single-arch build + push
docker build \
  -t public.ecr.aws/${ECR_ALIAS}/${REPO_NAME}:${TAG} .
docker push \
  public.ecr.aws/${ECR_ALIAS}/${REPO_NAME}:${TAG}
```

### Helm Chart (GitHub Pages)

Helm charts are released automatically via the
`helm-release` workflow, which publishes to the
[oodle-ai/helm-charts](https://github.com/oodle-ai/helm-charts)
GitHub Pages index.

## Architecture

```
┌───────────────────────────────┐
│          oodle-agent          │
│                               │
│  ┌─────────┐  ┌────────────┐ │
│  │  Agent   │  │   Proxy    │ │
│  │ (WS Mgr) │  │  Handler   │ │
│  └────┬────┘  └─────┬──────┘ │
│       │              │        │
│  ┌────▼────┐  ┌─────▼──────┐ │
│  │ Conn[0] │  │ K8s Client │ │
│  │ Conn[1] │  └────────────┘ │
│  └────┬────┘                  │
└───────┼───────────────────────┘
        │ WSS
┌───────▼───────────────────────┐
│     Oodle Gateway (HA)        │
│   gateway-0  |  gateway-1     │
└───────────────────────────────┘
```
