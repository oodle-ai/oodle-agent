# Oodle Gateway-Agent Threat Model

## Scope

This document describes the threat model for the Oodle
gateway-agent framework: a SaaS gateway and in-cluster
agent that communicate over WebSocket Secure (WSS) with
application-level certificate verification.

---

## Architecture Overview

- **Gateway**: SaaS component running in Oodle's
  infrastructure.
  - Accepts agent WebSocket connections.
  - Authenticates agents, routes proxy requests, stores
    routing info in DynamoDB.

- **Agent**: Lightweight component deployed in customer
  Kubernetes environments.
  - Establishes persistent connections to gateway.
  - Executes proxy requests (HTTP, TCP, Postgres, K8s
    metadata, etc.).
  - Handles sensitive customer data (Postgres, K8s
    metadata).

- **Transport**: WebSocket Secure (WSS) with mTLS between
  agent and gateway.

---

## Trust Boundaries

| Boundary | Trust Level | Notes |
|----------|-------------|-------|
| **Gateway** | Partially trusted | Multi-tenant SaaS. Oodle controls |
|          |               | code; runs in Oodle infrastructure. |
| **Agent** | Untrusted      | Runs in customer env. Customer |
|          |               | controls deployment. |
| **Agent data** | Sensitive | Postgres, K8s metadata, secrets. |

---

## Key Mitigations (Summary)

- **Application-level cert verification** with
  certificate pinning to Amazon CA
- **Argon2id hashing** for any secrets
- **Timestamp validation + request ID dedup** for
  replay prevention
- **Agent-side endpoint whitelist policy** for
  outbound connections
- **Cross-tenant isolation** via instance validation
  (relies on internal network for HTTP proxy endpoint)
- **Binary WebSocket frames** for stream data
- **Resource limits** on streams and connections
- **K8s secrets denied by default** in policy

---

## Threat Categories and Mitigations

### 1. Installation Threats (T1.1–T1.4)

| ID | Threat | Mitigation |
|----|--------|------------|
| **T1.1** | Tampering with agent binary | cosign image signing; |
|     | during download/install | `make image-sign`. |
| **T1.2** | Malicious K8s RBAC granting | Minimal RBAC: read-only |
|     | excess privileges | to common resources. |
| **T1.3** | Compromised Helm chart | Signed Helm packages |
|     | (malicious values) | via `helm package --sign`. |
| **T1.4** | Supply chain attacks on | Multi-stage builds; |
|     | base image or deps | govulncheck + trivy scan. |

### 2. Registration Threats (T2.1–T2.5)

| ID | Threat | Mitigation |
|----|--------|------------|
| **T2.1** | Stolen registration tokens | Argon2id hashing; tokens are |
|     |  | single-use with 24h expiry. |
| **T2.2** | Replay registration | One-time token consumed on |
|     | (reuse captured auth) | first use; cert-based after. |
| **T2.3** | Rogue agents impersonating | App-level client cert + Agent |
|     | valid customer | ID + Instance validation. |
| **T2.4** | CSR injection | CSR validated by gateway CA; |
|     | (malicious cert request) | only ECDSA P-256+ accepted. |
| **T2.5** | MITM during initial | TLS 1.2+ enforced; certificate |
|     | registration | pinning to Amazon CA. |

### 3. Connection Threats (T3.1–T3.5)

| ID | Threat | Mitigation |
|----|--------|------------|
| **T3.1** | MITM on WSS tunnel | TLS (terminated at LB); |
|     | (decrypt/modify traffic) | cert pinning to Amazon CA. |
| **T3.2** | Certificate theft/cloning | Long-lived certs (10yr); |
|     | (exfiltrated cert reuse) | revocation flag in DDB. |
| **T3.3** | Expired certificate | Agent checks expiry before |
|     | exploitation | connect; warns at 30 days. |
| **T3.4** | DNS spoofing | Certificate pinning; |
|     | (redirect to fake gateway) | hostname in cert. |
| **T3.5** | TLS downgrade | Minimum TLS 1.2; |
|     | (force weaker cipher) | no fallback. |

### 4. Communication Threats (T4.1–T4.6)

| ID | Threat | Mitigation |
|----|--------|------------|
| **T4.1** | Message replay | Timestamp validation; |
|     | (replay captured requests) | request ID deduplication. |
| **T4.2** | Cross-tenant data leakage | Instance validation per |
|     | (agent A sees tenant B) | request; routing by instance. |
| **T4.3** | Agent resource exhaustion | Resource limits: max |
|     | (stream floods, DoS) | streams, requests; timeouts. |
| **T4.4** | Malformed message injection | Strict message validation; |
|     | (JSON parsing, injection) | reject unknown message types. |
| **T4.5** | Stream data manipulation | Binary WebSocket frames |
|     | (inject/corrupt bytes) | for raw streams; frame format. |
| **T4.6** | Privilege escalation via K8s | K8s secrets denied by default |
|     | metadata (e.g. read secrets) | in policy; deny_resources. |

---

## Mitigation Details

### Application-Level Cert Verification with Pinning

- Agent and gateway mutually authenticate via TLS.
- Client certificates issued by Oodle PKI.
- Agent pins the gateway's TLS CA to Amazon Root CA,
  preventing MITM via rogue CAs.

### Argon2id Hashing for Tokens

- Registration and proxy tokens hashed with Argon2id
  (OWASP params).
- 64MB memory, 4 threads, salt per hash.
- Constant-time comparison.

### Timestamp + Request ID Dedup (Replay Prevention)

- Gateway sends `timestamp` in ms.
- Agent rejects messages > `TimestampMaxAge` (default 60s).
- Agent maintains bounded dedup cache for `request_id`.
- Duplicate IDs rejected.

### Agent-Side Endpoint Whitelist Policy

- Agent `Policy` config: `AllowedEndpoints`.
- `stream_open` and proxy requests checked before
  outbound connect.
- Supports host:port, wildcards (e.g. `*.example.com`).

### Cross-Tenant Isolation via Instance Validation

- Every request validated against authenticated
  instance.
- Routing table keyed by instance + agent.
- No cross-instance routing.

### Binary WebSocket Frames for Stream Data

- Stream data uses binary frames (not base64 JSON).
- Format: `[4B streamID len][streamID][payload]`.
- Reduces manipulation surface.

### Resource Limits on Streams and Connections

- `MaxConcurrentStreams` (default 100).
- `MaxConcurrentRequests` (default 50).
- `StreamInactivityTimeout` (default 5m).
- `requestIDCacheSize` (10000).

### K8s Secrets Denied by Default in Policy

- `deny_resources` takes precedence.
- `secrets` denied by default in deny list.
- `allowed_namespaces` restricts scope.

---

## Data Flow

**Primary path:**

```
Agent → WSS (TLS at LB) → Gateway → API Server
```

**Proxy requests:**

```
Gateway → Agent → Target (HTTP/TCP/Postgres/etc.)
         ↑
    Request over WebSocket
```

**Stream tunneling:**

```
Gateway ←→ Agent ←→ Target (TCP)
   ↑
   Bidirectional via WebSocket
```

---

## Data Flow Summary

| Path | Direction | Transport |
|------|-----------|-----------|
| Agent connect | Agent → Gateway | WSS (mTLS) |
| Agent auth | Agent → Gateway | JSON over WSS |
| Proxy request | Gateway → Agent | JSON (request) |
| Proxy response | Agent → Gateway | JSON (response) |
| Stream open | Gateway → Agent | JSON |
| Stream data | Bidirectional | Binary WebSocket |
| Stream close | Either | JSON |

---

## Assumptions

- Customer network is potentially hostile to the agent.
- Gateway is in Oodle's control; agent is not.
- Registration token is single-use and expires in 24h.
- Client certificates are the sole auth mechanism.
- Gateway URLs are hardcoded or from trusted config.
- Clock sync is reasonable (within timestamp window).
