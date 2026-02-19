# Enterprise AI Agent Platform

Production-grade, security-first autonomous AI agent infrastructure.  
Designed for 10M+ users, regulatory environments, and hostile internet conditions.

## Architecture at a Glance

```
Client → API Gateway (TLS 1.3 + mTLS)
           → Auth Service (JWT + RBAC)
           → Security Engine (injection scan + SSRF)
           → Orchestrator (Temporal)
               → Agent Workers (gVisor sandbox)
                   → LLM Gateway (multi-provider + circuit breaker)
                   → Tool Registry (WASM sandbox)
                   → Browser Service (Playwright + compliance proxy)
                   → HITL Service (dead man's switch)
           → Audit Service (immutable, cryptographically chained)
```

## Module Map

| Path | Purpose |
|------|---------|
| `cmd/server/` | Main entrypoint — wires all services |
| `internal/auth/` | JWT issuance/validation, mTLS, RBAC |
| `internal/security/` | Injection detection, SSRF, risk scoring, SQL injection |
| `internal/compliance/` | robots.txt, domain deny list, rate limiting |
| `internal/agent/` | Think→Plan→Act→Observe→Verify loop |
| `internal/llm/` | Multi-provider gateway, circuit breaker, token budgeting |
| `internal/tools/` | Tool registry, WASM-sandboxed execution |
| `internal/browser/` | Playwright pool, session management |
| `internal/hitl/` | Human-in-the-loop reviews, dead man's switch |
| `internal/audit/` | Immutable event log, cryptographic chaining |
| `internal/observability/` | Prometheus metrics, health probes |
| `internal/gateway/` | HTTP API handlers, middleware stack |
| `pkg/config/` | Environment-based configuration, fail-fast validation |
| `pkg/crypto/` | AES-256-GCM encryption, ECDSA signing |
| `pkg/errors/` | Structured domain errors with HTTP status |
| `pkg/logger/` | Structured logging with correlation ID propagation |
| `deployments/k8s/` | Kubernetes manifests, NetworkPolicies, HPAs |
| `deployments/docker/` | Hardened multi-stage Dockerfile (distroless) |
| `deployments/grafana/` | Production dashboard |
| `scripts/` | Schema migrations, chaos tests, smoke tests, canary monitor |
| `tests/load/` | k6 load test suite |
| `.github/workflows/` | Full CI/CD pipeline |

## Security Properties

- **Zero-trust**: Every service-to-service call requires mTLS. No implicit trust.
- **Prompt injection resistant**: 8-layer defence (pattern matching → semantic similarity → structural separation → tool validation → output validation).
- **SSRF proof**: All outbound URLs validated against private IP ranges before execution, plus egress proxy enforcement.
- **Compliant by default**: robots.txt enforced on every navigation. Domain deny list. Per-domain rate limiting.
- **Immutable audit trail**: Every action produces a cryptographically chained, tamper-evident audit event stored in NATS JetStream → S3 (Object Lock, 7-year retention).
- **Sandboxed execution**: Agent workers run in gVisor (syscall interception). Tool plugins run in WASM (capability-declared, network-restricted).
- **Dead man's switch HITL**: High-risk actions require human approval. If no reviewer responds within SLA, the action auto-cancels (never auto-approves).

## Quick Start (Development)

```bash
# Clone and enter
git clone https://github.com/enterprise/agent-platform
cd agent-platform

# Start dependencies
docker compose -f deployments/docker/docker-compose.dev.yml up -d

# Set required environment variables
export DATABASE_DSN="postgres://postgres:dev@localhost:5432/agentplatform?sslmode=disable"
export REDIS_ADDR="localhost:6379"
export REDIS_PASSWORD=""
export NATS_URL="nats://localhost:4222"
export NATS_CREDENTIALS_FILE="/dev/null"
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="dev-root-token"
export TLS_CERT_FILE="./certs/dev.crt"
export TLS_KEY_FILE="./certs/dev.key"
export MTLS_CA_FILE="./certs/ca.crt"
export MTLS_CERT_FILE="./certs/dev.crt"
export MTLS_KEY_FILE="./certs/dev.key"
export TEMPORAL_HOST_PORT="localhost:7233"
export OPA_POLICY_BUNDLE_URL="http://localhost:8181/bundles/platform"
export TRACING_ENDPOINT="http://localhost:4317"
export BROWSER_EGRESS_PROXY_URL="http://localhost:3128"
export JWT_SECRET_OVERRIDE="dev-secret-minimum-32-chars-long"
export ENVIRONMENT="development"

# Run migrations
psql "$DATABASE_DSN" -f scripts/001_schema.sql

# Start the server
go run ./cmd/server
```

## Running Tests

```bash
# Unit tests with race detector
go test -race ./...

# With coverage report
go test -race -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Security-specific tests
go test -race ./internal/security/... -v

# Load tests (requires k6 and a running platform)
export PLATFORM_URL=https://staging.example.com
export API_TOKEN=your-token
k6 run tests/load/k6-staging.js
```

## Deploying to Production

```bash
# 1. Build and push (done by CI, but manual if needed)
docker build --target production -t ghcr.io/enterprise/agent-platform:v1.0.0 \
  -f deployments/docker/Dockerfile .

# 2. Deploy to staging
helm upgrade --install agent-platform ./helm/agent-platform \
  --namespace agent-platform \
  --values helm/agent-platform/values-staging.yaml

# 3. Run smoke tests
PLATFORM_URL=https://staging.example.com \
  API_TOKEN=$TOKEN \
  ./scripts/smoke-test.sh

# 4. Deploy canary to production (5% traffic)
helm upgrade --install agent-platform-canary ./helm/agent-platform \
  --set canary.enabled=true --set canary.weight=5

# 5. Monitor canary (auto-rollbacks if SLOs breached)
./scripts/monitor-canary.sh --duration=600

# 6. Full promotion
helm upgrade agent-platform ./helm/agent-platform --set canary.enabled=false
```

## SLOs

| Service | Availability | p99 Latency |
|---------|-------------|-------------|
| API Gateway | 99.99% | 100ms |
| Auth Service | 99.99% | 50ms |
| Orchestrator | 99.95% | 500ms |
| Agent Workers | 99.9% | 30s (task start) |
| Browser Service | 99.5% | 10s (navigation) |

## What Is NOT Supported

- CAPTCHA bypassing
- Tor/proxy chain circumvention  
- Scraping sites that explicitly disallow bots
- Bypassing rate limits via IP rotation
- Security circumvention of any kind
- Running as root or with escalated privileges

These restrictions are enforced in code, not just policy.

## License

Proprietary. All rights reserved.
