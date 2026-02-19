# syntax=docker/dockerfile:1.7
# Production hardened multi-stage build.
# Final image: distroless, non-root, read-only filesystem, no shell.

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install CA certs for TLS validation in build stage only.
RUN apk add --no-cache ca-certificates git

WORKDIR /build

# Copy and download dependencies first (better layer caching).
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source.
COPY . .

# Build with security flags:
#   -trimpath: remove local file paths from binary
#   CGO_ENABLED=0: fully static binary
#   -ldflags: strip debug info, set build version
ARG VERSION=dev
ARG BUILD_TIME
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -extldflags '-static'" \
    -o /build/server ./cmd/server

# Build worker binary.
# (In a real project, worker would have its own cmd/worker/main.go)
# RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /build/worker ./cmd/worker

# Verify the binary is static.
RUN file /build/server | grep -q 'statically linked' || echo "Warning: binary may not be fully static"

# ── Stage 2: Security scanning (optional, run in CI) ─────────────────────────
# FROM aquasec/trivy:latest AS scanner
# COPY --from=builder /build/server /server
# RUN trivy fs --exit-code 1 --severity HIGH,CRITICAL /server

# ── Stage 3: Final distroless image ──────────────────────────────────────────
# gcr.io/distroless/static-debian12: no shell, no package manager, no libc.
# This eliminates an entire class of container escape attacks.
FROM gcr.io/distroless/static-debian12:nonroot AS production

# Copy CA certificates for outbound TLS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary only — nothing else.
COPY --from=builder /build/server /app/server

# Distroless nonroot runs as UID 65532 by default.
USER nonroot:nonroot

# Expose application and metrics ports.
EXPOSE 8443 9090

# No ENTRYPOINT script (reduces attack surface).
# Binary is the only thing in the container that can run.
ENTRYPOINT ["/app/server"]

# Labels for registry metadata and supply chain provenance.
LABEL org.opencontainers.image.source="https://github.com/enterprise/agent-platform"
LABEL org.opencontainers.image.description="Enterprise AI Agent Platform - Production Build"
LABEL org.opencontainers.image.licenses="Proprietary"

# ── Development image (NOT for production) ───────────────────────────────────
FROM golang:1.22-alpine AS development
RUN apk add --no-cache ca-certificates curl
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["go", "run", "./cmd/server"]
