#!/usr/bin/env bash
# monitor-canary.sh — Automated canary health monitor.
# Queries Prometheus and auto-rolls back if thresholds are exceeded.
# Used as a CI gate between canary → full production rollout.

set -euo pipefail

# ── Defaults (override via flags) ─────────────────────────────────────────────
DURATION=600             # seconds to monitor
ERROR_RATE_THRESHOLD=0.005  # 0.5%
LATENCY_P99_THRESHOLD=2000  # ms
PROMETHEUS_URL="${PROMETHEUS_URL:-http://prometheus:9090}"
CHECK_INTERVAL=30
NAMESPACE="agent-platform"

# ── Flag parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration=*)              DURATION="${1#*=}" ;;
    --error-rate-threshold=*)  ERROR_RATE_THRESHOLD="${1#*=}" ;;
    --latency-p99-threshold=*) LATENCY_P99_THRESHOLD="${1#*=}" ;;
    --prometheus-url=*)        PROMETHEUS_URL="${1#*=}" ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[$(date -u +%H:%M:%S)]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[$(date -u +%H:%M:%S)]${NC} $*"; }
log_error() { echo -e "${RED}[$(date -u +%H:%M:%S)]${NC} $*"; }

# ── Prometheus query helper ───────────────────────────────────────────────────
query_prometheus() {
  local query="$1"
  curl -sf "$PROMETHEUS_URL/api/v1/query" \
    --data-urlencode "query=$query" \
    | jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0"
}

# ── Rollback function ─────────────────────────────────────────────────────────
rollback() {
  local reason="$1"
  log_error "ROLLBACK TRIGGERED: $reason"
  log_error "Rolling back canary deployment..."
  
  helm uninstall agent-platform-canary --namespace "$NAMESPACE" 2>/dev/null || true
  
  # Alert on-call engineer.
  if [[ -n "${PAGERDUTY_KEY:-}" ]]; then
    curl -sf -X POST "https://events.pagerduty.com/v2/enqueue" \
      -H "Content-Type: application/json" \
      -d "{
        \"routing_key\": \"$PAGERDUTY_KEY\",
        \"event_action\": \"trigger\",
        \"payload\": {
          \"summary\": \"Canary auto-rollback: $reason\",
          \"severity\": \"critical\",
          \"source\": \"canary-monitor\"
        }
      }" || log_warn "PagerDuty alert failed"
  fi
  
  exit 1
}

# ── Main monitoring loop ──────────────────────────────────────────────────────
log_info "Canary monitor started"
log_info "  Duration:              ${DURATION}s"
log_info "  Error rate threshold:  ${ERROR_RATE_THRESHOLD}"
log_info "  Latency p99 threshold: ${LATENCY_P99_THRESHOLD}ms"
log_info "  Check interval:        ${CHECK_INTERVAL}s"

END_TIME=$(($(date +%s) + DURATION))
CHECKS_PASSED=0
CHECKS_FAILED=0

while [[ $(date +%s) -lt $END_TIME ]]; do
  sleep "$CHECK_INTERVAL"
  
  REMAINING=$((END_TIME - $(date +%s)))
  
  # Query canary-specific metrics (filtered by pod label).
  ERROR_RATE=$(query_prometheus \
    'sum(rate(agentplatform_http_requests_total{status=~"5..",version="canary"}[2m])) / sum(rate(agentplatform_http_requests_total{version="canary"}[2m]))')
  
  LATENCY_P99=$(query_prometheus \
    'histogram_quantile(0.99, rate(agentplatform_http_request_duration_seconds_bucket{version="canary"}[2m])) * 1000')
  
  ACTIVE_TASKS=$(query_prometheus \
    'agentplatform_agent_active_tasks{version="canary"}')

  log_info "Check | Error: ${ERROR_RATE} | P99: ${LATENCY_P99}ms | Active tasks: ${ACTIVE_TASKS} | ${REMAINING}s remaining"

  # Check error rate threshold.
  if (( $(echo "$ERROR_RATE > $ERROR_RATE_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
    ((CHECKS_FAILED++))
    log_warn "Error rate ${ERROR_RATE} exceeds threshold ${ERROR_RATE_THRESHOLD} (failure #${CHECKS_FAILED})"
    
    # Require 2 consecutive failures before rollback (avoids flappy metric spikes).
    if [[ $CHECKS_FAILED -ge 2 ]]; then
      rollback "Error rate ${ERROR_RATE} exceeded threshold ${ERROR_RATE_THRESHOLD} on ${CHECKS_FAILED} consecutive checks"
    fi
    continue
  fi

  # Check latency threshold.
  if (( $(echo "$LATENCY_P99 > $LATENCY_P99_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
    ((CHECKS_FAILED++))
    log_warn "P99 latency ${LATENCY_P99}ms exceeds threshold ${LATENCY_P99_THRESHOLD}ms (failure #${CHECKS_FAILED})"
    
    if [[ $CHECKS_FAILED -ge 2 ]]; then
      rollback "P99 latency ${LATENCY_P99}ms exceeded threshold ${LATENCY_P99_THRESHOLD}ms on ${CHECKS_FAILED} consecutive checks"
    fi
    continue
  fi

  # Reset failure counter on a clean check.
  CHECKS_FAILED=0
  ((CHECKS_PASSED++))
done

log_info "Canary monitoring complete."
log_info "  Passed checks: $CHECKS_PASSED"
log_info "  Deployment is healthy — safe to promote to full production."
