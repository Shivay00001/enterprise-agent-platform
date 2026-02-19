package observability

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the platform.
type Metrics struct {
	// HTTP metrics
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPRequestTotal    *prometheus.CounterVec
	HTTPRequestInFlight *prometheus.GaugeVec

	// Agent metrics
	AgentTaskTotal     *prometheus.CounterVec
	AgentTaskDuration  *prometheus.HistogramVec
	AgentStepTotal     *prometheus.CounterVec
	AgentIterations    *prometheus.HistogramVec
	AgentActiveTasksGauge prometheus.Gauge

	// LLM metrics
	LLMCallTotal       *prometheus.CounterVec
	LLMCallDuration    *prometheus.HistogramVec
	LLMTokensConsumed  *prometheus.CounterVec
	LLMCostUSD         *prometheus.CounterVec
	LLMCacheHits       *prometheus.CounterVec

	// Tool metrics
	ToolCallTotal    *prometheus.CounterVec
	ToolCallDuration *prometheus.HistogramVec
	ToolCallBlocked  *prometheus.CounterVec

	// Security metrics
	InjectionDetected    *prometheus.CounterVec
	SSRFBlocked          prometheus.Counter
	RateLimitHits        *prometheus.CounterVec
	ComplianceBlocks     *prometheus.CounterVec
	HITLRequestsTotal    *prometheus.CounterVec
	HITLDecisionDuration prometheus.Histogram

	// Browser metrics
	BrowserSessionsActive  prometheus.Gauge
	BrowserPoolSize        prometheus.Gauge
	BrowserNavigationTotal *prometheus.CounterVec
	BrowserNavigationDuration *prometheus.HistogramVec

	// System metrics
	GoRoutines  prometheus.Gauge
	MemoryAlloc prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics.
func NewMetrics(namespace string) *Metrics {
	m := &Metrics{
		// HTTP
		HTTPRequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency distribution.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "path", "status"}),

		HTTPRequestTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests.",
		}, []string{"method", "path", "status"}),

		HTTPRequestInFlight: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "http_requests_in_flight",
			Help:      "Current in-flight HTTP requests.",
		}, []string{"method"}),

		// Agent
		AgentTaskTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "agent_tasks_total",
			Help:      "Total agent tasks by status.",
		}, []string{"status", "task_type"}),

		AgentTaskDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "agent_task_duration_seconds",
			Help:      "Agent task completion duration.",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800},
		}, []string{"status"}),

		AgentStepTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "agent_steps_total",
			Help:      "Total agent loop steps.",
		}, []string{"task_type"}),

		AgentIterations: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "agent_iterations",
			Help:      "Number of iterations per task.",
			Buckets:   []float64{1, 3, 5, 10, 20, 35, 50},
		}, []string{"status"}),

		AgentActiveTasksGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "agent_active_tasks",
			Help:      "Currently running agent tasks.",
		}),

		// LLM
		LLMCallTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "llm_calls_total",
			Help:      "Total LLM API calls.",
		}, []string{"provider", "model", "status"}),

		LLMCallDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "llm_call_duration_seconds",
			Help:      "LLM API call latency.",
			Buckets:   []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
		}, []string{"provider", "model"}),

		LLMTokensConsumed: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "llm_tokens_consumed_total",
			Help:      "Total LLM tokens consumed.",
		}, []string{"provider", "model", "type"}),

		LLMCostUSD: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "llm_cost_usd_total",
			Help:      "Total LLM cost in USD.",
		}, []string{"provider", "model"}),

		LLMCacheHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "llm_cache_hits_total",
			Help:      "LLM response cache hits.",
		}, []string{"provider"}),

		// Tools
		ToolCallTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tool_calls_total",
			Help:      "Total tool invocations.",
		}, []string{"tool", "status"}),

		ToolCallDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "tool_call_duration_seconds",
			Help:      "Tool execution latency.",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
		}, []string{"tool"}),

		ToolCallBlocked: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tool_calls_blocked_total",
			Help:      "Tool calls blocked by security or policy.",
		}, []string{"tool", "reason"}),

		// Security
		InjectionDetected: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "security_injection_detected_total",
			Help:      "Prompt injection detection events.",
		}, []string{"pattern", "severity_tier"}),

		SSRFBlocked: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "security_ssrf_blocked_total",
			Help:      "SSRF attempts blocked.",
		}),

		RateLimitHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_hits_total",
			Help:      "Rate limit triggers.",
		}, []string{"type", "identifier"}),

		ComplianceBlocks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "compliance_blocks_total",
			Help:      "Actions blocked by compliance engine.",
		}, []string{"reason"}),

		HITLRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "hitl_requests_total",
			Help:      "Human-in-the-loop requests by outcome.",
		}, []string{"outcome"}),

		HITLDecisionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "hitl_decision_duration_seconds",
			Help:      "Time from HITL submission to decision.",
			Buckets:   []float64{30, 60, 120, 300, 600, 1800, 3600},
		}),

		// Browser
		BrowserSessionsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "browser_sessions_active",
			Help:      "Currently active browser sessions.",
		}),

		BrowserPoolSize: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "browser_pool_size",
			Help:      "Current browser pool size.",
		}),

		BrowserNavigationTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "browser_navigations_total",
			Help:      "Total browser navigations.",
		}, []string{"status"}),

		BrowserNavigationDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "browser_navigation_duration_seconds",
			Help:      "Browser navigation latency.",
			Buckets:   []float64{0.5, 1, 2, 5, 10, 20, 30},
		}, []string{"status"}),

		// System
		GoRoutines: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "go_goroutines",
			Help:      "Number of active goroutines.",
		}),

		MemoryAlloc: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "go_memory_alloc_bytes",
			Help:      "Current memory allocation in bytes.",
		}),
	}

	// Start system metric collection.
	go m.collectSystemMetrics()

	return m
}

// collectSystemMetrics periodically collects Go runtime metrics.
func (m *Metrics) collectSystemMetrics() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.GoRoutines.Set(float64(runtime.NumGoroutine()))
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		m.MemoryAlloc.Set(float64(ms.Alloc))
	}
}

// Handler returns the Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware instruments HTTP handlers with request metrics.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := r.URL.Path
		method := r.Method

		m.HTTPRequestInFlight.WithLabelValues(method).Inc()
		defer m.HTTPRequestInFlight.WithLabelValues(method).Dec()

		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", wrapped.status)

		m.HTTPRequestDuration.WithLabelValues(method, path, status).Observe(duration)
		m.HTTPRequestTotal.WithLabelValues(method, path, status).Inc()
	})
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// HealthChecker provides health and readiness probes.
type HealthChecker struct {
	checks map[string]func(context.Context) error
}

// NewHealthChecker creates a health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]func(context.Context) error),
	}
}

// AddCheck registers a named health check function.
func (h *HealthChecker) AddCheck(name string, fn func(context.Context) error) {
	h.checks[name] = fn
}

// LivenessHandler returns HTTP 200 if the service is alive.
// Does not run dependency checks — just confirms the process is running.
func (h *HealthChecker) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"alive"}`))
}

// ReadinessHandler runs all dependency checks.
// Returns HTTP 200 only if all checks pass.
func (h *HealthChecker) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	results := make(map[string]string)
	allOK := true

	for name, check := range h.checks {
		if err := check(ctx); err != nil {
			results[name] = "fail: " + err.Error()
			allOK = false
		} else {
			results[name] = "ok"
		}
	}

	status := http.StatusOK
	statusStr := "ready"
	if !allOK {
		status = http.StatusServiceUnavailable
		statusStr = "not_ready"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"status":%q,"checks":%v}`, statusStr, formatChecks(results))
}

func formatChecks(m map[string]string) string {
	result := "{"
	first := true
	for k, v := range m {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%q:%q", k, v)
		first = false
	}
	result += "}"
	return result
}
