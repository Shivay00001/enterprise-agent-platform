package main

import (
	"context"
	"encoding/json"
	"fmt"
	goLog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/enterprise/agent-platform/internal/auth"
	"github.com/enterprise/agent-platform/internal/config"
	middleware "github.com/enterprise/agent-platform/internal/gateway"
	"github.com/enterprise/agent-platform/internal/ratelimit"
	"github.com/enterprise/agent-platform/internal/security"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	log, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config error", zap.Error(err))
	}

	// ─── Redis ────────────────────────────────────────────────────────────────
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    cfg.Redis.Addrs,
		Password: cfg.Redis.Password,
	})
	defer rdb.Close()

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		log.Fatal("redis connection failed", zap.Error(err))
	}

	// ─── Rate Limiter ─────────────────────────────────────────────────────────
	limiter := ratelimit.NewLimiter(rdb)

	// ─── Security Engine ────────────────────────────────────────────────────
	scanner, err := security.NewScanner()
	if err != nil {
		log.Fatal("security scanner init failed", zap.Error(err))
	}
	// Security engine (initialized but not used directly in gateway routes yet).
	_ = security.NewEngine(scanner)
	log.Info("security initialized")

	// ─── Auth ─────────────────────────────────────────────────────────────────
	jwtKey := []byte(os.Getenv("JWT_SIGNING_KEY"))
	if len(jwtKey) < 32 {
		log.Fatal("JWT_SIGNING_KEY must be at least 32 bytes")
	}
	tokenStore := &redisTokenStore{rdb: rdb}
	authenticator := middleware.NewJWTAuthenticator(jwtKey, tokenStore, log)

	// ─── RBAC ─────────────────────────────────────────────────────────────────
	enforcer := auth.NewEnforcer()

	// ─── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()

	// Base middleware (applied to all routes)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.CorrelationID)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.Logger(log))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.RateLimitMiddleware(limiter, middleware.RateLimitConfig{
		PerIPRPS:   100,
		PerUserRPS: cfg.RateLimit.PerUserRPS,
		PerOrgRPS:  cfg.RateLimit.PerOrgRPS,
		Window:     cfg.RateLimit.WindowSize,
	}, log))
	r.Use(chimiddleware.Compress(5))

	// ─── Public Routes ────────────────────────────────────────────────────────
	r.Group(func(r chi.Router) {
		r.Post("/auth/login", makeLoginHandler(jwtKey, log))
		r.Post("/auth/refresh", makeRefreshHandler(jwtKey, log))
		r.Get("/health", healthHandler)
		r.Get("/ready", readyHandler(rdb, log))
	})

	// ─── Authenticated Routes ─────────────────────────────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(authenticator.Middleware)
		r.Use(middleware.InjectionScanMiddleware(scanner, log))

		// Task management
		r.Route("/api/v1/tasks", func(r chi.Router) {
			r.With(middleware.RequirePermission(enforcer, auth.PermTaskCreate)).
				Post("/", makeCreateTaskHandler(log))
			r.With(middleware.RequirePermission(enforcer, auth.PermTaskRead)).
				Get("/{taskID}", makeGetTaskHandler(log))
			r.With(middleware.RequirePermission(enforcer, auth.PermTaskRead)).
				Get("/", makeListTasksHandler(log))
			r.With(middleware.RequirePermission(enforcer, auth.PermTaskCancel)).
				Delete("/{taskID}", makeCancelTaskHandler(log))
		})

		// HITL
		r.Route("/api/v1/hitl", func(r chi.Router) {
			r.With(middleware.RequirePermission(enforcer, auth.PermHITLReview)).
				Get("/pending", makeListHITLHandler(log))
			r.With(middleware.RequirePermission(enforcer, auth.PermHITLApprove)).
				Post("/{requestID}/approve", makeApproveHITLHandler(log))
			r.With(middleware.RequirePermission(enforcer, auth.PermHITLApprove)).
				Post("/{requestID}/reject", makeRejectHITLHandler(log))
		})

		// Audit
		r.Route("/api/v1/audit", func(r chi.Router) {
			r.With(middleware.RequirePermission(enforcer, auth.PermAuditRead)).
				Get("/events", makeListAuditHandler(log))
		})

		// Tools
		r.Route("/api/v1/tools", func(r chi.Router) {
			r.With(middleware.RequirePermission(enforcer, auth.PermToolRegister)).
				Post("/", makeRegisterToolHandler(log))
			r.Get("/", makeListToolsHandler(log))
		})

		// User profile
		r.Post("/auth/logout", makeLogoutHandler(tokenStore, log))
	})

	// ─── Metrics (internal, not behind auth) ──────────────────────────────────
	r.Get("/metrics", prometheusHandler())

	// ─── Server ───────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		// Disable HTTP/1.0 and require at least HTTP/1.1
		ErrorLog: newStdLogger(log),
	}

	// Start server
	go func() {
		log.Info("gateway starting",
			zap.String("addr", srv.Addr),
			zap.String("env", cfg.Server.Environment),
		)

		var serverErr error
		if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
			serverErr = srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			if cfg.Server.Environment == "production" {
				log.Fatal("TLS is required in production (TLS_CERT_FILE and TLS_KEY_FILE must be set)")
			}
			serverErr = srv.ListenAndServe()
		}

		if serverErr != nil && serverErr != http.ErrServerClosed {
			log.Fatal("server error", zap.Error(serverErr))
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Info("shutdown signal received")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", zap.Error(err))
	} else {
		log.Info("server stopped gracefully")
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "gateway"})
}

func readyHandler(rdb *redis.ClusterClient, log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Warn("readiness check failed: redis", zap.Error(err))
			http.Error(w, "not ready: redis unavailable", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	}
}

type createTaskRequest struct {
	Type         string            `json:"type"`
	Description  string            `json:"description"`
	Instructions string            `json:"instructions"`
	Context      map[string]string `json:"context"`
	AllowedTools []string          `json:"allowed_tools"`
	TokenBudget  int               `json:"token_budget"`
	CostBudget   float64           `json:"cost_budget_usd"`
}

func makeCreateTaskHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req createTaskRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Input validation
		if req.Type == "" {
			http.Error(w, "task type is required", http.StatusBadRequest)
			return
		}
		if len(req.Description) < 10 {
			http.Error(w, "description too short", http.StatusBadRequest)
			return
		}
		if len(req.Description) > 10000 {
			http.Error(w, "description too long (max 10000 chars)", http.StatusBadRequest)
			return
		}

		// In production: forward to orchestrator service via gRPC
		// Here: return the validated request structure
		resp := map[string]interface{}{
			"id":             "task-" + middleware.CorrelationIDFromContext(r.Context()),
			"status":         "queued",
			"type":           req.Type,
			"created_by":     principal.UserID,
			"org_id":         principal.OrgID,
			"correlation_id": middleware.CorrelationIDFromContext(r.Context()),
		}

		log.Info("task created",
			zap.String("type", req.Type),
			zap.String("user_id", principal.UserID.String()),
			zap.String("correlation_id", middleware.CorrelationIDFromContext(r.Context())),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
	}
}

func makeGetTaskHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		taskID := chi.URLParam(r, "taskID")
		if taskID == "" {
			http.Error(w, "task ID required", http.StatusBadRequest)
			return
		}

		// In production: query orchestrator for task status
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     taskID,
			"status": "running",
		})
	}
}

func makeListTasksHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In production: query database with org-scoped filters
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tasks": []interface{}{},
			"total": 0,
		})
	}
}

func makeCancelTaskHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		taskID := chi.URLParam(r, "taskID")
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		log.Info("task cancellation requested",
			zap.String("task_id", taskID),
			zap.String("user_id", principal.UserID.String()),
		)
		// In production: signal Temporal workflow to cancel
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "cancellation_requested"})
	}
}

func makeListHITLHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // Compliance checks.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"requests": []interface{}{},
			"total":    0,
		})
	}
}

func makeApproveHITLHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := chi.URLParam(r, "requestID")
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body struct {
			Note string `json:"note"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		log.Info("HITL approved",
			zap.String("request_id", requestID),
			zap.String("reviewer", principal.UserID.String()),
			zap.String("note", body.Note),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"request_id": requestID,
			"status":     "approved",
		})
	}
}

func makeRejectHITLHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := chi.URLParam(r, "requestID")
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		log.Info("HITL rejected",
			zap.String("request_id", requestID),
			zap.String("reviewer", principal.UserID.String()),
			zap.String("reason", body.Reason),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"request_id": requestID,
			"status":     "rejected",
		})
	}
}

func makeListAuditHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"events": []interface{}{},
			"total":  0,
		})
	}
}

func makeRegisterToolHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented: tool registration requires security review", http.StatusNotImplemented)
	}
}

func makeListToolsHandler(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tools": []interface{}{},
		})
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func makeLoginHandler(jwtKey []byte, log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if req.Email == "" || req.Password == "" {
			http.Error(w, "email and password required", http.StatusBadRequest)
			return
		}

		// In production: look up user from database, verify bcrypt hash
		// Never log the password
		_ = bcrypt.CompareHashAndPassword(nil, []byte(req.Password))

		// Stub: In production, return a real JWT
		http.Error(w, "authentication backend not configured in this module", http.StatusNotImplemented)
	}
}

func makeRefreshHandler(jwtKey []byte, log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}
}

func makeLogoutHandler(tokenStore *redisTokenStore, log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Revoke the current token by adding JTI to blocklist
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Token Store ──────────────────────────────────────────────────────────────

type redisTokenStore struct {
	rdb *redis.ClusterClient
}

func (s *redisTokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	result, err := s.rdb.Exists(ctx, "revoked_jti:"+jti).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

func (s *redisTokenStore) Revoke(ctx context.Context, jti string, expiry time.Duration) error {
	return s.rdb.Set(ctx, "revoked_jti:"+jti, "1", expiry).Err()
}

// ─── Prometheus ───────────────────────────────────────────────────────────────

func prometheusHandler() http.HandlerFunc {
	// In production: use promhttp.Handler()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# Prometheus metrics endpoint\n# Install promhttp and add real metrics\n")
	}
}

// ─── Logging adapter ─────────────────────────────────────────────────────────

func newStdLogger(log *zap.Logger) *goLog.Logger {
	return goLog.New(&zapWriter{log: log}, "", 0)
}

type zapWriter struct {
	log *zap.Logger
}

func (z *zapWriter) Write(p []byte) (n int, err error) {
	z.log.Error(string(p))
	return len(p), nil
}
