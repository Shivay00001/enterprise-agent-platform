package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"

	"github.com/enterprise/agent-platform/internal/agent"
	"github.com/enterprise/agent-platform/internal/audit"
	"github.com/enterprise/agent-platform/internal/auth"
	"github.com/enterprise/agent-platform/internal/hitl"
	"github.com/enterprise/agent-platform/internal/observability"
	"github.com/enterprise/agent-platform/internal/security"
	appcfg "github.com/enterprise/agent-platform/pkg/config"
	apperr "github.com/enterprise/agent-platform/pkg/errors"
	"github.com/enterprise/agent-platform/pkg/logger"
)

// Server is the HTTP API gateway.
type Server struct {
	cfg      *appcfg.Config
	authSvc  *auth.Service
	agentEng *agent.Engine
	hitlSvc  *hitl.Service
	secEng   *security.Engine
	auditSvc *audit.Service
	metrics  *observability.Metrics
	health   *observability.HealthChecker
	log      *logger.Logger
}

// NewServer creates a new gateway server.
func NewServer(
	cfg *appcfg.Config,
	authSvc *auth.Service,
	agentEng *agent.Engine,
	hitlSvc *hitl.Service,
	secEng *security.Engine,
	auditSvc *audit.Service,
	metrics *observability.Metrics,
	health *observability.HealthChecker,
	log *logger.Logger,
) *Server {
	return &Server{
		cfg:      cfg,
		authSvc:  authSvc,
		agentEng: agentEng,
		hitlSvc:  hitlSvc,
		secEng:   secEng,
		auditSvc: auditSvc,
		metrics:  metrics,
		health:   health,
		log:      log,
	}
}

// Router builds and returns the chi router with all routes.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	// Global middleware stack.
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.correlationIDMiddleware)
	r.Use(s.loggingMiddleware)
	r.Use(s.metrics.Middleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(s.securityHeaders)

	// Global rate limiting: 1000 requests/minute per IP.
	r.Use(httprate.LimitByIP(1000, 1*time.Minute))

	// Health endpoints (unauthenticated).
	r.Get("/health/live", s.health.LivenessHandler)
	r.Get("/health/ready", s.health.ReadinessHandler)
	r.Handle("/metrics", observability.Handler())

	// API v1 — authenticated routes.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.authSvc.Middleware)

		// Task management.
		r.Route("/tasks", func(r chi.Router) {
			// Per-user task creation rate limit.
			r.With(httprate.LimitByIP(20, 1*time.Minute)).
				Post("/", s.authSvc.RequirePermission(auth.PermTaskCreate)(
					http.HandlerFunc(s.handleCreateTask),
				).ServeHTTP)

			r.With(s.authSvc.RequirePermission(auth.PermTaskRead)).
				Get("/{taskID}", s.handleGetTask)

			r.With(s.authSvc.RequirePermission(auth.PermTaskCancel)).
				Post("/{taskID}/cancel", s.handleCancelTask)
		})

		// HITL review management.
		r.Route("/reviews", func(r chi.Router) {
			r.With(s.authSvc.RequirePermission(auth.PermHITLApprove)).
				Get("/pending", s.handleListPendingReviews)

			r.With(s.authSvc.RequirePermission(auth.PermHITLApprove)).
				Get("/{reviewID}", s.handleGetReview)

			r.With(s.authSvc.RequirePermission(auth.PermHITLApprove)).
				Post("/{reviewID}/decide", s.handleDecideReview)
		})
	})

	return r
}

// --- Task handlers ---

type createTaskRequest struct {
	Description   string                 `json:"description"`
	TokenBudget   int                    `json:"token_budget,omitempty"`
	CostBudgetUSD float64                `json:"cost_budget_usd,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type createTaskResponse struct {
	TaskID        string    `json:"task_id"`
	CorrelationID string    `json:"correlation_id"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.FromContext(ctx)

	claims := auth.ClaimsFromContext(ctx)
	if claims == nil {
		s.writeError(w, apperr.ErrUnauthorized)
		return
	}

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperr.ErrValidation.Wrap(err))
		return
	}

	if req.Description == "" {
		s.writeError(w, apperr.ErrValidation.WithField("field", "description").WithField("reason", "required"))
		return
	}
	if len(req.Description) > 10000 {
		s.writeError(w, apperr.ErrValidation.WithField("field", "description").WithField("reason", "too_long"))
		return
	}

	// Security: scan task description for injection before creating task.
	if pattern, severity := s.secEng.ScanForInjection(ctx, req.Description); pattern != nil && severity > 0.85 {
		s.auditSvc.NewEvent(correlationIDFromContext(ctx), "task.create.injection_blocked").
			WithActor(audit.ActorUser, claims.UserID, r.RemoteAddr).
			WithResource("task", "new", claims.OrgID).
			WithOutcome(audit.OutcomeBlocked).
			WithMeta("pattern", pattern.RuleID).
			WithMeta("severity", severity).
			Emit(ctx)
		s.writeError(w, apperr.ErrPromptInjection.WithField("pattern", pattern.RuleID))
		return
	}

	// Apply budget defaults.
	tokenBudget := req.TokenBudget
	if tokenBudget == 0 {
		tokenBudget = s.cfg.Agent.DefaultTokenBudget
	}
	costBudget := req.CostBudgetUSD
	if costBudget == 0 {
		costBudget = s.cfg.Agent.DefaultCostBudget
	}

	correlationID, _ := uuid.NewV7()
	taskID, _ := uuid.NewV7()

	task := &agent.Task{
		ID:            taskID.String(),
		CorrelationID: correlationID.String(),
		UserID:        claims.UserID,
		OrgID:         claims.OrgID,
		Description:   req.Description,
		Status:        agent.StatusPending,
		TokenBudget:   tokenBudget,
		CostBudgetUSD: costBudget,
		CreatedAt:     time.Now().UTC(),
		Metadata:      req.Metadata,
	}

	s.auditSvc.NewEvent(task.CorrelationID, "task.create").
		WithActor(audit.ActorUser, claims.UserID, r.RemoteAddr).
		WithResource("task", task.ID, claims.OrgID).
		WithTask(task.ID).
		WithOutcome(audit.OutcomeSuccess).
		Emit(ctx)

	log.Info("task created",
		logger.Str("task_id", task.ID),
		logger.Str("user_id", claims.UserID),
	)

	// Execute the task asynchronously.
	// In production this is submitted to Temporal. Here we show the direct call
	// for clarity — the Temporal worker wraps this Execute call.
	go func() {
		execCtx := logger.FromContext(ctx).WithContext(context.Background())
		s.metrics.AgentActiveTasksGauge.Inc()
		defer s.metrics.AgentActiveTasksGauge.Dec()

		startTime := time.Now()
		_, err := s.agentEng.Execute(execCtx, task)
		duration := time.Since(startTime)

		status := string(task.Status)
		s.metrics.AgentTaskTotal.WithLabelValues(status, "standard").Inc()
		s.metrics.AgentTaskDuration.WithLabelValues(status).Observe(duration.Seconds())

		if err != nil {
			log.Error("task execution failed",
				logger.Str("task_id", task.ID),
				logger.Err(err),
			)
		}
	}()

	s.writeJSON(w, http.StatusAccepted, createTaskResponse{
		TaskID:        task.ID,
		CorrelationID: task.CorrelationID,
		Status:        string(task.Status),
		CreatedAt:     task.CreatedAt,
	})
}

func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")
	if taskID == "" {
		s.writeError(w, apperr.ErrValidation.WithField("field", "taskID"))
		return
	}
	// In production: query Temporal for workflow status.
	// Returning a placeholder to illustrate the pattern.
	s.writeJSON(w, http.StatusOK, map[string]string{"task_id": taskID, "status": "running"})
}

func (s *Server) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")
	claims := auth.ClaimsFromContext(r.Context())

	s.auditSvc.NewEvent(chi.URLParam(r, "taskID"), "task.cancel").
		WithActor(audit.ActorUser, claims.UserID, r.RemoteAddr).
		WithResource("task", taskID, claims.OrgID).
		WithTask(taskID).
		WithOutcome(audit.OutcomeSuccess).
		Emit(r.Context())

	// In production: send cancellation signal to Temporal workflow.
	s.writeJSON(w, http.StatusOK, map[string]string{"task_id": taskID, "status": "cancellation_requested"})
}

// --- HITL review handlers ---

func (s *Server) handleListPendingReviews(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	ids, err := s.hitlSvc.ListPending(r.Context(), claims.OrgID)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"review_ids": ids, "count": len(ids)})
}

func (s *Server) handleGetReview(w http.ResponseWriter, r *http.Request) {
	reviewID := chi.URLParam(r, "reviewID")
	review, err := s.hitlSvc.Get(r.Context(), reviewID)
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, review)
}

type decideReviewRequest struct {
	Decision     string                 `json:"decision"` // approved | rejected | modified
	Note         string                 `json:"note"`
	ModifiedArgs map[string]interface{} `json:"modified_args,omitempty"`
}

func (s *Server) handleDecideReview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reviewID := chi.URLParam(r, "reviewID")
	claims := auth.ClaimsFromContext(ctx)

	var req decideReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperr.ErrValidation.Wrap(err))
		return
	}

	var status hitl.ReviewStatus
	switch req.Decision {
	case "approved":
		status = hitl.ReviewApproved
	case "rejected":
		status = hitl.ReviewRejected
	case "modified":
		if len(req.ModifiedArgs) == 0 {
			s.writeError(w, apperr.ErrValidation.WithField("reason", "modified_args required for modified decision"))
			return
		}
		status = hitl.ReviewModified
	default:
		s.writeError(w, apperr.ErrValidation.WithField("field", "decision").WithField("reason", "must be approved, rejected, or modified"))
		return
	}

	if err := s.hitlSvc.Decide(ctx, hitl.Decision{
		ReviewID:     reviewID,
		ReviewerID:   claims.UserID,
		Status:       status,
		Note:         req.Note,
		ModifiedArgs: req.ModifiedArgs,
	}); err != nil {
		s.writeError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"review_id": reviewID, "decision": string(status)})
}

// --- middleware ---

func (s *Server) correlationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" {
			id, _ := uuid.NewV7()
			cid = id.String()
		}
		w.Header().Set("X-Correlation-ID", cid)
		ctx := context.WithValue(r.Context(), correlationIDKey{}, cid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := correlationIDFromContext(r.Context())
		log := s.log.WithCorrelationID(cid).WithField("method", r.Method).WithField("path", r.URL.Path)
		ctx := log.WithContext(r.Context())
		log.Info("request received")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// --- response helpers ---

func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	ae := apperr.AsAppError(err)
	s.writeJSON(w, ae.HTTPStatus, map[string]interface{}{
		"error":   ae.Code,
		"message": ae.Message,
	})
}

type correlationIDKey struct{}

func correlationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationIDKey{}).(string); ok {
		return v
	}
	return ""
}

// End of file
