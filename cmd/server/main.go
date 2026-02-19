package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/enterprise/agent-platform/internal/agent"
	"github.com/enterprise/agent-platform/internal/audit"
	"github.com/enterprise/agent-platform/internal/auth"
	"github.com/enterprise/agent-platform/internal/compliance"
	"github.com/enterprise/agent-platform/internal/gateway"
	"github.com/enterprise/agent-platform/internal/hitl"
	"github.com/enterprise/agent-platform/internal/llm"
	"github.com/enterprise/agent-platform/internal/observability"
	"github.com/enterprise/agent-platform/internal/ratelimit"
	"github.com/enterprise/agent-platform/internal/security"
	"github.com/enterprise/agent-platform/internal/tools"
	"github.com/enterprise/agent-platform/pkg/config"
	"github.com/enterprise/agent-platform/pkg/crypto"
	"github.com/enterprise/agent-platform/pkg/logger"
)

func main() {
	// Load config — fails fast if any env var is missing.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	log := logger.New(cfg.Observability.LogLevel, cfg.Observability.ServiceName)
	log.Info("agent platform starting",
		logger.Str("environment", cfg.Server.Environment),
		logger.Str("service", cfg.Observability.ServiceName),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = log.WithContext(ctx)

	// --- Infrastructure connections ---

	// Redis cluster.
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addrs[0],
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("redis connection failed", logger.Err(err))
	}
	log.Info("redis connected")

	// ─── Rate Limiter ─────────────────────────────────────────────────────────
	limiter := ratelimit.NewLimiter(rdb)
	log.Info("rate limiter initialized")

	// Postgres pool.
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.DSN)
	if err != nil {
		log.Fatal("postgres config parse failed", logger.Err(err))
	}
	poolCfg.MaxConns = int32(cfg.Database.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.Database.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.Database.ConnMaxLifetime
	poolCfg.MaxConnIdleTime = cfg.Database.ConnMaxIdleTime

	dbPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatal("postgres pool creation failed", logger.Err(err))
	}
	defer dbPool.Close()
	if err := dbPool.Ping(ctx); err != nil {
		log.Fatal("postgres connection failed", logger.Err(err))
	}
	log.Info("postgres connected")

	// NATS JetStream.
	nc, err := nats.Connect(cfg.NATS.URL,
		nats.UserCredentials(cfg.NATS.CredentialsFile),
		nats.ReconnectWait(2*time.Second),
		nats.MaxReconnects(10),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Error("NATS disconnected", logger.Err(err))
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info("NATS reconnected")
		}),
	)
	if err != nil {
		log.Fatal("NATS connection failed", logger.Err(err))
	}
	defer nc.Close()
	log.Info("NATS connected")

	// --- Generate or load audit encryption key ---
	// In production, this comes from Vault. Here we generate for startup.
	auditEncKey, err := crypto.GenerateAESKey()
	if err != nil {
		log.Fatal("failed to generate audit encryption key", logger.Err(err))
	}

	// --- Service initialization ---

	// Audit service (first: other services depend on it for logging).
	auditSvc, err := audit.NewService(nc, cfg.Observability.ServiceName, auditEncKey)
	if err != nil {
		log.Fatal("audit service init failed", logger.Err(err))
	}
	log.Info("audit service initialized")

	// Security engine.
	scanner, err := security.NewScanner()
	if err != nil {
		log.Fatal("security scanner init failed", logger.Err(err))
	}
	secEng := security.NewEngine(scanner)
	log.Info("security engine initialized")

	// Compliance engine.
	// Map literal values to compliance.Config
	compCfg := compliance.Config{
		UserAgent:         "TestAgent/1.0",
		RobotsCacheTTL:    30 * time.Second,
		DefaultCrawlDelay: 100 * time.Millisecond,
		MaxReqsPerDomain:  100,
	}
	compEng, err := compliance.NewEngine(compCfg, limiter, log) // Compliance checks.
	if err != nil {
		log.Fatal("compliance engine init failed", logger.Err(err))
	}
	log.Info("compliance engine initialized")

	// LLM gateway.
	// NOTE: In production, API keys are loaded from Vault here.
	// cfg.LLM.Providers[i].APIKey = vaultClient.Get("secret/llm/anthropic")
	metrics := observability.NewMetrics("agentplatform")
	// LLM gateway.
	var llmProviders []llm.ProviderConfig
	for _, p := range cfg.LLM.Providers {
		llmProviders = append(llmProviders, llm.ProviderConfig{
			Name:    p.Name,
			APIKey:  p.APIKey,
			BaseURL: p.BaseURL,
			Model:   p.Models[0], // Use first model as default
			Timeout: p.Timeout,
		})
	}
	llmGW := llm.NewGateway(llmProviders, log)
	log.Info("LLM gateway initialized")

	// Tool registry.
	toolReg := tools.NewRegistry(secEng, auditSvc)
	log.Info("tool registry initialized", logger.Int("tools", len(toolReg.List())))

	// HITL service.
	hitlSvc := hitl.NewService(rdb, auditSvc, 30*time.Minute) // 30 min SLA
	hitlSvc.StartSLAMonitor(ctx)
	log.Info("HITL service initialized")

	// Agent execution engine.
	agentEng := agent.NewEngine(
		&cfg.Agent,
		llmGW,
		toolReg,
		secEng,
		compEng,
		hitlSvc,
		auditSvc,
	)
	log.Info("agent engine initialized")

	// Auth service.
	// NOTE: JWT secret loaded from Vault in production.
	jwtSecret := os.Getenv("JWT_SECRET_OVERRIDE") // dev override only
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET_OVERRIDE not set (use Vault in production)")
	}
	authSvc := auth.NewService(&cfg.Auth, rdb, jwtSecret)
	log.Info("auth service initialized")

	// Health checker.
	health := observability.NewHealthChecker()
	health.AddCheck("redis", func(ctx context.Context) error {
		return rdb.Ping(ctx).Err()
	})
	health.AddCheck("postgres", func(ctx context.Context) error {
		return dbPool.Ping(ctx)
	})
	health.AddCheck("nats", func(ctx context.Context) error {
		if !nc.IsConnected() {
			return fmt.Errorf("not connected")
		}
		return nil
	})

	// --- HTTP Server ---
	gw := gateway.NewServer(cfg, authSvc, agentEng, hitlSvc, secEng, auditSvc, metrics, health, log)
	router := gw.Router()

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Separate metrics server on a different port to avoid exposing metrics publicly.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", observability.Handler())
	metricsMux.HandleFunc("/health/live", health.LivenessHandler)
	metricsMux.HandleFunc("/health/ready", health.ReadinessHandler)
	metricsSrv := &http.Server{
		Addr:        fmt.Sprintf(":%d", cfg.Observability.PrometheusPort),
		Handler:     metricsMux,
		ReadTimeout: 10 * time.Second,
	}

	// Start servers.
	go func() {
		log.Info("API server starting", logger.Str("addr", srv.Addr))
		var err error
		if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			log.Warn("TLS not configured — running plaintext HTTP (dev only)")
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal("API server failed", logger.Err(err))
		}
	}()

	go func() {
		log.Info("metrics server starting", logger.Str("addr", metricsSrv.Addr))
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("metrics server failed", logger.Err(err))
		}
	}()

	log.Info("agent platform ready")

	// Audit the startup.
	auditSvc.NewEvent("startup", "system.started").
		WithActor(audit.ActorSystem, cfg.Observability.ServiceName, "").
		WithResource("service", cfg.Observability.ServiceName, "").
		WithOutcome(audit.OutcomeSuccess).
		WithMeta("environment", cfg.Server.Environment).
		Emit(ctx)

	// --- Graceful shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Info("shutdown signal received", logger.Str("signal", sig.String()))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	// Stop accepting new requests.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("API server shutdown error", logger.Err(err))
	}
	metricsSrv.Shutdown(shutdownCtx)

	// Cancel the root context to stop background workers.
	cancel()

	// Audit the shutdown.
	auditSvc.NewEvent("shutdown", "system.stopped").
		WithActor(audit.ActorSystem, cfg.Observability.ServiceName, "").
		WithResource("service", cfg.Observability.ServiceName, "").
		WithOutcome(audit.OutcomeSuccess).
		Emit(context.Background())

	log.Info("agent platform stopped cleanly")
}
