package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the full application configuration.
// All values are loaded from environment variables — no defaults embed secrets.
type Config struct {
	Server     ServerConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	NATS       NATSConfig
	Vault      VaultConfig
	LLM        LLMConfig
	Auth       AuthConfig
	Agent      AgentConfig
	Browser    BrowserConfig
	Compliance ComplianceConfig
	Temporal   TemporalConfig
	OPA        OPAConfig
	Observability ObservabilityConfig
}

type ServerConfig struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	TLSCertFile     string
	TLSKeyFile      string
	Environment     string // production | staging | development
}

type DatabaseConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type RedisConfig struct {
	Addrs    []string
	Password string
	DB       int
}

type NATSConfig struct {
	URL            string
	CredentialsFile string
	StreamName     string
}

type VaultConfig struct {
	Address   string
	Token     string // bootstrap token only; rotated immediately
	MountPath string
}

type LLMConfig struct {
	Providers       []LLMProvider
	DefaultProvider string
	MaxTokensHard   int
	CostCapPerTask  float64 // USD
	CacheEnabled    bool
	CacheTTL        time.Duration
}

type LLMProvider struct {
	Name     string
	APIKey   string // loaded from Vault at runtime
	BaseURL  string
	Models   []string
	Priority int     // lower = higher priority
	CostPer1KTokens float64
	CircuitBreakerThreshold int
	Timeout  time.Duration
}

type AuthConfig struct {
	JWTSecret          string // loaded from Vault
	JWTExpiry          time.Duration
	RefreshTokenExpiry time.Duration
	MTLSCAFile         string
	MTLSCertFile       string
	MTLSKeyFile        string
}

type AgentConfig struct {
	MaxIterations      int
	MaxTaskDuration    time.Duration
	CheckpointInterval time.Duration
	RiskThresholdHITL  float64 // 0-1, above this → HITL required
	RiskThresholdBlock float64 // 0-1, above this → blocked
	DefaultTokenBudget int
	DefaultCostBudget  float64
}

type BrowserConfig struct {
	PoolSize         int
	MaxSessions      int
	SessionTimeout   time.Duration
	NavigationTimeout time.Duration
	EgressProxyURL   string
	UserAgent        string // honest platform UA
	CleanupInterval  time.Duration
}

type ComplianceConfig struct {
	RobotsCheckEnabled   bool
	RobotsCacheTTL       time.Duration
	MaxRequestsPerDomain int
	CrawlDelayDefault    time.Duration
	DenyListFile         string
}

type TemporalConfig struct {
	HostPort    string
	Namespace   string
	TaskQueue   string
	MaxWorkers  int
}

type OPAConfig struct {
	PolicyBundleURL string
	RefreshInterval time.Duration
}

type ObservabilityConfig struct {
	PrometheusPort int
	TracingEndpoint string
	LogLevel       string
	ServiceName    string
}

// Load reads all configuration from environment variables.
// It returns an error listing ALL missing/invalid variables so operators
// can fix everything in one pass rather than one-by-one.
func Load() (*Config, error) {
	var errs []string

	cfg := &Config{}

	// Server
	cfg.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")
	cfg.Server.Port = getEnvInt("SERVER_PORT", 8443, &errs)
	cfg.Server.ReadTimeout = getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second, &errs)
	cfg.Server.WriteTimeout = getEnvDuration("SERVER_WRITE_TIMEOUT", 60*time.Second, &errs)
	cfg.Server.IdleTimeout = getEnvDuration("SERVER_IDLE_TIMEOUT", 120*time.Second, &errs)
	cfg.Server.ShutdownTimeout = getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second, &errs)
	cfg.Server.TLSCertFile = requireEnv("TLS_CERT_FILE", &errs)
	cfg.Server.TLSKeyFile = requireEnv("TLS_KEY_FILE", &errs)
	cfg.Server.Environment = getEnv("ENVIRONMENT", "production")

	// Database
	cfg.Database.DSN = requireEnv("DATABASE_DSN", &errs)
	cfg.Database.MaxOpenConns = getEnvInt("DB_MAX_OPEN_CONNS", 25, &errs)
	cfg.Database.MaxIdleConns = getEnvInt("DB_MAX_IDLE_CONNS", 10, &errs)
	cfg.Database.ConnMaxLifetime = getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute, &errs)
	cfg.Database.ConnMaxIdleTime = getEnvDuration("DB_CONN_MAX_IDLE_TIME", 2*time.Minute, &errs)

	// Redis
	cfg.Redis.Addrs = []string{requireEnv("REDIS_ADDR", &errs)}
	cfg.Redis.Password = requireEnv("REDIS_PASSWORD", &errs)
	cfg.Redis.DB = getEnvInt("REDIS_DB", 0, &errs)

	// NATS
	cfg.NATS.URL = requireEnv("NATS_URL", &errs)
	cfg.NATS.CredentialsFile = requireEnv("NATS_CREDENTIALS_FILE", &errs)
	cfg.NATS.StreamName = getEnv("NATS_STREAM_NAME", "agent-events")

	// Vault
	cfg.Vault.Address = requireEnv("VAULT_ADDR", &errs)
	cfg.Vault.Token = requireEnv("VAULT_TOKEN", &errs)
	cfg.Vault.MountPath = getEnv("VAULT_MOUNT_PATH", "secret")

	// Auth
	cfg.Auth.JWTExpiry = getEnvDuration("JWT_EXPIRY", 15*time.Minute, &errs)
	cfg.Auth.RefreshTokenExpiry = getEnvDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour, &errs)
	cfg.Auth.MTLSCAFile = requireEnv("MTLS_CA_FILE", &errs)
	cfg.Auth.MTLSCertFile = requireEnv("MTLS_CERT_FILE", &errs)
	cfg.Auth.MTLSKeyFile = requireEnv("MTLS_KEY_FILE", &errs)

	// Agent
	cfg.Agent.MaxIterations = getEnvInt("AGENT_MAX_ITERATIONS", 50, &errs)
	cfg.Agent.MaxTaskDuration = getEnvDuration("AGENT_MAX_TASK_DURATION", 30*time.Minute, &errs)
	cfg.Agent.CheckpointInterval = getEnvDuration("AGENT_CHECKPOINT_INTERVAL", 5*time.Minute, &errs)
	cfg.Agent.RiskThresholdHITL = getEnvFloat("AGENT_RISK_THRESHOLD_HITL", 0.6, &errs)
	cfg.Agent.RiskThresholdBlock = getEnvFloat("AGENT_RISK_THRESHOLD_BLOCK", 0.95, &errs)
	cfg.Agent.DefaultTokenBudget = getEnvInt("AGENT_DEFAULT_TOKEN_BUDGET", 50000, &errs)
	cfg.Agent.DefaultCostBudget = getEnvFloat("AGENT_DEFAULT_COST_BUDGET", 1.0, &errs)

	// Browser
	cfg.Browser.PoolSize = getEnvInt("BROWSER_POOL_SIZE", 20, &errs)
	cfg.Browser.MaxSessions = getEnvInt("BROWSER_MAX_SESSIONS", 100, &errs)
	cfg.Browser.SessionTimeout = getEnvDuration("BROWSER_SESSION_TIMEOUT", 10*time.Minute, &errs)
	cfg.Browser.NavigationTimeout = getEnvDuration("BROWSER_NAV_TIMEOUT", 30*time.Second, &errs)
	cfg.Browser.EgressProxyURL = requireEnv("BROWSER_EGRESS_PROXY_URL", &errs)
	cfg.Browser.UserAgent = getEnv("BROWSER_USER_AGENT", "EnterpiseAgentPlatform/1.0 (+https://yourdomain.com/bot)")
	cfg.Browser.CleanupInterval = getEnvDuration("BROWSER_CLEANUP_INTERVAL", 30*time.Second, &errs)

	// Compliance
	cfg.Compliance.RobotsCheckEnabled = getEnvBool("COMPLIANCE_ROBOTS_CHECK", true)
	cfg.Compliance.RobotsCacheTTL = getEnvDuration("COMPLIANCE_ROBOTS_CACHE_TTL", 24*time.Hour, &errs)
	cfg.Compliance.MaxRequestsPerDomain = getEnvInt("COMPLIANCE_MAX_REQS_PER_DOMAIN", 60, &errs) // per minute
	cfg.Compliance.CrawlDelayDefault = getEnvDuration("COMPLIANCE_CRAWL_DELAY_DEFAULT", time.Second, &errs)
	cfg.Compliance.DenyListFile = getEnv("COMPLIANCE_DENY_LIST_FILE", "/etc/agent/deny-domains.txt")

	// Temporal
	cfg.Temporal.HostPort = requireEnv("TEMPORAL_HOST_PORT", &errs)
	cfg.Temporal.Namespace = getEnv("TEMPORAL_NAMESPACE", "agent-platform")
	cfg.Temporal.TaskQueue = getEnv("TEMPORAL_TASK_QUEUE", "agent-tasks")
	cfg.Temporal.MaxWorkers = getEnvInt("TEMPORAL_MAX_WORKERS", 100, &errs)

	// OPA
	cfg.OPA.PolicyBundleURL = requireEnv("OPA_POLICY_BUNDLE_URL", &errs)
	cfg.OPA.RefreshInterval = getEnvDuration("OPA_REFRESH_INTERVAL", 5*time.Minute, &errs)

	// Observability
	cfg.Observability.PrometheusPort = getEnvInt("PROMETHEUS_PORT", 9090, &errs)
	cfg.Observability.TracingEndpoint = requireEnv("TRACING_ENDPOINT", &errs)
	cfg.Observability.LogLevel = getEnv("LOG_LEVEL", "info")
	cfg.Observability.ServiceName = getEnv("SERVICE_NAME", "agent-platform")

	// LLM
	cfg.LLM.MaxTokensHard = getEnvInt("LLM_MAX_TOKENS_HARD", 200000, &errs)
	cfg.LLM.CostCapPerTask = getEnvFloat("LLM_COST_CAP_PER_TASK", 2.0, &errs)
	cfg.LLM.CacheEnabled = getEnvBool("LLM_CACHE_ENABLED", true)
	cfg.LLM.CacheTTL = getEnvDuration("LLM_CACHE_TTL", 1*time.Hour, &errs)

	if len(errs) > 0 {
		msg := "configuration errors:\n"
		for _, e := range errs {
			msg += "  - " + e + "\n"
		}
		return nil, fmt.Errorf(msg)
	}

	return cfg, nil
}

func requireEnv(key string, errs *[]string) string {
	v := os.Getenv(key)
	if v == "" {
		*errs = append(*errs, fmt.Sprintf("required environment variable %q is not set", key))
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int, errs *[]string) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("invalid integer for %q: %v", key, err))
		return fallback
	}
	return i
}

func getEnvFloat(key string, fallback float64, errs *[]string) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("invalid float for %q: %v", key, err))
		return fallback
	}
	return f
}

func getEnvDuration(key string, fallback time.Duration, errs *[]string) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("invalid duration for %q: %v", key, err))
		return fallback
	}
	return d
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
