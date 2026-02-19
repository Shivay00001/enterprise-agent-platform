package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the complete application configuration loaded from environment
// variables. No defaults are assumed for security-critical settings.
type Config struct {
	Server     ServerConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	NATS       NATSConfig
	Vault      VaultConfig
	LLM        LLMConfig
	Auth       AuthConfig
	Agent      AgentConfig
	Compliance ComplianceConfig
	Telemetry  TelemetryConfig
	Browser    BrowserConfig
	RateLimit  RateLimitConfig
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
	PrimaryDSN     string
	ReplicaDSN     string
	MaxOpenConns   int
	MaxIdleConns   int
	ConnMaxLifetime time.Duration
	MigrationsPath string
}

type RedisConfig struct {
	Addrs      []string
	Password   string
	DB         int
	MaxRetries int
	PoolSize   int
	TLSEnabled bool
}

type NATSConfig struct {
	URLs            []string
	NKeyPath        string
	TLSCertFile     string
	TLSKeyFile      string
	TLSCAFile       string
	StreamName      string
	ConsumerName    string
	AckWait         time.Duration
	MaxDeliver      int
}

type VaultConfig struct {
	Address    string
	AuthMethod string // kubernetes | token | approle
	RoleID     string
	SecretID   string
	MountPath  string
	TokenPath  string // for k8s auth
	K8sRole    string
}

type LLMConfig struct {
	PrimaryProvider   string
	FallbackProviders []string
	APIKeys           map[string]string // loaded from Vault at runtime
	MaxTokensDefault  int
	MaxCostUSDPerTask float64
	TimeoutSeconds    int
	CircuitBreakerCfg CircuitBreakerConfig
	Models            ModelRoutingConfig
}

type ModelRoutingConfig struct {
	Default        string
	LowCost        string
	HighCapability string
	LocalFallback  string
}

type CircuitBreakerConfig struct {
	MaxRequests      uint32
	Interval         time.Duration
	Timeout          time.Duration
	FailureThreshold float64
}

type AuthConfig struct {
	JWTSigningKey        string // loaded from Vault
	JWTExpiry            time.Duration
	RefreshTokenExpiry   time.Duration
	MTLSEnabled          bool
	MTLSCAFile           string
	AllowedIssuers       []string
	SessionCleanupInterval time.Duration
}

type AgentConfig struct {
	MaxIterations       int
	MaxTaskDuration     time.Duration
	CheckpointInterval  time.Duration
	StuckDetectionTime  time.Duration
	HeartbeatInterval   time.Duration
	HighRiskThreshold   float64
	CriticalRiskThreshold float64
	WorkerConcurrency   int
	TaskQueueName       string
}

type ComplianceConfig struct {
	RobotsCache       time.Duration
	DefaultCrawlDelay time.Duration
	AllowedDomains    []string // empty = all allowed (with robots.txt)
	BlockedDomains    []string
	BlockedIPRanges   []string // CIDR notation
	MaxRequestsPerDomain int
	UserAgent         string
}

type TelemetryConfig struct {
	OTLPEndpoint    string
	ServiceName     string
	ServiceVersion  string
	SamplingRatio   float64
	MetricsPort     int
	TracingEnabled  bool
	MetricsEnabled  bool
}

type BrowserConfig struct {
	PoolSize           int
	MaxSessionsPerTask int
	NavigationTimeout  time.Duration
	PageLoadTimeout    time.Duration
	CleanupTimeout     time.Duration
	ChromiumPath       string
	UserDataDir        string
	HeadlessMode       bool
	ProxyURL           string
}

type RateLimitConfig struct {
	GlobalRPS          int
	PerUserRPS         int
	PerOrgRPS          int
	PerDomainRPS       int
	BurstMultiplier    int
	WindowSize         time.Duration
}

// Load reads configuration from environment variables. Returns an error
// for any required variable that is missing or invalid.
func Load() (*Config, error) {
	cfg := &Config{}
	var errs []string

	// Server
	cfg.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")
	cfg.Server.Port = getEnvInt("SERVER_PORT", 8080, &errs)
	cfg.Server.ReadTimeout = getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second)
	cfg.Server.WriteTimeout = getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second)
	cfg.Server.IdleTimeout = getEnvDuration("SERVER_IDLE_TIMEOUT", 120*time.Second)
	cfg.Server.ShutdownTimeout = getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 15*time.Second)
	cfg.Server.TLSCertFile = getEnv("TLS_CERT_FILE", "")
	cfg.Server.TLSKeyFile = getEnv("TLS_KEY_FILE", "")
	cfg.Server.Environment = requireEnv("ENVIRONMENT", &errs)

	// Database
	cfg.Database.PrimaryDSN = requireEnv("DATABASE_PRIMARY_DSN", &errs)
	cfg.Database.ReplicaDSN = getEnv("DATABASE_REPLICA_DSN", cfg.Database.PrimaryDSN)
	cfg.Database.MaxOpenConns = getEnvInt("DATABASE_MAX_OPEN_CONNS", 25, &errs)
	cfg.Database.MaxIdleConns = getEnvInt("DATABASE_MAX_IDLE_CONNS", 5, &errs)
	cfg.Database.ConnMaxLifetime = getEnvDuration("DATABASE_CONN_MAX_LIFETIME", 5*time.Minute)
	cfg.Database.MigrationsPath = getEnv("DATABASE_MIGRATIONS_PATH", "migrations")

	// Redis
	redisAddrs := requireEnv("REDIS_ADDRS", &errs)
	cfg.Redis.Addrs = strings.Split(redisAddrs, ",")
	cfg.Redis.Password = getEnv("REDIS_PASSWORD", "")
	cfg.Redis.DB = getEnvInt("REDIS_DB", 0, &errs)
	cfg.Redis.MaxRetries = getEnvInt("REDIS_MAX_RETRIES", 3, &errs)
	cfg.Redis.PoolSize = getEnvInt("REDIS_POOL_SIZE", 50, &errs)
	cfg.Redis.TLSEnabled = getEnvBool("REDIS_TLS_ENABLED", true)

	// NATS
	natsURLs := requireEnv("NATS_URLS", &errs)
	cfg.NATS.URLs = strings.Split(natsURLs, ",")
	cfg.NATS.NKeyPath = getEnv("NATS_NKEY_PATH", "")
	cfg.NATS.TLSCertFile = getEnv("NATS_TLS_CERT", "")
	cfg.NATS.TLSKeyFile = getEnv("NATS_TLS_KEY", "")
	cfg.NATS.TLSCAFile = getEnv("NATS_TLS_CA", "")
	cfg.NATS.StreamName = getEnv("NATS_STREAM_NAME", "agent-events")
	cfg.NATS.ConsumerName = getEnv("NATS_CONSUMER_NAME", "audit-consumer")
	cfg.NATS.AckWait = getEnvDuration("NATS_ACK_WAIT", 30*time.Second)
	cfg.NATS.MaxDeliver = getEnvInt("NATS_MAX_DELIVER", 5, &errs)

	// Vault
	cfg.Vault.Address = requireEnv("VAULT_ADDR", &errs)
	cfg.Vault.AuthMethod = getEnv("VAULT_AUTH_METHOD", "kubernetes")
	cfg.Vault.MountPath = getEnv("VAULT_MOUNT_PATH", "secret")
	cfg.Vault.K8sRole = getEnv("VAULT_K8S_ROLE", "agent-platform")
	cfg.Vault.TokenPath = getEnv("VAULT_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	cfg.Vault.RoleID = getEnv("VAULT_ROLE_ID", "")
	cfg.Vault.SecretID = getEnv("VAULT_SECRET_ID", "")

	// Auth
	cfg.Auth.JWTExpiry = getEnvDuration("JWT_EXPIRY", 15*time.Minute)
	cfg.Auth.RefreshTokenExpiry = getEnvDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour)
	cfg.Auth.MTLSEnabled = getEnvBool("MTLS_ENABLED", true)
	cfg.Auth.MTLSCAFile = getEnv("MTLS_CA_FILE", "")
	issuers := getEnv("JWT_ALLOWED_ISSUERS", "")
	if issuers != "" {
		cfg.Auth.AllowedIssuers = strings.Split(issuers, ",")
	}
	cfg.Auth.SessionCleanupInterval = getEnvDuration("SESSION_CLEANUP_INTERVAL", 1*time.Hour)

	// Agent
	cfg.Agent.MaxIterations = getEnvInt("AGENT_MAX_ITERATIONS", 50, &errs)
	cfg.Agent.MaxTaskDuration = getEnvDuration("AGENT_MAX_TASK_DURATION", 30*time.Minute)
	cfg.Agent.CheckpointInterval = getEnvDuration("AGENT_CHECKPOINT_INTERVAL", 1*time.Minute)
	cfg.Agent.StuckDetectionTime = getEnvDuration("AGENT_STUCK_DETECTION", 5*time.Minute)
	cfg.Agent.HeartbeatInterval = getEnvDuration("AGENT_HEARTBEAT_INTERVAL", 30*time.Second)
	cfg.Agent.HighRiskThreshold = getEnvFloat("AGENT_HIGH_RISK_THRESHOLD", 0.6)
	cfg.Agent.CriticalRiskThreshold = getEnvFloat("AGENT_CRITICAL_RISK_THRESHOLD", 0.8)
	cfg.Agent.WorkerConcurrency = getEnvInt("AGENT_WORKER_CONCURRENCY", 10, &errs)
	cfg.Agent.TaskQueueName = getEnv("AGENT_TASK_QUEUE", "agent-tasks")

	// LLM
	cfg.LLM.PrimaryProvider = requireEnv("LLM_PRIMARY_PROVIDER", &errs)
	fallbacks := getEnv("LLM_FALLBACK_PROVIDERS", "")
	if fallbacks != "" {
		cfg.LLM.FallbackProviders = strings.Split(fallbacks, ",")
	}
	cfg.LLM.MaxTokensDefault = getEnvInt("LLM_MAX_TOKENS_DEFAULT", 4096, &errs)
	cfg.LLM.MaxCostUSDPerTask = getEnvFloat("LLM_MAX_COST_USD_PER_TASK", 1.0)
	cfg.LLM.TimeoutSeconds = getEnvInt("LLM_TIMEOUT_SECONDS", 60, &errs)
	cfg.LLM.Models.Default = getEnv("LLM_MODEL_DEFAULT", "claude-3-5-sonnet-20241022")
	cfg.LLM.Models.LowCost = getEnv("LLM_MODEL_LOW_COST", "claude-3-haiku-20240307")
	cfg.LLM.Models.HighCapability = getEnv("LLM_MODEL_HIGH_CAP", "claude-3-5-sonnet-20241022")
	cfg.LLM.Models.LocalFallback = getEnv("LLM_MODEL_LOCAL", "llama3.1:70b")
	cfg.LLM.CircuitBreakerCfg = CircuitBreakerConfig{
		MaxRequests:      getEnvUint("CB_MAX_REQUESTS", 1),
		Interval:         getEnvDuration("CB_INTERVAL", 60*time.Second),
		Timeout:          getEnvDuration("CB_TIMEOUT", 30*time.Second),
		FailureThreshold: getEnvFloat("CB_FAILURE_THRESHOLD", 0.5),
	}

	// Compliance
	cfg.Compliance.RobotsCache = getEnvDuration("COMPLIANCE_ROBOTS_CACHE", 24*time.Hour)
	cfg.Compliance.DefaultCrawlDelay = getEnvDuration("COMPLIANCE_DEFAULT_CRAWL_DELAY", 1*time.Second)
	cfg.Compliance.UserAgent = getEnv("COMPLIANCE_USER_AGENT", "AgentPlatform/1.0 (+https://yourdomain.com/bot)")
	cfg.Compliance.MaxRequestsPerDomain = getEnvInt("COMPLIANCE_MAX_REQS_PER_DOMAIN", 60, &errs)
	blockedDomains := getEnv("COMPLIANCE_BLOCKED_DOMAINS", "")
	if blockedDomains != "" {
		cfg.Compliance.BlockedDomains = strings.Split(blockedDomains, ",")
	}
	// Default: block all private IP ranges
	cfg.Compliance.BlockedIPRanges = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}

	// Telemetry
	cfg.Telemetry.OTLPEndpoint = getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	cfg.Telemetry.ServiceName = getEnv("OTEL_SERVICE_NAME", "agent-platform")
	cfg.Telemetry.ServiceVersion = getEnv("SERVICE_VERSION", "0.0.0")
	cfg.Telemetry.SamplingRatio = getEnvFloat("OTEL_SAMPLING_RATIO", 0.1)
	cfg.Telemetry.MetricsPort = getEnvInt("METRICS_PORT", 9090, &errs)
	cfg.Telemetry.TracingEnabled = getEnvBool("TRACING_ENABLED", true)
	cfg.Telemetry.MetricsEnabled = getEnvBool("METRICS_ENABLED", true)

	// Browser
	cfg.Browser.PoolSize = getEnvInt("BROWSER_POOL_SIZE", 20, &errs)
	cfg.Browser.NavigationTimeout = getEnvDuration("BROWSER_NAV_TIMEOUT", 30*time.Second)
	cfg.Browser.PageLoadTimeout = getEnvDuration("BROWSER_PAGE_LOAD_TIMEOUT", 15*time.Second)
	cfg.Browser.CleanupTimeout = getEnvDuration("BROWSER_CLEANUP_TIMEOUT", 5*time.Second)
	cfg.Browser.ChromiumPath = getEnv("BROWSER_CHROMIUM_PATH", "/usr/bin/chromium")
	cfg.Browser.UserDataDir = getEnv("BROWSER_USER_DATA_DIR", "/tmp/browser-profiles")
	cfg.Browser.HeadlessMode = getEnvBool("BROWSER_HEADLESS", true)
	cfg.Browser.ProxyURL = getEnv("BROWSER_PROXY_URL", "")

	// Rate limiting
	cfg.RateLimit.GlobalRPS = getEnvInt("RATELIMIT_GLOBAL_RPS", 10000, &errs)
	cfg.RateLimit.PerUserRPS = getEnvInt("RATELIMIT_PER_USER_RPS", 10, &errs)
	cfg.RateLimit.PerOrgRPS = getEnvInt("RATELIMIT_PER_ORG_RPS", 100, &errs)
	cfg.RateLimit.PerDomainRPS = getEnvInt("RATELIMIT_PER_DOMAIN_RPS", 1, &errs)
	cfg.RateLimit.BurstMultiplier = getEnvInt("RATELIMIT_BURST_MULTIPLIER", 3, &errs)
	cfg.RateLimit.WindowSize = getEnvDuration("RATELIMIT_WINDOW", 1*time.Second)

	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration errors:\n  %s", strings.Join(errs, "\n  "))
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string, errs *[]string) string {
	v := os.Getenv(key)
	if v == "" {
		*errs = append(*errs, fmt.Sprintf("required env var %s is not set", key))
	}
	return v
}

func getEnvInt(key string, fallback int, errs *[]string) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("env var %s must be an integer, got %q", key, v))
		return fallback
	}
	return i
}

func getEnvUint(key string, fallback uint32) uint32 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return fallback
	}
	return uint32(i)
}

func getEnvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
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

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
