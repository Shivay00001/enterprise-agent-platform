package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/enterprise/agent-platform/internal/auth"
	"github.com/enterprise/agent-platform/internal/models"
	"github.com/enterprise/agent-platform/internal/ratelimit"
	"github.com/enterprise/agent-platform/internal/security"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Correlation ID ───────────────────────────────────────────────────────────

type correlationKey struct{}

// CorrelationID injects a correlation ID into every request context.
// Uses the X-Correlation-ID header if provided by the client, otherwise generates one.
func CorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := r.Header.Get("X-Correlation-ID")
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		// Validate format to prevent injection via header
		if len(correlationID) > 64 || !isAlphanumericDash(correlationID) {
			correlationID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), correlationKey{}, correlationID)
		w.Header().Set("X-Correlation-ID", correlationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CorrelationIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(correlationKey{}).(string); ok {
		return id
	}
	return ""
}

func isAlphanumericDash(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ─── JWT Authentication ───────────────────────────────────────────────────────

// Claims extends the standard JWT claims with our application claims.
type Claims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
	OrgID  string `json:"oid"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	JTI    string `json:"jti"` // unique token ID for revocation
}

// JWTAuthenticator validates JWT tokens and populates the request context.
type JWTAuthenticator struct {
	signingKey  []byte
	allowedAlgs []string
	tokenStore  TokenStore // for JTI revocation list
	log         *zap.Logger
}

// TokenStore provides JTI (token ID) revocation checking.
type TokenStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// NewJWTAuthenticator creates a new JWT authenticator.
func NewJWTAuthenticator(signingKey []byte, tokenStore TokenStore, log *zap.Logger) *JWTAuthenticator {
	return &JWTAuthenticator{
		signingKey:  signingKey,
		allowedAlgs: []string{"HS256"}, // explicit algorithm pinning
		tokenStore:  tokenStore,
		log:         log,
	}
}

// Middleware returns the JWT authentication middleware.
func (a *JWTAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := a.validateToken(r.Context(), tokenStr)
		if err != nil {
			a.log.Warn("JWT validation failed",
				zap.String("error", err.Error()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("correlation_id", CorrelationIDFromContext(r.Context())),
			)
			http.Error(w, "unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			http.Error(w, "unauthorized: invalid user ID in token", http.StatusUnauthorized)
			return
		}
		orgID, err := uuid.Parse(claims.OrgID)
		if err != nil {
			http.Error(w, "unauthorized: invalid org ID in token", http.StatusUnauthorized)
			return
		}

		principal := &auth.Principal{
			UserID: userID,
			OrgID:  orgID,
			Email:  claims.Email,
			Role:   models.Role(claims.Role),
		}

		ctx := auth.WithPrincipal(r.Context(), principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *JWTAuthenticator) validateToken(ctx context.Context, tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(a.allowedAlgs),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	token, err := parser.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return a.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check JTI revocation (for logout/key rotation)
	if claims.JTI != "" && a.tokenStore != nil {
		revoked, err := a.tokenStore.IsRevoked(ctx, claims.JTI)
		if err == nil && revoked {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	return claims, nil
}

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("Authorization header must be 'Bearer <token>'")
	}
	if parts[1] == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return parts[1], nil
}

// ─── mTLS ─────────────────────────────────────────────────────────────────────

// MTLSValidator extracts and validates client certificate identity.
type MTLSValidator struct {
	caPool *x509.CertPool
	log    *zap.Logger
}

// NewMTLSValidator creates an mTLS validator from a CA certificate file.
func NewMTLSValidator(caFile string, log *zap.Logger) (*MTLSValidator, error) {
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	return &MTLSValidator{caPool: pool, log: log}, nil
}

// TLSConfig returns a TLS config requiring client certificate verification.
func (v *MTLSValidator) TLSConfig() *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  v.caPool,
		MinVersion: tls.VersionTLS13,
	}
}

// ServiceIdentityFromCert extracts the service name from a client certificate CN.
func (v *MTLSValidator) ServiceIdentityFromRequest(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// ─── Rate Limit Middleware ────────────────────────────────────────────────────

// RateLimitConfig defines limits for the middleware.
type RateLimitConfig struct {
	PerUserRPS int
	PerOrgRPS  int
	PerIPRPS   int
	Window     time.Duration
}

// RateLimitMiddleware enforces per-user, per-org, and per-IP rate limits.
func RateLimitMiddleware(limiter *ratelimit.Limiter, cfg RateLimitConfig, log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Per-IP limit (first line of defense, no auth required)
			ip := extractIP(r)
			if result, err := limiter.AllowIP(ctx, ip, cfg.PerIPRPS, cfg.Window); err == nil && !result.Allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", result.RetryAfter.Seconds()))
				w.Header().Set("X-RateLimit-Remaining", "0")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				log.Warn("rate limit exceeded",
					zap.String("ip", ip),
					zap.String("type", "ip"),
				)
				return
			}

			// Per-user and per-org limits (require authenticated principal)
			if principal, ok := auth.PrincipalFromContext(ctx); ok {
				if result, err := limiter.AllowUser(ctx, principal.UserID.String(), cfg.PerUserRPS, cfg.Window); err == nil && !result.Allowed {
					w.Header().Set("Retry-After", fmt.Sprintf("%.0f", result.RetryAfter.Seconds()))
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					return
				}

				if result, err := limiter.AllowOrg(ctx, principal.OrgID.String(), cfg.PerOrgRPS, cfg.Window); err == nil && !result.Allowed {
					w.Header().Set("Retry-After", fmt.Sprintf("%.0f", result.RetryAfter.Seconds()))
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractIP(r *http.Request) string {
	// Check forwarded headers (when behind trusted reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (leftmost = original client)
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to remote addr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

// ─── Request Body Scanner ────────────────────────────────────────────────────

// InjectionScanMiddleware scans request bodies for prompt injection attempts.
// Only applies to endpoints that accept user instructions.
func InjectionScanMiddleware(scanner *security.Scanner, log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only scan POST/PUT/PATCH with content
			if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
				next.ServeHTTP(w, r)
				return
			}

			// Read headers to find task description fields (not full body scan)
			// Full body scan happens at the service layer with structured parsing
			if userInstruction := r.Header.Get("X-Agent-Instruction"); userInstruction != "" {
				result := scanner.Scan(r.Context(), userInstruction)
				if result.Action == security.ActionBlock {
					log.Warn("injection detected in request header",
						zap.String("score", fmt.Sprintf("%.2f", result.Score)),
						zap.String("correlation_id", CorrelationIDFromContext(r.Context())),
					)
					http.Error(w, "request rejected: security policy violation", http.StatusBadRequest)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ─── Structured Logging Middleware ────────────────────────────────────────────

// Logger logs structured request/response information.
func Logger(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", rw.statusCode),
				zap.Duration("duration", duration),
				zap.String("correlation_id", CorrelationIDFromContext(r.Context())),
				zap.String("remote_addr", extractIP(r)),
			}

			if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
				fields = append(fields,
					zap.String("user_id", principal.UserID.String()),
					zap.String("org_id", principal.OrgID.String()),
					zap.String("role", string(principal.Role)),
				)
			}

			if rw.statusCode >= 500 {
				log.Error("request completed", fields...)
			} else if rw.statusCode >= 400 {
				log.Warn("request completed", fields...)
			} else {
				log.Info("request completed", fields...)
			}
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// ─── Security Headers ────────────────────────────────────────────────────────

// SecurityHeaders adds secure response headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		// Remove server identification
		h.Del("Server")
		next.ServeHTTP(w, r)
	})
}

// RequirePermission is a route-level authorization middleware.
func RequirePermission(enforcer *auth.Enforcer, perm auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := auth.PrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := enforcer.RequirePermission(r.Context(), principal, perm); err != nil {
				http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── Request Timeout ─────────────────────────────────────────────────────────

// Timeout adds a deadline to each request context.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
