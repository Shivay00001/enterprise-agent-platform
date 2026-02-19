package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/enterprise/agent-platform/internal/models"
	appcfg "github.com/enterprise/agent-platform/pkg/config"
	apperr "github.com/enterprise/agent-platform/pkg/errors"
)

// Role and Permission definitions are in rbac.go and internal/models

// Claims represents the JWT claims payload.
type Claims struct {
	UserID    string      `json:"uid"`
	OrgID     string      `json:"oid"`
	Role      models.Role `json:"rol"`
	SessionID string      `json:"sid"`
	jwt.RegisteredClaims
}

// Service provides authentication and authorisation.
type Service struct {
	cfg    *appcfg.AuthConfig
	redis  *redis.Client
	secret []byte
}

// NewService creates a new auth service.
func NewService(cfg *appcfg.AuthConfig, rdb *redis.Client, jwtSecret string) *Service {
	return &Service{
		cfg:    cfg,
		redis:  rdb,
		secret: []byte(jwtSecret),
	}
}

// IssueToken creates a signed JWT for the given user.
func (s *Service) IssueToken(ctx context.Context, userID, orgID string, role models.Role) (string, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	now := time.Now().UTC()
	claims := Claims{
		UserID:    userID,
		OrgID:     orgID,
		Role:      role,
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti.String(),
			Issuer:    "agent-platform-auth",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.JWTExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// ValidateToken validates a JWT and checks revocation.
func (s *Service) ValidateToken(ctx context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, apperr.ErrUnauthorized.Wrap(err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, apperr.ErrUnauthorized
	}

	// Check token revocation list in Redis.
	revoked, err := s.isRevoked(ctx, claims.RegisteredClaims.ID)
	if err != nil {
		return nil, fmt.Errorf("check revocation: %w", err)
	}
	if revoked {
		return nil, apperr.ErrUnauthorized.WithField("reason", "token_revoked")
	}

	return claims, nil
}

// RevokeToken adds a JTI to the revocation list until its expiry.
func (s *Service) RevokeToken(ctx context.Context, claims *Claims) error {
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil // Already expired, nothing to revoke.
	}
	key := revokedKey(claims.RegisteredClaims.ID)
	return s.redis.Set(ctx, key, "1", ttl).Err()
}

func (s *Service) isRevoked(ctx context.Context, jti string) (bool, error) {
	key := revokedKey(jti)
	res, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return res > 0, nil
}

func revokedKey(jti string) string {
	return "auth:revoked:" + jti
}

// HasPermission checks if the given role has the requested permission.
func HasPermission(role models.Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// Middleware is HTTP middleware that validates JWTs and injects claims into context.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			http.Error(w, "authorization header required", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			http.Error(w, "malformed authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := s.ValidateToken(r.Context(), parts[1])
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := ContextWithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission is HTTP middleware that enforces a specific permission.
func (s *Service) RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "no auth context", http.StatusUnauthorized)
				return
			}
			if !HasPermission(claims.Role, perm) {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type ctxKey string

const claimsKey ctxKey = "auth_claims"

// ContextWithClaims stores claims in context.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext retrieves claims from context.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// BuildMTLSConfig creates a tls.Config for mutual TLS using the configured CA and certs.
func BuildMTLSConfig(cfg *appcfg.AuthConfig) (*tls.Config, error) {
	caCert, err := os.ReadFile(cfg.MTLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	cert, err := tls.LoadX509KeyPair(cfg.MTLSCertFile, cfg.MTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load service cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
