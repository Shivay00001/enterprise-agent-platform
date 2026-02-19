package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/enterprise/agent-platform/internal/auth"
	"github.com/enterprise/agent-platform/internal/models"
	appcfg "github.com/enterprise/agent-platform/pkg/config"
)

// miniredis would be used in a real test suite; here we use a nil client
// and test only the logic that doesn't require Redis (token signing/validation).

func testAuthConfig() *appcfg.AuthConfig {
	return &appcfg.AuthConfig{
		JWTExpiry:          15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
}

func TestIssueAndValidateToken(t *testing.T) {
	svc := auth.NewService(testAuthConfig(), nil, "test-secret-key-must-be-long-enough")
	ctx := context.Background()

	token, err := svc.IssueToken(ctx, "user-123", "org-456", models.RoleOperator)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// ValidateToken with nil redis means revocation check is skipped in tests.
	// In integration tests, use miniredis.
	claims, err := svc.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("expected UserID user-123, got %q", claims.UserID)
	}
	if claims.OrgID != "org-456" {
		t.Errorf("expected OrgID org-456, got %q", claims.OrgID)
	}
	if claims.Role != models.RoleOperator {
		t.Errorf("expected role operator, got %q", claims.Role)
	}
	if claims.RegisteredClaims.ID == "" {
		t.Error("expected non-empty JTI")
	}
	if claims.SessionID == "" {
		t.Error("expected non-empty session ID")
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	svc := auth.NewService(testAuthConfig(), nil, "test-secret-key-must-be-long-enough")
	ctx := context.Background()

	cases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage token", "notavalidjwt"},
		{"wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ1c2VyIn0.wrongsig"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ValidateToken(ctx, tc.token)
			if err == nil {
				t.Errorf("expected error for invalid token %q, got nil", tc.name)
			}
		})
	}
}

func TestHasPermission_Matrix(t *testing.T) {
	cases := []struct {
		role       models.Role
		permission auth.Permission
		want       bool
	}{
		// Platform admin can do everything
		{models.RolePlatformAdmin, auth.PermTaskCreate, true},
		{models.RolePlatformAdmin, auth.PermPolicyModify, true},
		{models.RolePlatformAdmin, auth.PermComplianceOverride, true},

		// Operator can create tasks and invoke tools
		{models.RoleOperator, auth.PermTaskCreate, true},
		{models.RoleOperator, auth.PermToolInvoke, true},
		{models.RoleOperator, auth.PermAuditRead, true},
		// But cannot manage policies or users
		{models.RoleOperator, auth.PermPolicyModify, false},
		{models.RoleOperator, auth.PermUserManage, false},
		{models.RoleOperator, auth.PermComplianceOverride, false},

		// HITL reviewer can only approve reviews and read tasks
		{models.RoleHITLReviewer, auth.PermHITLApprove, true},
		{models.RoleHITLReviewer, auth.PermTaskRead, true},
		{models.RoleHITLReviewer, auth.PermTaskCreate, false},
		{models.RoleHITLReviewer, auth.PermToolInvoke, false},

		// Auditor is read-only
		{models.RoleAuditor, auth.PermAuditRead, true},
		{models.RoleAuditor, auth.PermTaskRead, true},
		{models.RoleAuditor, auth.PermTaskCreate, false},
		{models.RoleAuditor, auth.PermToolInvoke, false},
		{models.RoleAuditor, auth.PermPolicyModify, false},

		// Plugin developer has minimal permissions
		{models.RolePluginDev, auth.PermToolRegister, true},
		{models.RolePluginDev, auth.PermTaskCreate, false},
		{models.RolePluginDev, auth.PermToolInvoke, false},
	}

	for _, tc := range cases {
		name := string(tc.role) + "_" + string(tc.permission)
		t.Run(name, func(t *testing.T) {
			got := auth.HasPermission(tc.role, tc.permission)
			if got != tc.want {
				t.Errorf("HasPermission(%q, %q) = %v, want %v",
					tc.role, tc.permission, got, tc.want)
			}
		})
	}
}

func TestTokenExpiry(t *testing.T) {
	// Use a very short expiry to test expiration.
	cfg := &appcfg.AuthConfig{
		JWTExpiry: 1 * time.Millisecond,
	}
	svc := auth.NewService(cfg, nil, "test-secret-key-must-be-long-enough")
	ctx := context.Background()

	token, err := svc.IssueToken(ctx, "user-1", "org-1", models.RoleOperator)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = svc.ValidateToken(ctx, token)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}
