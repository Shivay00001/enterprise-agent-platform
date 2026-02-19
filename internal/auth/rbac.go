package auth

import (
	"context"
	"fmt"

	"github.com/enterprise/agent-platform/internal/models"
	"github.com/google/uuid"
)

// Permission represents a fine-grained action on a resource type.
type Permission string

const (
	// Task permissions
	PermTaskCreate  Permission = "task:create"
	PermTaskRead    Permission = "task:read"
	PermTaskCancel  Permission = "task:cancel"
	PermTaskReadAll Permission = "task:read:all" // across org
	PermTaskReadOrg Permission = "task:read:org" // own org only

	// Tool permissions
	PermToolInvoke         Permission = "tool:invoke"
	PermToolInvokeHigh     Permission = "tool:invoke:high_risk"
	PermToolInvokeCritical Permission = "tool:invoke:critical"
	PermToolRegister       Permission = "tool:register"
	PermToolApprove        Permission = "tool:approve"

	// HITL permissions
	PermHITLReview  Permission = "hitl:review"
	PermHITLApprove Permission = "hitl:approve"

	// Audit permissions
	PermAuditRead    Permission = "audit:read"
	PermAuditExport  Permission = "audit:export"
	PermAuditReadAll Permission = "audit:read:all"

	// Admin permissions
	PermUserManage         Permission = "user:manage"
	PermOrgManage          Permission = "org:manage"
	PermPolicyModify       Permission = "policy:modify"
	PermPluginApprove      Permission = "plugin:approve"
	PermSystemAdmin        Permission = "system:admin"
	PermComplianceOverride Permission = "compliance:override"

	// Model permissions
	PermModelDefault Permission = "model:default"
	PermModelHighCap Permission = "model:high_capability"
	PermModelLocal   Permission = "model:local"
)

// rolePermissions defines the permissions granted to each role.
// This is the authoritative permission matrix — any change here
// requires a security review and is captured in the audit log.
var rolePermissions = map[models.Role][]Permission{
	models.RolePlatformAdmin: {
		PermTaskCreate, PermTaskRead, PermTaskCancel, PermTaskReadAll,
		PermToolInvoke, PermToolInvokeHigh, PermToolInvokeCritical,
		PermToolRegister, PermToolApprove,
		PermHITLReview, PermHITLApprove,
		PermAuditRead, PermAuditExport, PermAuditReadAll,
		PermUserManage, PermOrgManage, PermPolicyModify,
		PermPluginApprove, PermSystemAdmin,
		PermModelDefault, PermModelHighCap, PermModelLocal,
	},
	models.RoleOrgAdmin: {
		PermTaskCreate, PermTaskRead, PermTaskCancel, PermTaskReadOrg,
		PermToolInvoke, PermToolInvokeHigh,
		PermHITLReview, PermHITLApprove,
		PermAuditRead, PermAuditExport,
		PermUserManage,
		PermModelDefault, PermModelHighCap,
	},
	models.RoleOperator: {
		PermTaskCreate, PermTaskRead, PermTaskCancel,
		PermToolInvoke,
		PermAuditRead,
		PermModelDefault,
	},
	models.RoleHITLReviewer: {
		PermTaskRead,
		PermHITLReview, PermHITLApprove,
		PermAuditRead,
	},
	models.RoleAuditor: {
		PermAuditRead, PermAuditExport, PermAuditReadAll,
		PermTaskRead,
	},
	models.RolePluginDev: {
		PermToolRegister,
		PermTaskRead, // own tasks only
	},
}

// tokenBudgets defines the maximum tokens per task for each role.
var tokenBudgets = map[models.Role]int{
	models.RolePlatformAdmin: 100000,
	models.RoleOrgAdmin:      50000,
	models.RoleOperator:      20000,
	models.RoleHITLReviewer:  0, // cannot create tasks
	models.RoleAuditor:       0,
	models.RolePluginDev:     5000,
}

// costBudgets defines max USD per task for each role.
var costBudgets = map[models.Role]float64{
	models.RolePlatformAdmin: 10.0,
	models.RoleOrgAdmin:      5.0,
	models.RoleOperator:      1.0,
	models.RoleHITLReviewer:  0,
	models.RoleAuditor:       0,
	models.RolePluginDev:     0.1,
}

// hitlThresholds defines the risk score above which HITL is required per role.
var hitlThresholds = map[models.Role]float64{
	models.RolePlatformAdmin: 0.9, // high bar, trusted role
	models.RoleOrgAdmin:      0.7,
	models.RoleOperator:      0.6,
	models.RoleHITLReviewer:  0.0, // cannot create tasks anyway
	models.RoleAuditor:       0.0,
	models.RolePluginDev:     0.4,
}

// Principal represents an authenticated entity making a request.
type Principal struct {
	UserID uuid.UUID
	OrgID  uuid.UUID
	Email  string
	Role   models.Role
}

// Enforcer performs RBAC authorization checks.
type Enforcer struct{}

// NewEnforcer creates a new RBAC enforcer.
func NewEnforcer() *Enforcer {
	return &Enforcer{}
}

// HasPermission returns true if the principal holds the given permission.
func (e *Enforcer) HasPermission(ctx context.Context, principal *Principal, perm Permission) bool {
	perms, ok := rolePermissions[principal.Role]
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

// RequirePermission returns an error if the principal does not hold the permission.
func (e *Enforcer) RequirePermission(ctx context.Context, principal *Principal, perm Permission) error {
	if !e.HasPermission(ctx, principal, perm) {
		return &AuthorizationError{
			Principal:  principal,
			Permission: perm,
		}
	}
	return nil
}

// CanAccessTask checks whether the principal can access a specific task.
// Org-scoped roles can only access tasks within their org.
func (e *Enforcer) CanAccessTask(ctx context.Context, principal *Principal, taskOrgID, taskUserID uuid.UUID) error {
	if !e.HasPermission(ctx, principal, PermTaskRead) {
		return &AuthorizationError{Principal: principal, Permission: PermTaskRead}
	}

	// Platform admins can read all tasks
	if e.HasPermission(ctx, principal, PermTaskReadAll) {
		return nil
	}

	// Org admins can read all tasks in their org
	if e.HasPermission(ctx, principal, PermTaskReadOrg) {
		if principal.OrgID != taskOrgID {
			return fmt.Errorf("access denied: task belongs to different organization")
		}
		return nil
	}

	// Operators can only read their own tasks
	if principal.UserID != taskUserID {
		return fmt.Errorf("access denied: can only access own tasks")
	}

	return nil
}

// CanInvokeTool checks whether the principal can invoke a tool at the given risk level.
func (e *Enforcer) CanInvokeTool(ctx context.Context, principal *Principal, toolRisk models.RiskLevel) error {
	switch toolRisk {
	case models.RiskLevelLow, models.RiskLevelMedium:
		return e.RequirePermission(ctx, principal, PermToolInvoke)
	case models.RiskLevelHigh:
		return e.RequirePermission(ctx, principal, PermToolInvokeHigh)
	case models.RiskLevelCritical:
		return e.RequirePermission(ctx, principal, PermToolInvokeCritical)
	default:
		return fmt.Errorf("unknown risk level: %s", toolRisk)
	}
}

// TokenBudget returns the maximum token budget for the principal's role.
func (e *Enforcer) TokenBudget(principal *Principal, requested int) (int, error) {
	max, ok := tokenBudgets[principal.Role]
	if !ok {
		return 0, fmt.Errorf("unknown role: %s", principal.Role)
	}
	if max == 0 {
		return 0, fmt.Errorf("role %s cannot create tasks", principal.Role)
	}
	if requested <= 0 || requested > max {
		return max, nil // clamp to role maximum
	}
	return requested, nil
}

// CostBudget returns the maximum cost budget (USD) for the principal's role.
func (e *Enforcer) CostBudget(principal *Principal, requested float64) (float64, error) {
	max, ok := costBudgets[principal.Role]
	if !ok {
		return 0, fmt.Errorf("unknown role: %s", principal.Role)
	}
	if max == 0 {
		return 0, fmt.Errorf("role %s cannot create tasks", principal.Role)
	}
	if requested <= 0 || requested > max {
		return max, nil
	}
	return requested, nil
}

// HITLThreshold returns the risk score above which HITL is required for this principal.
func (e *Enforcer) HITLThreshold(principal *Principal) float64 {
	threshold, ok := hitlThresholds[principal.Role]
	if !ok {
		return 0.0 // default: always require HITL
	}
	return threshold
}

// RequiresHITL returns true if the given risk score exceeds the principal's HITL threshold.
func (e *Enforcer) RequiresHITL(principal *Principal, riskScore float64) bool {
	return riskScore >= e.HITLThreshold(principal)
}

// ─── Errors ──────────────────────────────────────────────────────────────────

type AuthorizationError struct {
	Principal  *Principal
	Permission Permission
	Reason     string
}

func (e *AuthorizationError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("authorization denied: role %s lacks permission %s: %s",
			e.Principal.Role, e.Permission, e.Reason)
	}
	return fmt.Sprintf("authorization denied: role %s lacks permission %s",
		e.Principal.Role, e.Permission)
}

func IsAuthorizationError(err error) bool {
	_, ok := err.(*AuthorizationError)
	return ok
}

// ─── Context helpers ─────────────────────────────────────────────────────────

type contextKey string

const principalKey contextKey = "principal"

// WithPrincipal stores the principal in the context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext retrieves the principal from the context.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok
}

// MustPrincipal retrieves the principal or panics — use only in middleware-protected handlers.
func MustPrincipal(ctx context.Context) *Principal {
	p, ok := PrincipalFromContext(ctx)
	if !ok {
		panic("principal not in context: handler must be protected by auth middleware")
	}
	return p
}
