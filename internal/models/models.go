package models

import (
	"time"

	"github.com/google/uuid"
)

// ─── Task ────────────────────────────────────────────────────────────────────

type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusQueued     TaskStatus = "queued"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusPaused     TaskStatus = "paused" // awaiting HITL
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
	TaskStatusBlocked    TaskStatus = "blocked" // compliance block
)

type TaskType string

const (
	TaskTypeWebBrowse    TaskType = "web_browse"
	TaskTypeDataExtract  TaskType = "data_extract"
	TaskTypeFormFill     TaskType = "form_fill"
	TaskTypeResearch     TaskType = "research"
	TaskTypeMonitor      TaskType = "monitor"
	TaskTypeAutomation   TaskType = "automation"
)

type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"      // < 0.3
	RiskLevelMedium   RiskLevel = "medium"   // 0.3 - 0.6
	RiskLevelHigh     RiskLevel = "high"     // 0.6 - 0.8
	RiskLevelCritical RiskLevel = "critical" // > 0.8
)

// Task is the core unit of work in the platform.
type Task struct {
	ID              uuid.UUID         `json:"id" db:"id"`
	OrgID           uuid.UUID         `json:"org_id" db:"org_id"`
	UserID          uuid.UUID         `json:"user_id" db:"user_id"`
	Type            TaskType          `json:"type" db:"type"`
	Status          TaskStatus        `json:"status" db:"status"`
	Description     string            `json:"description" db:"description"`
	Instructions    string            `json:"instructions" db:"instructions"`
	Context         map[string]string `json:"context" db:"context"`
	AllowedTools    []string          `json:"allowed_tools" db:"allowed_tools"`
	TokenBudget     int               `json:"token_budget" db:"token_budget"`
	TokensUsed      int               `json:"tokens_used" db:"tokens_used"`
	CostBudgetUSD   float64           `json:"cost_budget_usd" db:"cost_budget_usd"`
	CostUsedUSD     float64           `json:"cost_used_usd" db:"cost_used_usd"`
	MaxIterations   int               `json:"max_iterations" db:"max_iterations"`
	IterationCount  int               `json:"iteration_count" db:"iteration_count"`
	RiskScore       float64           `json:"risk_score" db:"risk_score"`
	RiskLevel       RiskLevel         `json:"risk_level" db:"risk_level"`
	HITLRequired    bool              `json:"hitl_required" db:"hitl_required"`
	HITLApproved    *bool             `json:"hitl_approved,omitempty" db:"hitl_approved"`
	HITLApprovedBy  *uuid.UUID        `json:"hitl_approved_by,omitempty" db:"hitl_approved_by"`
	HITLApprovedAt  *time.Time        `json:"hitl_approved_at,omitempty" db:"hitl_approved_at"`
	WorkflowID      string            `json:"workflow_id" db:"workflow_id"`
	CorrelationID   string            `json:"correlation_id" db:"correlation_id"`
	Result          *TaskResult       `json:"result,omitempty" db:"result"`
	Error           *TaskError        `json:"error,omitempty" db:"error"`
	Checkpoints     []Checkpoint      `json:"checkpoints,omitempty"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
	StartedAt       *time.Time        `json:"started_at,omitempty" db:"started_at"`
	CompletedAt     *time.Time        `json:"completed_at,omitempty" db:"completed_at"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty" db:"expires_at"`
}

type TaskResult struct {
	Summary     string            `json:"summary"`
	Data        interface{}       `json:"data,omitempty"`
	Artifacts   []Artifact        `json:"artifacts,omitempty"`
	StepsCompleted int            `json:"steps_completed"`
	Confidence  float64           `json:"confidence"`
	Partial     bool              `json:"partial"`
}

type TaskError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Step      int    `json:"step,omitempty"`
	Retryable bool   `json:"retryable"`
}

type Checkpoint struct {
	ID             uuid.UUID   `json:"id"`
	TaskID         uuid.UUID   `json:"task_id"`
	IterationNum   int         `json:"iteration_num"`
	CompletedSteps []string    `json:"completed_steps"`
	State          interface{} `json:"state"`
	TokensUsed     int         `json:"tokens_used"`
	CostUsed       float64     `json:"cost_used"`
	CreatedAt      time.Time   `json:"created_at"`
}

type Artifact struct {
	ID          uuid.UUID `json:"id"`
	TaskID      uuid.UUID `json:"task_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	StorageKey  string    `json:"storage_key"`
	Checksum    string    `json:"checksum"` // SHA-256
	CreatedAt   time.Time `json:"created_at"`
}

// ─── Agent Step ──────────────────────────────────────────────────────────────

type StepType string

const (
	StepTypeThink    StepType = "think"
	StepTypePlan     StepType = "plan"
	StepTypeAct      StepType = "act"
	StepTypeObserve  StepType = "observe"
	StepTypeVerify   StepType = "verify"
	StepTypeEscalate StepType = "escalate"
)

type AgentStep struct {
	ID            uuid.UUID   `json:"id"`
	TaskID        uuid.UUID   `json:"task_id"`
	IterationNum  int         `json:"iteration_num"`
	Type          StepType    `json:"type"`
	Input         interface{} `json:"input,omitempty"`
	Output        interface{} `json:"output,omitempty"`
	ToolCall      *ToolCall   `json:"tool_call,omitempty"`
	ToolResult    *ToolResult `json:"tool_result,omitempty"`
	TokensUsed    int         `json:"tokens_used"`
	CostUSD       float64     `json:"cost_usd"`
	DurationMs    int64       `json:"duration_ms"`
	RiskScore     float64     `json:"risk_score"`
	Success       bool        `json:"success"`
	Error         string      `json:"error,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
}

// ─── Tool ────────────────────────────────────────────────────────────────────

type ToolDefinition struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Version         string                 `json:"version"`
	Category        ToolCategory           `json:"category"`
	Parameters      map[string]interface{} `json:"parameters"` // JSON Schema
	RequiredParams  []string               `json:"required_params"`
	RiskLevel       RiskLevel              `json:"risk_level"`
	RequiresHITL    bool                   `json:"requires_hitl"`
	Capabilities    []string               `json:"capabilities"` // network, filesystem, etc.
	WASMModule      []byte                 `json:"-"`            // loaded at runtime
	Enabled         bool                   `json:"enabled"`
	PluginID        *uuid.UUID             `json:"plugin_id,omitempty"`
}

type ToolCategory string

const (
	ToolCategoryBrowse    ToolCategory = "browse"
	ToolCategoryExtract   ToolCategory = "extract"
	ToolCategorySearch    ToolCategory = "search"
	ToolCategoryCompute   ToolCategory = "compute"
	ToolCategoryStore     ToolCategory = "store"
	ToolCategoryNotify    ToolCategory = "notify"
	ToolCategoryDestructive ToolCategory = "destructive"
)

type ToolCall struct {
	ToolName   string                 `json:"tool_name"`
	Arguments  map[string]interface{} `json:"arguments"`
	CallID     string                 `json:"call_id"`
	IdempotencyKey string             `json:"idempotency_key"`
}

type ToolResult struct {
	CallID   string      `json:"call_id"`
	Success  bool        `json:"success"`
	Output   interface{} `json:"output,omitempty"`
	Error    string      `json:"error,omitempty"`
	Cached   bool        `json:"cached"`
}

// ─── HITL ────────────────────────────────────────────────────────────────────

type HITLRequestStatus string

const (
	HITLPending  HITLRequestStatus = "pending"
	HITLApproved HITLRequestStatus = "approved"
	HITLRejected HITLRequestStatus = "rejected"
	HITLExpired  HITLRequestStatus = "expired"
)

type HITLRequest struct {
	ID              uuid.UUID         `json:"id"`
	TaskID          uuid.UUID         `json:"task_id"`
	WorkflowID      string            `json:"workflow_id"`
	Reason          string            `json:"reason"`
	ProposedAction  interface{}       `json:"proposed_action"`
	Context         interface{}       `json:"context"`
	RiskScore       float64           `json:"risk_score"`
	RiskFactors     []string          `json:"risk_factors"`
	Status          HITLRequestStatus `json:"status"`
	AssignedTo      *uuid.UUID        `json:"assigned_to,omitempty"`
	ReviewedBy      *uuid.UUID        `json:"reviewed_by,omitempty"`
	ReviewNote      string            `json:"review_note,omitempty"`
	SLADeadline     time.Time         `json:"sla_deadline"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// ─── Audit ───────────────────────────────────────────────────────────────────

type AuditEventType string

const (
	AuditEventTaskCreated     AuditEventType = "task.created"
	AuditEventTaskStarted     AuditEventType = "task.started"
	AuditEventTaskCompleted   AuditEventType = "task.completed"
	AuditEventTaskFailed      AuditEventType = "task.failed"
	AuditEventTaskCancelled   AuditEventType = "task.cancelled"
	AuditEventToolCalled      AuditEventType = "tool.called"
	AuditEventToolBlocked     AuditEventType = "tool.blocked"
	AuditEventHITLRequested   AuditEventType = "hitl.requested"
	AuditEventHITLApproved    AuditEventType = "hitl.approved"
	AuditEventHITLRejected    AuditEventType = "hitl.rejected"
	AuditEventInjectionDetected AuditEventType = "security.injection_detected"
	AuditEventRateLimited     AuditEventType = "security.rate_limited"
	AuditEventAuthFailed      AuditEventType = "security.auth_failed"
	AuditEventComplianceBlock AuditEventType = "compliance.blocked"
	AuditEventLLMCalled       AuditEventType = "llm.called"
	AuditEventLLMError        AuditEventType = "llm.error"
)

type ActorType string

const (
	ActorTypeUser    ActorType = "user"
	ActorTypeService ActorType = "service"
	ActorTypeAgent   ActorType = "agent"
	ActorTypeSystem  ActorType = "system"
)

type AuditEvent struct {
	ID            uuid.UUID      `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	CorrelationID string         `json:"correlation_id"`
	TraceID       string         `json:"trace_id"`
	ServiceName   string         `json:"service_name"`
	EventType     AuditEventType `json:"event_type"`
	Actor         AuditActor     `json:"actor"`
	Resource      AuditResource  `json:"resource"`
	Outcome       string         `json:"outcome"` // success | failure | blocked
	RiskScore     float64        `json:"risk_score"`
	Severity      string         `json:"severity"` // info | warn | error | critical
	PrevHash      string         `json:"prev_hash"`    // SHA-256 of previous event
	Signature     string         `json:"signature"`    // ECDSA signature
	Payload       interface{}    `json:"payload"`      // event-specific data
	IPAddress     string         `json:"ip_address,omitempty"`
	UserAgent     string         `json:"user_agent,omitempty"`
}

type AuditActor struct {
	Type   ActorType  `json:"type"`
	ID     string     `json:"id"`
	OrgID  string     `json:"org_id,omitempty"`
	Email  string     `json:"email,omitempty"` // hashed in storage
}

type AuditResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// ─── User / RBAC ─────────────────────────────────────────────────────────────

type Role string

const (
	RolePlatformAdmin  Role = "platform_admin"
	RoleOrgAdmin       Role = "org_admin"
	RoleOperator       Role = "operator"
	RoleHITLReviewer   Role = "hitl_reviewer"
	RoleAuditor        Role = "auditor"
	RolePluginDev      Role = "plugin_developer"
)

type User struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	OrgID        uuid.UUID  `json:"org_id" db:"org_id"`
	Email        string     `json:"email" db:"email"`
	PasswordHash string     `json:"-" db:"password_hash"`
	Role         Role       `json:"role" db:"role"`
	Active       bool       `json:"active" db:"active"`
	MFAEnabled   bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret    string     `json:"-" db:"mfa_secret"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

type Organization struct {
	ID              uuid.UUID `json:"id" db:"id"`
	Name            string    `json:"name" db:"name"`
	Plan            string    `json:"plan" db:"plan"` // free | pro | enterprise
	MonthlyTokenBudget int    `json:"monthly_token_budget" db:"monthly_token_budget"`
	TokensUsedMonth int       `json:"tokens_used_month" db:"tokens_used_month"`
	MonthlyBudgetUSD float64  `json:"monthly_budget_usd" db:"monthly_budget_usd"`
	CostUsedMonth   float64   `json:"cost_used_month" db:"cost_used_month"`
	Active          bool      `json:"active" db:"active"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// ─── Plugin ──────────────────────────────────────────────────────────────────

type PluginStatus string

const (
	PluginStatusPending  PluginStatus = "pending_review"
	PluginStatusApproved PluginStatus = "approved"
	PluginStatusRejected PluginStatus = "rejected"
	PluginStatusRevoked  PluginStatus = "revoked"
)

type Plugin struct {
	ID           uuid.UUID    `json:"id" db:"id"`
	Name         string       `json:"name" db:"name"`
	Version      string       `json:"version" db:"version"`
	Description  string       `json:"description" db:"description"`
	AuthorID     uuid.UUID    `json:"author_id" db:"author_id"`
	WASMChecksum string       `json:"wasm_checksum" db:"wasm_checksum"` // SHA-256
	WASMStorageKey string     `json:"wasm_storage_key" db:"wasm_storage_key"`
	Capabilities []string     `json:"capabilities" db:"capabilities"`
	Status       PluginStatus `json:"status" db:"status"`
	ReviewedBy   *uuid.UUID   `json:"reviewed_by,omitempty" db:"reviewed_by"`
	ReviewedAt   *time.Time   `json:"reviewed_at,omitempty" db:"reviewed_at"`
	ReviewNotes  string       `json:"review_notes,omitempty" db:"review_notes"`
	Signature    string       `json:"signature" db:"signature"` // cryptographic signature
	CreatedAt    time.Time    `json:"created_at" db:"created_at"`
}
