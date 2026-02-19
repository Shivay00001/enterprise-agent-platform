package llm

import "github.com/enterprise/agent-platform/internal/models"

// ─── Request / Response types ─────────────────────────────────────────────────

type ThinkRequest struct {
	TaskID      string            `json:"task_id"`
	Description string            `json:"description"`
	TaskType    string            `json:"task_type"`
	Context     map[string]string `json:"context,omitempty"`
}

type ThinkResponse struct {
	Understanding string   `json:"understanding"`
	Feasible      bool     `json:"feasible"`
	Constraints   []string `json:"constraints,omitempty"`
	TokensUsed    int      `json:"tokens_used"`
	CostUSD       float64  `json:"cost_usd"`
}

type PlanRequest struct {
	TaskID        string   `json:"task_id"`
	Understanding string   `json:"understanding"`
	AllowedTools  []string `json:"allowed_tools"`
}

type PlanResponse struct {
	Plan       *Plan   `json:"plan"`
	TokensUsed int     `json:"tokens_used"`
	CostUSD    float64 `json:"cost_usd"`
}

type Plan struct {
	Steps      []PlanStep `json:"steps"`
	Summary    string     `json:"summary"`
	Reversible bool       `json:"reversible"`
}

type PlanStep struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	ToolName       string                 `json:"tool_name,omitempty"`
	Arguments      map[string]interface{} `json:"arguments,omitempty"`
	Reason         string                 `json:"reason"`
	ExpectedOutput interface{}            `json:"expected_output,omitempty"`
	DependsOn      []string               `json:"depends_on,omitempty"`
	RetryCount     int                    `json:"retry_count"`
}

type ObserveRequest struct {
	TaskID         string             `json:"task_id"`
	Step           string             `json:"step"`
	ToolResult     *models.ToolResult `json:"tool_result"`
	CompletedSteps []string           `json:"completed_steps"`
}

type ObserveResponse struct {
	Analysis   string  `json:"analysis"`
	Progress   float64 `json:"progress"` // 0-1
	TokensUsed int     `json:"tokens_used"`
	CostUSD    float64 `json:"cost_usd"`
}

type VerifyRequest struct {
	TaskID          string             `json:"task_id"`
	Step            string             `json:"step"`
	ExpectedOutcome interface{}        `json:"expected_outcome"`
	ActualResult    *models.ToolResult `json:"actual_result"`
	Observation     string             `json:"observation"`
}

type VerifyResponse struct {
	Verified   bool    `json:"verified"`
	Reason     string  `json:"reason"`
	TokensUsed int     `json:"tokens_used"`
	CostUSD    float64 `json:"cost_usd"`
}

// ToolDefinition defines a tool exposed to the LLM.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type ToolCall struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type Message struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

type TaskBudget struct {
	TaskID         string
	TokenBudget    int
	TokensConsumed int
	CostBudget     float64
	CostConsumed   float64
}

func (b *TaskBudget) BudgetWarning() (bool, string) {
	if float64(b.TokensConsumed) > float64(b.TokenBudget)*0.8 {
		return true, "Warning: 80% of token budget consumed"
	}
	return false, ""
}
