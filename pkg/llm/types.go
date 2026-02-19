package llm

import (
	"github.com/enterprise/agent-platform/internal/models"
)

// ThinkRequest is the input for the thinking phase.
type ThinkRequest struct {
	TaskID      string
	Description string
	TaskType    string
	Context     map[string]string
}

// ThinkResponse is the output of the thinking phase.
type ThinkResponse struct {
	Understanding string
	TokensUsed    int
	CostUSD       float64
}

// PlanRequest is the input for the planning phase.
type PlanRequest struct {
	TaskID        string
	Understanding string
	AllowedTools  []string
}

// PlanResponse is the output of the planning phase.
type PlanResponse struct {
	Plan       *Plan
	TokensUsed int
	CostUSD    float64
}

// Plan represents the sequence of steps.
type Plan struct {
	Steps []PlanStep
}

// PlanStep represents a single step in the plan.
type PlanStep struct {
	Name           string
	ToolName       string
	Arguments      map[string]interface{}
	Reason         string
	ExpectedOutput string
	RetryCount     int
}

// ObserveRequest is the input for the observation phase.
type ObserveRequest struct {
	TaskID         string
	Step           string
	ToolResult     *models.ToolResult
	CompletedSteps []string
}

// ObserveResponse is the output of the observation phase.
type ObserveResponse struct {
	Analysis   string
	TokensUsed int
	CostUSD    float64
}

// VerifyRequest is the input for the verification phase.
type VerifyRequest struct {
	TaskID          string
	Step            string
	ExpectedOutcome string
	ActualResult    *models.ToolResult
	Observation     string
}

// VerifyResponse is the output of the verification phase.
type VerifyResponse struct {
	Verified   bool
	TokensUsed int
	CostUSD    float64
}
