package agent

import (
	"context"
	"math"
	"strings"

	"github.com/enterprise/agent-platform/internal/models"
)

// RiskScorer computes risk scores for planned agent actions.
// Scores are in [0.0, 1.0] where 1.0 is maximally dangerous.
type RiskScorer struct{}

func NewRiskScorer() *RiskScorer {
	return &RiskScorer{}
}

// RiskFactors holds the individual dimensions of risk for an action.
type RiskFactors struct {
	Destructiveness float64          `json:"destructiveness"` // can this cause permanent damage?
	Reversibility   float64          `json:"reversibility"`   // can it be undone?
	Scope           float64          `json:"scope"`           // how many resources affected?
	ExternalEffect  float64          `json:"external_effect"` // real-world effects?
	Novelty         float64          `json:"novelty"`         // have we done this before?
	Composite       float64          `json:"composite"`       // final score
	Level           models.RiskLevel `json:"level"`
	Factors         []string         `json:"factors"` // human-readable explanations
}

// PlannedAction represents an action the agent is about to take.
type PlannedAction struct {
	ToolName     string
	Arguments    map[string]interface{}
	Context      string
	PriorActions []string // history for novelty calculation
}

// Score computes the risk score for a planned action.
func (r *RiskScorer) Score(ctx context.Context, action *PlannedAction, tool *models.ToolDefinition) *RiskFactors {
	rf := &RiskFactors{}
	var reasons []string

	// ─── Destructiveness ─────────────────────────────────────────────────────
	switch tool.Category {
	case models.ToolCategoryDestructive:
		rf.Destructiveness = 0.95
		reasons = append(reasons, "tool is in destructive category")
	case models.ToolCategoryNotify:
		rf.Destructiveness = 0.70
		reasons = append(reasons, "sending notifications has external effects")
	case models.ToolCategoryStore:
		rf.Destructiveness = 0.40
		reasons = append(reasons, "data modification")
	case models.ToolCategoryBrowse, models.ToolCategorySearch:
		rf.Destructiveness = 0.05
		// read-only operations
	default:
		rf.Destructiveness = 0.20
	}

	// Amplify destructiveness for known dangerous argument patterns
	if hasDeletePattern(action.ToolName, action.Arguments) {
		rf.Destructiveness = math.Max(rf.Destructiveness, 0.90)
		reasons = append(reasons, "delete/remove operation detected")
	}
	if hasBulkPattern(action.Arguments) {
		rf.Destructiveness = math.Min(1.0, rf.Destructiveness*1.3)
		reasons = append(reasons, "bulk operation")
	}

	// ─── Reversibility ────────────────────────────────────────────────────────
	if isHardDelete(action.ToolName, action.Arguments) {
		rf.Reversibility = 1.0
		reasons = append(reasons, "hard delete: cannot be undone")
	} else if isSoftDelete(action.ToolName, action.Arguments) {
		rf.Reversibility = 0.20
		reasons = append(reasons, "soft delete: recoverable")
	} else if isWriteOperation(action.ToolName) {
		rf.Reversibility = 0.35
		reasons = append(reasons, "write operation: reversible with effort")
	} else {
		rf.Reversibility = 0.05
	}

	// ─── Scope ───────────────────────────────────────────────────────────────
	rf.Scope = scopeScore(action.Arguments)
	if rf.Scope > 0.5 {
		reasons = append(reasons, "affects multiple resources")
	}

	// ─── External Effect ─────────────────────────────────────────────────────
	rf.ExternalEffect = externalEffectScore(tool, action)
	if rf.ExternalEffect > 0.5 {
		reasons = append(reasons, "causes real-world external effects")
	}

	// ─── Novelty ─────────────────────────────────────────────────────────────
	rf.Novelty = noveltyScore(action, action.PriorActions)
	if rf.Novelty > 0.5 {
		reasons = append(reasons, "action type not seen in recent history")
	}

	// ─── Composite ───────────────────────────────────────────────────────────
	// Primary: max of destructiveness and (reversibility weighted)
	// Secondary: scope + external effect contribution
	// Tertiary: novelty small bump
	primary := math.Max(rf.Destructiveness, 0.5*rf.Reversibility+0.5*rf.Destructiveness)
	secondary := 0.3*rf.Scope + 0.4*rf.ExternalEffect
	tertiary := 0.1 * rf.Novelty

	composite := math.Min(1.0, primary*0.6+secondary*0.3+tertiary*0.1)

	// Direct overrides for critical tool types
	if tool.RequiresHITL {
		composite = math.Max(composite, 0.70)
		reasons = append(reasons, "tool marked as requiring HITL")
	}

	rf.Composite = composite
	rf.Factors = reasons
	rf.Level = riskLevel(composite)

	return rf
}

func riskLevel(score float64) models.RiskLevel {
	switch {
	case score >= 0.8:
		return models.RiskLevelCritical
	case score >= 0.6:
		return models.RiskLevelHigh
	case score >= 0.3:
		return models.RiskLevelMedium
	default:
		return models.RiskLevelLow
	}
}

func hasDeletePattern(toolName string, args map[string]interface{}) bool {
	toolLower := strings.ToLower(toolName)
	if strings.Contains(toolLower, "delete") || strings.Contains(toolLower, "remove") ||
		strings.Contains(toolLower, "destroy") || strings.Contains(toolLower, "purge") {
		return true
	}
	for k, v := range args {
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, "delete") || strings.Contains(kLower, "remove") {
			return true
		}
		if s, ok := v.(string); ok {
			sLower := strings.ToLower(s)
			if strings.Contains(sLower, "delete=true") || strings.Contains(sLower, "force=true") {
				return true
			}
		}
	}
	return false
}

func isHardDelete(toolName string, args map[string]interface{}) bool {
	toolLower := strings.ToLower(toolName)
	if strings.Contains(toolLower, "hard_delete") || strings.Contains(toolLower, "permanent") {
		return true
	}
	for k, v := range args {
		if strings.ToLower(k) == "permanent" || strings.ToLower(k) == "hard" {
			if b, ok := v.(bool); ok && b {
				return true
			}
		}
	}
	return false
}

func isSoftDelete(toolName string, args map[string]interface{}) bool {
	return strings.Contains(strings.ToLower(toolName), "soft_delete") ||
		strings.Contains(strings.ToLower(toolName), "archive")
}

func isWriteOperation(toolName string) bool {
	lower := strings.ToLower(toolName)
	writeWords := []string{"create", "update", "write", "submit", "post", "send", "publish", "set", "put", "patch"}
	for _, w := range writeWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func hasBulkPattern(args map[string]interface{}) bool {
	for k, v := range args {
		lower := strings.ToLower(k)
		if lower == "all" || lower == "bulk" || lower == "batch" {
			if b, ok := v.(bool); ok && b {
				return true
			}
		}
		// Check for array/list arguments with many items
		if arr, ok := v.([]interface{}); ok && len(arr) > 10 {
			return true
		}
	}
	return false
}

func scopeScore(args map[string]interface{}) float64 {
	// Look for indicators of broad scope
	for k, v := range args {
		lower := strings.ToLower(k)
		if lower == "all" || lower == "everyone" || lower == "global" {
			if b, ok := v.(bool); ok && b {
				return 0.90
			}
		}
		if arr, ok := v.([]interface{}); ok {
			n := len(arr)
			if n > 100 {
				return 0.95
			} else if n > 10 {
				return 0.70
			} else if n > 1 {
				return 0.40
			}
		}
	}
	return 0.10 // single resource
}

func externalEffectScore(tool *models.ToolDefinition, action *PlannedAction) float64 {
	toolLower := strings.ToLower(action.ToolName)

	// Payment/financial
	if strings.Contains(toolLower, "pay") || strings.Contains(toolLower, "charge") ||
		strings.Contains(toolLower, "purchase") || strings.Contains(toolLower, "buy") {
		return 0.95
	}

	// Communication
	if strings.Contains(toolLower, "email") || strings.Contains(toolLower, "sms") ||
		strings.Contains(toolLower, "notify") || strings.Contains(toolLower, "message") ||
		strings.Contains(toolLower, "send") {
		return 0.75
	}

	// Form submission
	if strings.Contains(toolLower, "submit") || strings.Contains(toolLower, "form") {
		return 0.60
	}

	// API calls
	if strings.Contains(toolLower, "api") || strings.Contains(toolLower, "webhook") {
		return 0.50
	}

	// Reading/browsing
	if tool.Category == models.ToolCategoryBrowse || tool.Category == models.ToolCategorySearch {
		return 0.05
	}

	return 0.20
}

func noveltyScore(action *PlannedAction, history []string) float64 {
	if len(history) == 0 {
		return 0.50 // no history = moderate novelty
	}
	toolKey := strings.ToLower(action.ToolName)
	for _, h := range history {
		if strings.Contains(strings.ToLower(h), toolKey) {
			return 0.10 // seen before
		}
	}
	return 0.50 // not seen in history
}
