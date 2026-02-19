package security

// ActionType represents the category of action a tool performs.
type ActionType string

const (
	ActionTypeRead     ActionType = "read"
	ActionTypeWrite    ActionType = "write"
	ActionTypeNavigate ActionType = "navigate"
	ActionTypeExecute  ActionType = "execute"
	ActionTypeDelete   ActionType = "delete"
)

// RiskScore represents the calculated risk of an action.
type RiskScore struct {
	Total float64
}

// ScoreActionRisk calculates the risk of an action.
// This is a placeholder for the actual risk scoring logic.
func (e *Engine) ScoreActionRisk(action ActionType, isSystem bool, isEarly bool, metadata map[string]interface{}) RiskScore {
	// Default low risk
	return RiskScore{Total: 0.1}
}
