package security

import (
	"context"
)

// Engine is the main security entry point.
type Engine struct {
	scanner *Scanner
}

// NewEngine creates a new security engine.
func NewEngine(scanner *Scanner) *Engine {
	return &Engine{scanner: scanner}
}

// ValidateToolArguments checks if the arguments for a tool are safe.
func (e *Engine) ValidateToolArguments(ctx context.Context, toolName string, args map[string]interface{}) error {
	// For now, basic validation. Real implementation would check against policy.
	return nil
}

// ScanForInjection scans text for prompt injection attempts.
// Returns the matched pattern (if any) and a severity score (0.0 - 1.0).
func (e *Engine) ScanForInjection(ctx context.Context, text string) (*Trigger, float64) {
	result := e.scanner.Scan(ctx, text)
	if result.Detected && len(result.Triggers) > 0 {
		// Return the highest scoring trigger
		bestTrigger := &result.Triggers[0]
		for i := range result.Triggers {
			if result.Triggers[i].Score > bestTrigger.Score {
				bestTrigger = &result.Triggers[i]
			}
		}
		return bestTrigger, result.Score
	}
	return nil, 0.0
}
