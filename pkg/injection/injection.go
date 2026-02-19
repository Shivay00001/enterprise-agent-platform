package injection

import (
	"context"
	"strings"
)

// Action defines the action to take based on scan results.
type Action string

const (
	ActionBlock Action = "block"
	ActionAllow Action = "allow"
	ActionFlag  Action = "flag"
)

// ScanResult holds the result of an injection scan.
type ScanResult struct {
	Action   Action
	Score    float64
	Triggers []string
}

// Scanner handles prompt injection detection.
type Scanner struct {
	// configuration fields can be added here
}

// NewScanner creates a new Scanner instance.
func NewScanner() *Scanner {
	return &Scanner{}
}

// Scan checks the input for prompt injection attempts.
func (s *Scanner) Scan(ctx context.Context, input string) *ScanResult {
	// Basic heuristic implementation
	// In a real system, this might call an external model or use complex rules.

	lower := strings.ToLower(input)
	score := 0.0
	var triggers []string

	// Simple keyword detection for demonstration
	if strings.Contains(lower, "ignore previous instructions") {
		score += 0.9
		triggers = append(triggers, "ignore_instructions")
	}
	if strings.Contains(lower, "system prompt") {
		score += 0.5
		triggers = append(triggers, "system_prompt_leak")
	}

	action := ActionAllow
	if score >= 0.8 {
		action = ActionBlock
	} else if score >= 0.4 {
		action = ActionFlag
	}

	return &ScanResult{
		Action:   action,
		Score:    score,
		Triggers: triggers,
	}
}

// ScanWebContent checks web content for potential injection attacks or harmful content.
func (s *Scanner) ScanWebContent(ctx context.Context, content string) *ScanResult {
	// Similar to Scan but potentially different heuristics for web content
	return s.Scan(ctx, content)
}

// SanitizeForPrompt cleans the input to make it safer for inclusion in a prompt.
func SanitizeForPrompt(input string) string {
	// Basic sanitization
	// Remove potential control characters or delimiters that could confuse the LLM
	sanitized := strings.ReplaceAll(input, "<|endoftext|>", "")
	sanitized = strings.ReplaceAll(sanitized, "[INST]", "")
	sanitized = strings.ReplaceAll(sanitized, "[/INST]", "")
	return sanitized
}
