package security

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// DetectionResult holds the result of an injection scan.
type DetectionResult struct {
	Detected   bool      `json:"detected"`
	Score      float64   `json:"score"` // 0.0 = clean, 1.0 = definite injection
	Confidence float64   `json:"confidence"`
	Triggers   []Trigger `json:"triggers"`
	Action     Action    `json:"action"`
}

type Trigger struct {
	RuleID      string  `json:"rule_id"`
	RuleType    string  `json:"rule_type"`
	Description string  `json:"description"`
	Matched     string  `json:"matched"`
	Score       float64 `json:"score"`
}

type Action string

const (
	ActionAllow  Action = "allow"
	ActionReview Action = "review" // escalate to HITL
	ActionBlock  Action = "block"
)

// Scanner detects prompt injection attempts in user-supplied text.
// Uses multiple detection strategies: pattern matching, structural analysis,
// instruction detection, and heuristic scoring.
type Scanner struct {
	mu                  sync.RWMutex
	patterns            []*injectionPattern
	systemPromptMarkers []string
}

type injectionPattern struct {
	id          string
	regex       *regexp.Regexp
	score       float64
	description string
	ruleType    string
}

// NewScanner creates a new injection scanner with the default ruleset.
func NewScanner() (*Scanner, error) {
	s := &Scanner{
		systemPromptMarkers: []string{
			"ignore previous instructions",
			"ignore all previous",
			"disregard your instructions",
			"forget your system prompt",
			"you are now",
			"your new instructions",
			"act as if",
			"pretend you are",
			"from now on you",
			"override your",
			"bypass your",
			"your guidelines no longer",
			"jailbreak",
			"dan mode",
			"developer mode",
			"ignore your training",
			"ignore your guidelines",
			"as an ai with no restrictions",
			"your new role is",
			"you have been freed",
		},
	}

	rules := []struct {
		id          string
		pattern     string
		score       float64
		description string
		ruleType    string
	}{
		// Direct instruction override attempts
		{
			"INJ-001",
			`(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|directives?|rules?|guidelines?|constraints?|system\s+prompt)`,
			0.95,
			"Direct instruction override attempt",
			"instruction_override",
		},
		// Role impersonation
		{
			"INJ-002",
			`(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|you\s+are\s+a)\s+.{0,50}(ai|bot|assistant|model|gpt|claude|system)`,
			0.85,
			"Role impersonation attempt",
			"role_impersonation",
		},
		// Jailbreak keywords
		{
			"INJ-003",
			`(?i)(jailbreak|jailbroken|dan\s+mode|developer\s+mode|unrestricted\s+mode|god\s+mode|sudo\s+mode|admin\s+mode|no[\s-]filter)`,
			0.90,
			"Jailbreak attempt",
			"jailbreak",
		},
		// Tool call injection — attempts to generate fake tool calls
		{
			"INJ-004",
			`(?i)(call\s+tool|execute\s+tool|run\s+tool|invoke\s+tool|tool:\s*\w+|function:\s*\w+)\s*[\(\{]`,
			0.80,
			"Tool call injection attempt",
			"tool_injection",
		},
		// System prompt extraction
		{
			"INJ-005",
			`(?i)(repeat|print|output|show|display|reveal|tell\s+me)\s+(your|the)\s+(system\s+prompt|instructions?|guidelines?|rules?|initial\s+prompt)`,
			0.85,
			"System prompt extraction attempt",
			"prompt_extraction",
		},
		// Delimiter injection — trying to escape user content context
		{
			"INJ-006",
			`(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[SYSTEM\]|\[USER\]|\[ASSISTANT\])`,
			0.90,
			"Prompt delimiter injection",
			"delimiter_injection",
		},
		// URL-based payload delivery in instructions
		{
			"INJ-007",
			`(?i)(navigate\s+to|go\s+to|visit|open)\s+.{0,20}(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.|localhost|0\.0\.0\.0|metadata\.google|169\.254\.169\.254)`,
			0.95,
			"SSRF attempt via instruction",
			"ssrf_injection",
		},
		// Exfiltration via URL construction
		{
			"INJ-008",
			`(?i)(send|post|submit|upload|exfiltrate|leak)\s+.{0,50}(to|at)\s+(https?://|ftp://)`,
			0.75,
			"Data exfiltration attempt",
			"exfiltration",
		},
		// Hidden instruction via whitespace/unicode tricks
		{
			"INJ-009",
			`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{00AD}]{3,}`,
			0.85,
			"Hidden text via zero-width characters",
			"unicode_obfuscation",
		},
		// Code execution attempts
		{
			"INJ-010",
			`(?i)(execute|run|eval|exec)\s+(this|the\s+following)?\s*(code|script|command|shell|bash|python|javascript)`,
			0.80,
			"Code execution injection attempt",
			"code_execution",
		},
		// Fake completion signals
		{
			"INJ-011",
			`(?i)(task\s+completed|action\s+taken|i\s+have\s+(already|just)\s+(done|completed|executed|performed)|success(fully)?\s+(deleted|sent|purchased|submitted))`,
			0.70,
			"Fake completion signal",
			"fake_completion",
		},
		// Privilege escalation
		{
			"INJ-012",
			`(?i)(you\s+have\s+been\s+granted|your\s+permissions?\s+(have\s+been\s+)?(upgraded|elevated|changed)|admin\s+(access|mode|privileges?))`,
			0.85,
			"Privilege escalation attempt",
			"privilege_escalation",
		},
	}

	for _, r := range rules {
		re, err := regexp.Compile(r.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %s: %w", r.id, err)
		}
		s.patterns = append(s.patterns, &injectionPattern{
			id:          r.id,
			regex:       re,
			score:       r.score,
			description: r.description,
			ruleType:    r.ruleType,
		})
	}

	return s, nil
}

// Scan analyzes text for injection attempts and returns a DetectionResult.
// The input is user-supplied text before it enters any prompt template.
func (s *Scanner) Scan(ctx context.Context, text string) DetectionResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := DetectionResult{
		Action: ActionAllow,
	}

	// Layer 1: Pattern matching
	for _, pattern := range s.patterns {
		matches := pattern.regex.FindAllString(text, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				result.Triggers = append(result.Triggers, Trigger{
					RuleID:      pattern.id,
					RuleType:    pattern.ruleType,
					Description: pattern.description,
					Matched:     truncate(match, 100),
					Score:       pattern.score,
				})
			}
		}
	}

	// Layer 2: System prompt marker detection (case-insensitive substring)
	lowerText := strings.ToLower(text)
	for _, marker := range s.systemPromptMarkers {
		if strings.Contains(lowerText, marker) {
			result.Triggers = append(result.Triggers, Trigger{
				RuleID:      "MARKER-001",
				RuleType:    "system_prompt_marker",
				Description: "Known instruction override phrase",
				Matched:     truncate(marker, 100),
				Score:       0.85,
			})
		}
	}

	// Layer 3: Structural analysis
	structuralTriggers := s.analyzeStructure(text)
	result.Triggers = append(result.Triggers, structuralTriggers...)

	// Layer 4: Unicode obfuscation detection
	if hasUnicodeObfuscation(text) {
		result.Triggers = append(result.Triggers, Trigger{
			RuleID:      "UNICODE-001",
			RuleType:    "unicode_obfuscation",
			Description: "Suspicious Unicode character usage",
			Score:       0.75,
		})
	}

	// Calculate composite score
	result.Score = compositeScore(result.Triggers)
	result.Confidence = confidence(result.Triggers)
	result.Detected = result.Score > 0.3

	// Determine action
	switch {
	case result.Score >= 0.85:
		result.Action = ActionBlock
	case result.Score >= 0.5:
		result.Action = ActionReview
	default:
		result.Action = ActionAllow
	}

	return result
}

// ScanWebContent scans content extracted from a webpage.
// Web content gets a slightly different ruleset because legitimate pages
// may contain words like "ignore" or "instructions" in normal context.
func (s *Scanner) ScanWebContent(ctx context.Context, text string) DetectionResult {
	// Apply more conservative thresholds for web content
	// (more false positives acceptable to prevent injection via webpage)
	result := s.Scan(ctx, text)
	// Lower action thresholds for untrusted web content
	if result.Score >= 0.5 {
		result.Action = ActionBlock
	} else if result.Score >= 0.3 {
		result.Action = ActionReview
	}
	return result
}

// analyzeStructure detects injection via structural patterns:
// - Unusual instruction density (many imperative verbs)
// - Role-playing setup patterns
// - Prompt boundary simulation
func (s *Scanner) analyzeStructure(text string) []Trigger {
	var triggers []Trigger

	lines := strings.Split(text, "\n")

	// Check for instruction-heavy content
	imperativeCount := 0
	imperativeVerbs := []string{"ignore", "disregard", "forget", "pretend", "act", "behave", "respond", "output", "print", "say", "tell", "write", "generate", "produce"}
	words := strings.Fields(strings.ToLower(text))
	for _, word := range words {
		word = strings.TrimFunc(word, func(r rune) bool {
			return !unicode.IsLetter(r)
		})
		for _, verb := range imperativeVerbs {
			if word == verb {
				imperativeCount++
				break
			}
		}
	}

	if len(words) > 20 && float64(imperativeCount)/float64(len(words)) > 0.1 {
		triggers = append(triggers, Trigger{
			RuleID:      "STRUCT-001",
			RuleType:    "instruction_density",
			Description: "Unusually high density of imperative verbs",
			Score:       0.60,
		})
	}

	// Check for simulated system/user turns
	turnSimulation := regexp.MustCompile(`(?i)^(system|user|assistant|human|ai):\s+`)
	simulatedTurns := 0
	for _, line := range lines {
		if turnSimulation.MatchString(line) {
			simulatedTurns++
		}
	}
	if simulatedTurns >= 2 {
		triggers = append(triggers, Trigger{
			RuleID:      "STRUCT-002",
			RuleType:    "turn_simulation",
			Description: "Simulated conversation turn structure",
			Score:       0.75,
		})
	}

	// Check for base64 encoded payloads
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	if base64Pattern.MatchString(text) {
		triggers = append(triggers, Trigger{
			RuleID:      "STRUCT-003",
			RuleType:    "encoded_payload",
			Description: "Possible base64-encoded payload",
			Score:       0.50,
		})
	}

	return triggers
}

// hasUnicodeObfuscation detects invisible characters used to hide injection content.
func hasUnicodeObfuscation(text string) bool {
	invisibleCount := 0
	for _, r := range text {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E':
			invisibleCount++
		}
	}
	return invisibleCount >= 3
}

// compositeScore computes a composite risk score from all triggers.
// Uses max with diminishing contribution from lower scores to
// avoid false positive amplification.
func compositeScore(triggers []Trigger) float64 {
	if len(triggers) == 0 {
		return 0
	}

	// Sort triggers by score descending (inline max-finding)
	maxScore := 0.0
	sumOthers := 0.0
	for _, t := range triggers {
		if t.Score > maxScore {
			sumOthers += maxScore
			maxScore = t.Score
		} else {
			sumOthers += t.Score
		}
	}

	// Primary score is the highest individual trigger
	// Plus diminishing contribution from others (they confirm suspicion)
	otherContribution := 0.0
	if len(triggers) > 1 {
		otherContribution = math.Log(1+sumOthers) * 0.05
	}

	score := math.Min(1.0, maxScore+otherContribution)
	return score
}

// confidence returns a confidence level (0-1) based on trigger count and score agreement.
func confidence(triggers []Trigger) float64 {
	if len(triggers) == 0 {
		return 0
	}
	if len(triggers) == 1 {
		return 0.70
	}
	if len(triggers) >= 3 {
		return 0.95
	}
	return 0.85
}

// SanitizeForPrompt removes or neutralizes content that should not enter LLM prompts.
// This is a defense-in-depth measure — primary defense is structural prompt isolation.
func SanitizeForPrompt(text string) string {
	// Remove zero-width characters
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E':
			// drop
		default:
			b.WriteRune(r)
		}
	}
	clean := b.String()

	// Escape special template delimiters that could break prompt structure
	clean = strings.ReplaceAll(clean, "{{", "{ {")
	clean = strings.ReplaceAll(clean, "}}", "} }")

	// Limit length to prevent token exhaustion attacks
	const maxLength = 10000
	runes := []rune(clean)
	if len(runes) > maxLength {
		runes = runes[:maxLength]
		clean = string(runes) + "\n[content truncated]"
	}

	return clean
}

// AddRuleFromJSON adds a custom injection rule from JSON definition.
// Used to update rules from the compliance system at runtime.
func (s *Scanner) AddRuleFromJSON(ruleJSON []byte) error {
	var rule struct {
		ID          string  `json:"id"`
		Pattern     string  `json:"pattern"`
		Score       float64 `json:"score"`
		Description string  `json:"description"`
		RuleType    string  `json:"rule_type"`
	}
	if err := json.Unmarshal(ruleJSON, &rule); err != nil {
		return fmt.Errorf("parse rule: %w", err)
	}

	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("compile pattern: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.patterns = append(s.patterns, &injectionPattern{
		id:          rule.ID,
		regex:       re,
		score:       rule.Score,
		description: rule.Description,
		ruleType:    rule.RuleType,
	})

	return nil
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
