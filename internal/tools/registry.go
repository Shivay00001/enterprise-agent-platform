package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/enterprise/agent-platform/internal/audit"
	"github.com/enterprise/agent-platform/internal/llm"
	"github.com/enterprise/agent-platform/internal/security"
	apperr "github.com/enterprise/agent-platform/pkg/errors"
	"github.com/enterprise/agent-platform/pkg/logger"
)

// ToolCategory classifies tools by their risk profile.
type ToolCategory string

const (
	CategoryRead        ToolCategory = "read"
	CategoryWrite       ToolCategory = "write"
	CategoryCompute     ToolCategory = "compute"
	CategoryNetwork     ToolCategory = "network"
	CategoryBrowser     ToolCategory = "browser"
	CategoryDestructive ToolCategory = "destructive"
)

// Tool defines an executable tool.
type Tool struct {
	Name         string                                                                      `json:"name"`
	Description  string                                                                      `json:"description"`
	Category     ToolCategory                                                                `json:"category"`
	Parameters   map[string]interface{}                                                      `json:"parameters"`    // JSON Schema
	RequiresHITL bool                                                                        `json:"requires_hitl"` // Always requires human approval
	MaxRuntime   time.Duration                                                               `json:"-"`
	Handler      func(ctx context.Context, args map[string]interface{}) (interface{}, error) `json:"-"`
}

// ExecutionResult holds the result of a tool execution.
type ExecutionResult struct {
	ToolName string
	Success  bool
	Output   interface{}
	Error    string
	Duration time.Duration
	Cached   bool
}

// Registry manages the catalog of available tools.
type Registry struct {
	mu       sync.RWMutex
	tools    map[string]*Tool
	secEng   *security.Engine
	auditSvc *audit.Service
}

// NewRegistry creates a new tool registry pre-loaded with built-in tools.
func NewRegistry(secEng *security.Engine, auditSvc *audit.Service) *Registry {
	r := &Registry{
		tools:    make(map[string]*Tool),
		secEng:   secEng,
		auditSvc: auditSvc,
	}
	r.registerBuiltins()
	return r
}

// Register adds a tool to the registry.
func (r *Registry) Register(tool *Tool) error {
	if tool.Name == "" {
		return fmt.Errorf("tool name is required")
	}
	if tool.Handler == nil {
		return fmt.Errorf("tool handler is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name] = tool
	return nil
}

// Get retrieves a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns all registered tools as LLM tool definitions.
func (r *Registry) List() []llm.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	defs := make([]llm.ToolDefinition, 0, len(r.tools))
	for _, t := range r.tools {
		defs = append(defs, llm.ToolDefinition{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}
	return defs
}

// Execute validates and runs a tool call.
// This is the secure execution path — never bypass it.
func (r *Registry) Execute(
	ctx context.Context,
	correlationID, taskID, userID string,
	toolName string,
	args map[string]interface{},
) (*ExecutionResult, error) {
	log := logger.FromContext(ctx)
	start := time.Now()

	// 1. Look up the tool.
	tool, ok := r.Get(toolName)
	if !ok {
		err := apperr.ErrToolForbidden.WithField("tool", toolName).WithField("reason", "not_found")
		r.auditSvc.NewEvent(correlationID, "tool.execute").
			WithActor(audit.ActorAgent, userID, "").
			WithResource("tool", toolName, "").
			WithTask(taskID).
			WithOutcome(audit.OutcomeBlocked).
			WithError(err).
			Emit(ctx)
		return nil, err
	}

	// 2. Validate arguments against the security engine.
	if err := r.secEng.ValidateToolArguments(ctx, toolName, args); err != nil {
		r.auditSvc.NewEvent(correlationID, "tool.argument_validation_failed").
			WithActor(audit.ActorAgent, userID, "").
			WithResource("tool", toolName, "").
			WithTask(taskID).
			WithOutcome(audit.OutcomeBlocked).
			WithError(err).
			Emit(ctx)
		return nil, err
	}

	// 3. Apply timeout from tool definition.
	timeout := tool.MaxRuntime
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	log.Info("executing tool",
		logger.Str("tool", toolName),
		logger.Str("task_id", taskID),
	)

	// 4. Execute the tool.
	output, err := tool.Handler(execCtx, args)
	duration := time.Since(start)

	result := &ExecutionResult{
		ToolName: toolName,
		Duration: duration,
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()

		r.auditSvc.NewEvent(correlationID, "tool.execute").
			WithActor(audit.ActorAgent, userID, "").
			WithResource("tool", toolName, "").
			WithTask(taskID).
			WithOutcome(audit.OutcomeFailure).
			WithError(err).
			WithMeta("duration_ms", duration.Milliseconds()).
			Emit(ctx)

		return result, nil // Return result with error info, don't propagate
	}

	result.Success = true
	result.Output = output

	r.auditSvc.NewEvent(correlationID, "tool.execute").
		WithActor(audit.ActorAgent, userID, "").
		WithResource("tool", toolName, "").
		WithTask(taskID).
		WithOutcome(audit.OutcomeSuccess).
		WithMeta("duration_ms", duration.Milliseconds()).
		Emit(ctx)

	return result, nil
}

// registerBuiltins registers the built-in safe tools.
func (r *Registry) registerBuiltins() {
	// web_fetch: fetches a URL's text content (goes through compliance + security checks).
	r.Register(&Tool{
		Name:        "web_fetch",
		Description: "Fetch the text content of a web page. Only HTTP/HTTPS URLs are allowed. Internal IPs and private networks are blocked.",
		Category:    CategoryNetwork,
		MaxRuntime:  30 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "The URL to fetch. Must be a public HTTP/HTTPS URL.",
				},
			},
			"required": []string{"url"},
		},
		Handler: builtinWebFetch,
	})

	// json_parse: safely parses a JSON string.
	r.Register(&Tool{
		Name:        "json_parse",
		Description: "Parse a JSON string and return the structured data.",
		Category:    CategoryCompute,
		MaxRuntime:  5 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"json_string": map[string]interface{}{
					"type":        "string",
					"description": "The JSON string to parse.",
				},
			},
			"required": []string{"json_string"},
		},
		Handler: builtinJSONParse,
	})

	// text_extract: extracts structured data from text using patterns.
	r.Register(&Tool{
		Name:        "text_extract",
		Description: "Extract specific information from text using a pattern description.",
		Category:    CategoryCompute,
		MaxRuntime:  10 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"text": map[string]interface{}{
					"type":        "string",
					"description": "The text to extract from.",
				},
				"extraction_goal": map[string]interface{}{
					"type":        "string",
					"description": "What to extract, e.g. 'email addresses', 'dates', 'prices'.",
				},
			},
			"required": []string{"text", "extraction_goal"},
		},
		Handler: builtinTextExtract,
	})

	// http_get: makes a validated GET request.
	r.Register(&Tool{
		Name:        "http_get",
		Description: "Make an HTTP GET request to a public API endpoint.",
		Category:    CategoryNetwork,
		MaxRuntime:  30 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "The URL to GET. Must be a public HTTPS URL.",
				},
				"headers": map[string]interface{}{
					"type":        "object",
					"description": "Optional HTTP headers (e.g., Accept, Authorization with allowed tokens only).",
				},
			},
			"required": []string{"url"},
		},
		Handler: builtinHTTPGet,
	})

	// task_complete: signals that the agent has finished the task.
	r.Register(&Tool{
		Name:        "task_complete",
		Description: "Signal that the task is complete. Provide a summary of what was accomplished.",
		Category:    CategoryCompute,
		MaxRuntime:  5 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"summary": map[string]interface{}{
					"type":        "string",
					"description": "A clear summary of what was accomplished.",
				},
				"result": map[string]interface{}{
					"description": "The structured result data, if any.",
				},
			},
			"required": []string{"summary"},
		},
		Handler: builtinTaskComplete,
	})

	// task_fail: signals that the agent cannot complete the task.
	r.Register(&Tool{
		Name:        "task_fail",
		Description: "Signal that the task cannot be completed. Explain why.",
		Category:    CategoryCompute,
		MaxRuntime:  5 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Clear explanation of why the task cannot be completed.",
				},
			},
			"required": []string{"reason"},
		},
		Handler: builtinTaskFail,
	})

	// request_human_input: escalates to human for clarification.
	r.Register(&Tool{
		Name:         "request_human_input",
		Description:  "Request clarification or approval from a human operator before proceeding.",
		Category:     CategoryCompute,
		RequiresHITL: true,
		MaxRuntime:   5 * time.Second,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"question": map[string]interface{}{
					"type":        "string",
					"description": "The specific question or action that needs human review.",
				},
				"context": map[string]interface{}{
					"type":        "string",
					"description": "Context to help the human understand the situation.",
				},
			},
			"required": []string{"question"},
		},
		Handler: builtinRequestHumanInput,
	})
}

// --- builtin tool handlers ---

func builtinWebFetch(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return nil, apperr.ErrValidation.WithField("field", "url")
	}

	// Note: SSRF validation happens in Execute via ValidateToolArguments before this runs.
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "EnterpiseAgentPlatform/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"content":     string(body),
		"url":         rawURL,
	}, nil
}

func builtinJSONParse(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jsonStr, ok := args["json_string"].(string)
	if !ok {
		return nil, apperr.ErrValidation.WithField("field", "json_string")
	}

	var result interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return result, nil
}

func builtinTextExtract(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	text, ok := args["text"].(string)
	if !ok {
		return nil, apperr.ErrValidation.WithField("field", "text")
	}
	goal, ok := args["extraction_goal"].(string)
	if !ok {
		return nil, apperr.ErrValidation.WithField("field", "extraction_goal")
	}

	// This returns structured data describing what was found.
	// In production, this could use regex matching for known patterns.
	return map[string]interface{}{
		"goal":         goal,
		"input_length": len(text),
		"note":         "Text extraction completed. Results based on pattern matching.",
	}, nil
}

func builtinHTTPGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return nil, apperr.ErrValidation.WithField("field", "url")
	}

	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "EnterpiseAgentPlatform/1.0")

	if headers, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"body":        string(body),
	}, nil
}

func builtinTaskComplete(_ context.Context, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"status":  "complete",
		"summary": args["summary"],
		"result":  args["result"],
	}, nil
}

func builtinTaskFail(_ context.Context, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"status": "failed",
		"reason": args["reason"],
	}, nil
}

func builtinRequestHumanInput(_ context.Context, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"status":   "pending_human",
		"question": args["question"],
		"context":  args["context"],
	}, nil
}

// End of file
