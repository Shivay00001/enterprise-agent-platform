package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enterprise/agent-platform/pkg/logger"
)

// Provider identifiers
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	ProviderGoogle    = "google"
	ProviderLocal     = "local"
)

// ─── Circuit Breaker ─────────────────────────────────────────────────────────

type cbState int32

const (
	cbClosed   cbState = 0
	cbOpen     cbState = 1
	cbHalfOpen cbState = 2
)

type CircuitBreaker struct {
	name            string
	state           atomic.Int32
	failures        atomic.Int64
	successes       atomic.Int64
	lastFailureTime atomic.Int64 // unix nano
	threshold       int64        // failure count to trip
	resetTimeout    time.Duration
	halfOpenLimit   int64
	halfOpenCount   atomic.Int64
}

func newCircuitBreaker(name string, threshold int, resetTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:          name,
		threshold:     int64(threshold),
		resetTimeout:  resetTimeout,
		halfOpenLimit: 1,
	}
	cb.state.Store(int32(cbClosed))
	return cb
}

func (cb *CircuitBreaker) Allow() bool {
	state := cbState(cb.state.Load())
	switch state {
	case cbClosed:
		return true
	case cbOpen:
		// Check if reset timeout has elapsed
		lastFail := time.Unix(0, cb.lastFailureTime.Load())
		if time.Since(lastFail) >= cb.resetTimeout {
			// Transition to half-open
			if cb.state.CompareAndSwap(int32(cbOpen), int32(cbHalfOpen)) {
				cb.halfOpenCount.Store(0)
			}
			return true
		}
		return false
	case cbHalfOpen:
		count := cb.halfOpenCount.Add(1)
		return count <= cb.halfOpenLimit
	}
	return false
}

func (cb *CircuitBreaker) RecordSuccess() {
	state := cbState(cb.state.Load())
	if state == cbHalfOpen {
		// Transition back to closed
		cb.state.Store(int32(cbClosed))
		cb.failures.Store(0)
		cb.successes.Store(0)
	} else {
		cb.successes.Add(1)
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.failures.Add(1)
	cb.lastFailureTime.Store(time.Now().UnixNano())

	if cb.failures.Load() >= cb.threshold {
		cb.state.Store(int32(cbOpen))
	}
}

func (cb *CircuitBreaker) IsOpen() bool {
	return cbState(cb.state.Load()) == cbOpen
}

// ─── Provider Config ─────────────────────────────────────────────────────────

type ProviderConfig struct {
	Name        string
	APIKey      string
	BaseURL     string
	Model       string
	MaxTokens   int
	Temperature float64
	// Cost per 1M tokens (input/output)
	InputCostPer1M  float64
	OutputCostPer1M float64
	Timeout         time.Duration
}

// ─── Gateway ─────────────────────────────────────────────────────────────────

// Gateway is the LLM multi-provider router with circuit breakers and cost tracking.
type Gateway struct {
	providers      []*providerClient
	mu             sync.RWMutex
	totalTokensIn  atomic.Int64
	totalTokensOut atomic.Int64
	totalCostUSD   atomic.Int64 // stored as microcents to avoid float atomics
	log            *logger.Logger
	httpClient     *http.Client
	budgets        sync.Map // map[string]*TaskBudget
}

type providerClient struct {
	config ProviderConfig
	cb     *CircuitBreaker
}

// NewGateway creates a new LLM gateway with the given provider configurations.
// Providers are tried in order: first available non-open circuit breaker wins.
func NewGateway(configs []ProviderConfig, log *logger.Logger) *Gateway {
	g := &Gateway{
		log: log,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       100,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false,
			},
		},
	}

	for _, cfg := range configs {
		pc := &providerClient{
			config: cfg,
			cb:     newCircuitBreaker(cfg.Name, 3, 30*time.Second),
		}
		g.providers = append(g.providers, pc)
	}

	return g
}

// ─── Chat Completion ─────────────────────────────────────────────────────────

// Message definition is now in types.go

// CompletionRequest is the unified request format.
type CompletionRequest struct {
	SystemPrompt  string
	Messages      []Message
	MaxTokens     int
	Temperature   float64 // use 0 for deterministic
	StopSequences []string
	Tools         []ToolDefinition
	TaskID        string
	TaskType      string
}

// CompletionResponse is the unified response format.
type CompletionResponse struct {
	Content      string
	ToolCalls    []ToolCall
	InputTokens  int
	OutputTokens int
	CostUSD      float64
	Provider     string
	Model        string
	FinishReason string
}

// Complete sends a chat completion request to the first available provider.
// Falls back through the provider list if a provider is unavailable.
func (g *Gateway) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
	g.mu.RLock()
	providers := make([]*providerClient, len(g.providers))
	copy(providers, g.providers)
	g.mu.RUnlock()

	var lastErr error
	for _, pc := range providers {
		if !pc.cb.Allow() {
			g.log.Debug("circuit breaker open, skipping provider",
				logger.Str("provider", pc.config.Name))
			continue
		}

		resp, err := g.callProvider(ctx, pc, req)
		if err != nil {
			pc.cb.RecordFailure()
			lastErr = err
			g.log.Warn("provider call failed, trying next",
				logger.Str("provider", pc.config.Name),
				logger.Err(err))
			continue
		}

		pc.cb.RecordSuccess()
		g.trackCost(resp)

		g.log.Info("llm completion",
			logger.Str("provider", resp.Provider),
			logger.Str("model", resp.Model),
			logger.Int("input_tokens", resp.InputTokens),
			logger.Int("output_tokens", resp.OutputTokens),
			logger.Float64("cost_usd", resp.CostUSD),
		)

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed (tried %d): last error: %w", len(providers), lastErr)
	}
	return nil, fmt.Errorf("no providers available (all circuit breakers open)")
}

func (g *Gateway) callProvider(ctx context.Context, pc *providerClient, req *CompletionRequest) (*CompletionResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, pc.config.Timeout)
	defer cancel()

	switch pc.config.Name {
	case ProviderAnthropic:
		return g.callAnthropic(callCtx, pc, req)
	case ProviderOpenAI:
		return g.callOpenAI(callCtx, pc, req)
	case ProviderLocal:
		return g.callOllama(callCtx, pc, req)
	default:
		return nil, fmt.Errorf("unknown provider: %s", pc.config.Name)
	}
}

// ─── Anthropic ────────────────────────────────────────────────────────────────

type anthropicRequest struct {
	Model         string             `json:"model"`
	MaxTokens     int                `json:"max_tokens"`
	System        string             `json:"system,omitempty"`
	Messages      []anthropicMessage `json:"messages"`
	Temperature   float64            `json:"temperature"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (g *Gateway) callAnthropic(ctx context.Context, pc *providerClient, req *CompletionRequest) (*CompletionResponse, error) {
	msgs := make([]anthropicMessage, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = anthropicMessage{Role: m.Role, Content: m.Content}
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = pc.config.MaxTokens
	}

	body := anthropicRequest{
		Model:         pc.config.Model,
		MaxTokens:     maxTokens,
		System:        req.SystemPrompt,
		Messages:      msgs,
		Temperature:   req.Temperature,
		StopSequences: req.StopSequences,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		pc.config.BaseURL+"/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", pc.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer httpResp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error %d: %s", httpResp.StatusCode, string(respData[:min(200, len(respData))]))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respData, &ar); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	content := ""
	for _, c := range ar.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}

	inputCost := float64(ar.Usage.InputTokens) * pc.config.InputCostPer1M / 1_000_000
	outputCost := float64(ar.Usage.OutputTokens) * pc.config.OutputCostPer1M / 1_000_000

	return &CompletionResponse{
		Content:      content,
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
		CostUSD:      inputCost + outputCost,
		Provider:     ProviderAnthropic,
		Model:        ar.Model,
		FinishReason: ar.StopReason,
	}, nil
}

// ─── OpenAI ───────────────────────────────────────────────────────────────────

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature"`
	Stop        []string        `json:"stop,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message      openAIMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (g *Gateway) callOpenAI(ctx context.Context, pc *providerClient, req *CompletionRequest) (*CompletionResponse, error) {
	msgs := []openAIMessage{}
	if req.SystemPrompt != "" {
		msgs = append(msgs, openAIMessage{Role: "system", Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, openAIMessage{Role: m.Role, Content: m.Content})
	}

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = pc.config.MaxTokens
	}

	body := openAIRequest{
		Model:       pc.config.Model,
		Messages:    msgs,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		Stop:        req.StopSequences,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		pc.config.BaseURL+"/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+pc.config.APIKey)

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer httpResp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai error %d: %s", httpResp.StatusCode, string(respData[:min(200, len(respData))]))
	}

	var or openAIResponse
	if err := json.Unmarshal(respData, &or); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	content := ""
	if len(or.Choices) > 0 {
		content = or.Choices[0].Message.Content
	}

	inputCost := float64(or.Usage.PromptTokens) * pc.config.InputCostPer1M / 1_000_000
	outputCost := float64(or.Usage.CompletionTokens) * pc.config.OutputCostPer1M / 1_000_000

	return &CompletionResponse{
		Content:      content,
		InputTokens:  or.Usage.PromptTokens,
		OutputTokens: or.Usage.CompletionTokens,
		CostUSD:      inputCost + outputCost,
		Provider:     ProviderOpenAI,
		Model:        or.Model,
	}, nil
}

// ─── Local / Ollama ───────────────────────────────────────────────────────────

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  struct {
		Temperature float64 `json:"temperature"`
		NumPredict  int     `json:"num_predict"`
	} `json:"options"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Model           string        `json:"model"`
	Message         ollamaMessage `json:"message"`
	Done            bool          `json:"done"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
}

func (g *Gateway) callOllama(ctx context.Context, pc *providerClient, req *CompletionRequest) (*CompletionResponse, error) {
	msgs := []ollamaMessage{}
	if req.SystemPrompt != "" {
		msgs = append(msgs, ollamaMessage{Role: "system", Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, ollamaMessage{Role: m.Role, Content: m.Content})
	}

	body := ollamaRequest{
		Model:    pc.config.Model,
		Messages: msgs,
		Stream:   false,
	}
	body.Options.Temperature = req.Temperature
	body.Options.NumPredict = req.MaxTokens

	data, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		pc.config.BaseURL+"/api/chat", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respData, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))

	var or ollamaResponse
	if err := json.Unmarshal(respData, &or); err != nil {
		return nil, fmt.Errorf("unmarshal ollama: %w", err)
	}

	return &CompletionResponse{
		Content:      or.Message.Content,
		InputTokens:  or.PromptEvalCount,
		OutputTokens: or.EvalCount,
		CostUSD:      0, // local = no cost
		Provider:     ProviderLocal,
		Model:        or.Model,
	}, nil
}

// ─── Cost Tracking ────────────────────────────────────────────────────────────

func (g *Gateway) trackCost(resp *CompletionResponse) {
	g.totalTokensIn.Add(int64(resp.InputTokens))
	g.totalTokensOut.Add(int64(resp.OutputTokens))
	// Store as nanocents to avoid float64 atomic issues
	nanocents := int64(resp.CostUSD * 1e9)
	g.totalCostUSD.Add(nanocents)
}

// Stats returns aggregate usage statistics.
func (g *Gateway) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_input_tokens":  g.totalTokensIn.Load(),
		"total_output_tokens": g.totalTokensOut.Load(),
		"total_cost_usd":      float64(g.totalCostUSD.Load()) / 1e9,
	}
}

// ProviderStatus returns the health status of each provider.
func (g *Gateway) ProviderStatus() []map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	status := make([]map[string]interface{}, len(g.providers))
	for i, pc := range g.providers {
		status[i] = map[string]interface{}{
			"provider": pc.config.Name,
			"model":    pc.config.Model,
			"cb_open":  pc.cb.IsOpen(),
			"failures": pc.cb.failures.Load(),
		}
	}
	return status
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (g *Gateway) GetBudgetStatus(taskID string) *TaskBudget {
	v, ok := g.budgets.Load(taskID)
	if !ok {
		return &TaskBudget{TaskID: taskID} // return empty budget if not tracked
	}
	return v.(*TaskBudget)
}

func (g *Gateway) ReleaseBudget(taskID string) {
	g.budgets.Delete(taskID)
}
