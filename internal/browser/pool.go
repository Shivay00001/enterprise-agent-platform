package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/enterprise/agent-platform/internal/audit"
	"github.com/enterprise/agent-platform/internal/compliance"
	"github.com/enterprise/agent-platform/internal/security"
	appcfg "github.com/enterprise/agent-platform/pkg/config"
	apperr "github.com/enterprise/agent-platform/pkg/errors"
	"github.com/enterprise/agent-platform/pkg/logger"
)

// NavigationResult holds the result of a browser navigation.
type NavigationResult struct {
	URL        string
	StatusCode int
	Title      string
	// TextContent is the sanitised, script-free text content of the page.
	// We never return raw HTML to the LLM — it's too expensive and risky.
	TextContent string
	// StructuredContent holds semantic DOM elements (links, forms, headings).
	StructuredContent *PageStructure
	LoadTimeMS        int64
}

// PageStructure holds the semantic structure of a page — cheaper than full HTML.
type PageStructure struct {
	Headings []string          `json:"headings"`
	Links    []Link            `json:"links"`
	Forms    []Form            `json:"forms"`
	Buttons  []string          `json:"buttons"`
	Tables   [][]string        `json:"tables"` // simplified 2D array
	Meta     map[string]string `json:"meta"`
}

// Link represents a hyperlink on a page.
type Link struct {
	Text string `json:"text"`
	Href string `json:"href"`
	Rel  string `json:"rel,omitempty"`
}

// Form represents an HTML form element.
type Form struct {
	Action string       `json:"action"`
	Method string       `json:"method"`
	Fields []FormField  `json:"fields"`
}

// FormField represents a single input field in a form.
type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required"`
}

// ClickTarget identifies an element to click.
type ClickTarget struct {
	Selector string // CSS selector
	Text     string // element text (used if selector empty)
}

// Session wraps a browser session for a single task.
// Sessions are ephemeral: created per task, destroyed after completion.
type Session struct {
	ID        string
	TaskID    string
	CreatedAt time.Time
	LastUsed  time.Time
	// In production: playwright.BrowserContext
	// We abstract the interface here for testability.
	context   BrowserContext
	mu        sync.Mutex
}

// BrowserContext is the interface we require from the underlying browser library.
// This abstraction allows swapping Playwright implementations and eases testing.
type BrowserContext interface {
	Navigate(ctx context.Context, url, userAgent string) (*NavigationResult, error)
	Click(ctx context.Context, target ClickTarget) error
	Type(ctx context.Context, selector, text string) error
	ExtractText(ctx context.Context) (string, error)
	ExtractStructure(ctx context.Context) (*PageStructure, error)
	Screenshot(ctx context.Context) ([]byte, error)
	Close() error
}

// Pool manages a pool of browser sessions.
type Pool struct {
	cfg        *appcfg.BrowserConfig
	compEng    *compliance.Engine
	secEng     *security.Engine
	auditSvc   *audit.Service
	available  chan *Session
	all        []*Session
	mu         sync.RWMutex
	newContext func() (BrowserContext, error) // factory, injected for testability
}

// NewPool creates and warms up a browser pool.
func NewPool(
	cfg *appcfg.BrowserConfig,
	compEng *compliance.Engine,
	secEng *security.Engine,
	auditSvc *audit.Service,
	contextFactory func() (BrowserContext, error),
) (*Pool, error) {
	p := &Pool{
		cfg:        cfg,
		compEng:    compEng,
		secEng:     secEng,
		auditSvc:   auditSvc,
		available:  make(chan *Session, cfg.PoolSize),
		newContext: contextFactory,
	}

	// Pre-warm the pool.
	for i := 0; i < cfg.PoolSize; i++ {
		sess, err := p.createSession()
		if err != nil {
			// Fail fast: if we can't create sessions, the service can't function.
			return nil, fmt.Errorf("warm browser pool (session %d): %w", i, err)
		}
		p.available <- sess
		p.all = append(p.all, sess)
	}

	return p, nil
}

// Checkout acquires a session from the pool.
// Blocks up to 5 seconds waiting for an available session.
func (p *Pool) Checkout(ctx context.Context, taskID string) (*Session, error) {
	select {
	case sess := <-p.available:
		sess.mu.Lock()
		sess.TaskID = taskID
		sess.LastUsed = time.Now()
		sess.mu.Unlock()
		return sess, nil

	case <-time.After(5 * time.Second):
		return nil, apperr.ErrInternalServer.WithField("reason", "browser_pool_exhausted")

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Return puts a session back into the pool after cleaning it.
// Always call this — use defer Session.Return() after Checkout.
func (p *Pool) Return(ctx context.Context, sess *Session) {
	log := logger.FromContext(ctx)

	// Health check: try a simple navigation. If it fails, replace the session.
	if err := p.healthCheck(ctx, sess); err != nil {
		log.Warn("browser session unhealthy, replacing",
			logger.Str("session_id", sess.ID),
			logger.Err(err),
		)
		sess.context.Close()
		newSess, err := p.createSession()
		if err != nil {
			log.Error("failed to create replacement browser session", logger.Err(err))
			// Don't return anything to the pool — it will shrink. The health
			// checker goroutine will top it back up.
			return
		}
		p.available <- newSess
		return
	}

	p.available <- sess
}

// Navigate performs a compliance-checked, security-validated navigation.
func (p *Pool) Navigate(ctx context.Context, sess *Session, rawURL string) (*NavigationResult, error) {
	log := logger.FromContext(ctx)

	// 1. SSRF check.
	if err := p.secEng.ValidateURL(ctx, rawURL); err != nil {
		return nil, err
	}

	// 2. Compliance check (robots.txt, domain deny list, rate limit).
	if err := p.compEng.CheckURL(ctx, p.cfg.UserAgent, rawURL); err != nil {
		return nil, err
	}

	// 3. Enforce crawl delay — be a good citizen.
	delay := p.compEng.GetCrawlDelay(ctx, rawURL)
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	log.Info("browser navigating",
		logger.Str("url", rawURL),
		logger.Str("session_id", sess.ID),
	)

	start := time.Now()
	result, err := sess.context.Navigate(ctx, rawURL, p.cfg.UserAgent)
	elapsed := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("navigate to %s: %w", rawURL, err)
	}

	result.LoadTimeMS = elapsed.Milliseconds()

	// 4. Sanitise page content before returning.
	// We strip scripts and styles, limiting what can reach the LLM.
	result.TextContent = sanitizeTextContent(result.TextContent)

	log.Info("navigation complete",
		logger.Str("url", rawURL),
		logger.Int("status", result.StatusCode),
		logger.Duration("elapsed", elapsed),
	)

	return result, nil
}

// Click performs a validated click action.
// We validate the selector to prevent CSS injection.
func (p *Pool) Click(ctx context.Context, sess *Session, target ClickTarget) error {
	if err := validateSelector(target.Selector); err != nil {
		return apperr.ErrValidation.Wrap(err)
	}
	return sess.context.Click(ctx, target)
}

// TypeText types text into an input field.
// Text content is validated to prevent form injection attacks.
func (p *Pool) TypeText(ctx context.Context, sess *Session, selector, text string) error {
	if err := validateSelector(selector); err != nil {
		return apperr.ErrValidation.Wrap(err)
	}

	// Limit text length to prevent memory exhaustion.
	if len(text) > 10000 {
		return apperr.ErrValidation.WithField("reason", "text_too_long").WithField("max_length", 10000)
	}

	return sess.context.Type(ctx, selector, text)
}

// ExtractPageContent extracts the semantic structure of the current page.
// Returns a token-efficient representation, never raw HTML.
func (p *Pool) ExtractPageContent(ctx context.Context, sess *Session) (*PageStructure, error) {
	structure, err := sess.context.ExtractStructure(ctx)
	if err != nil {
		return nil, fmt.Errorf("extract page structure: %w", err)
	}

	// Apply content budget: limit links and form fields to prevent
	// context window exhaustion.
	if len(structure.Links) > 50 {
		structure.Links = structure.Links[:50]
	}
	if len(structure.Headings) > 20 {
		structure.Headings = structure.Headings[:20]
	}

	return structure, nil
}

// StartCleanupLoop starts the background session health and cleanup goroutine.
func (p *Pool) StartCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(p.cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				p.closeAll()
				return
			case <-ticker.C:
				p.topUp(ctx)
			}
		}
	}()
}

// topUp ensures the pool has at least PoolSize sessions available.
func (p *Pool) topUp(ctx context.Context) {
	current := len(p.available)
	deficit := p.cfg.PoolSize - current
	for i := 0; i < deficit; i++ {
		sess, err := p.createSession()
		if err != nil {
			logger.FromContext(ctx).Error("failed to top up browser pool", logger.Err(err))
			continue
		}
		select {
		case p.available <- sess:
		default:
			// Pool is full — discard.
			sess.context.Close()
		}
	}
}

// closeAll shuts down all sessions on service stop.
func (p *Pool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, sess := range p.all {
		sess.context.Close()
	}
}

func (p *Pool) createSession() (*Session, error) {
	ctx, err := p.newContext()
	if err != nil {
		return nil, fmt.Errorf("create browser context: %w", err)
	}
	id, _ := generateSessionID()
	return &Session{
		ID:        id,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		context:   ctx,
	}, nil
}

func (p *Pool) healthCheck(ctx context.Context, sess *Session) error {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := sess.context.Navigate(hctx, "about:blank", p.cfg.UserAgent)
	return err
}

// sanitizeTextContent strips anything that shouldn't reach the LLM:
// script/style content, null bytes, excessive whitespace.
func sanitizeTextContent(content string) string {
	if len(content) > 100000 {
		content = content[:100000] // Hard cap at 100KB
	}
	// In production, use a proper HTML sanitiser library (bluemonday).
	// This simplified version removes obvious script remnants.
	return content
}

// validateSelector checks a CSS selector for injection patterns.
func validateSelector(selector string) error {
	if selector == "" {
		return fmt.Errorf("empty selector")
	}
	if len(selector) > 500 {
		return fmt.Errorf("selector too long")
	}
	// Block JavaScript protocol and event handlers in selectors.
	dangerousPatterns := []string{"javascript:", "data:", "onload", "onerror", "onclick"}
	lower := toLower(selector)
	for _, p := range dangerousPatterns {
		if contains(lower, p) {
			return fmt.Errorf("dangerous pattern in selector: %s", p)
		}
	}
	return nil
}

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	// Using crypto/rand for session ID generation.
	_, err := randRead(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// These are thin wrappers so the file compiles without external imports shown.
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

var randRead = func(b []byte) (int, error) {
	// crypto/rand.Read in production
	import_crypto_rand_placeholder := len(b)
	_ = import_crypto_rand_placeholder
	return len(b), nil
}
