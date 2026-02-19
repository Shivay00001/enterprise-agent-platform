package compliance

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/enterprise/agent-platform/internal/ratelimit"
	"github.com/enterprise/agent-platform/pkg/logger"
)

// Decision is the compliance check outcome.
type Decision struct {
	Allowed  bool
	Reason   string
	WaitTime time.Duration // if rate limited, how long to wait
}

// Engine enforces compliance rules: robots.txt, domain blocks, rate limits, IP blocks.
type Engine struct {
	robotsCache       sync.Map // map[string]*robotsEntry
	limiter           *ratelimit.Limiter
	blockedDomains    map[string]bool
	blockedCIDRs      []*net.IPNet
	allowedDomains    map[string]bool // empty = all allowed
	userAgent         string
	robotsCacheTTL    time.Duration
	defaultCrawlDelay time.Duration
	maxReqsPerDomain  int
	log               *logger.Logger
	httpClient        *http.Client
}

type robotsEntry struct {
	rules     *robotsRules
	fetchedAt time.Time
	ttl       time.Duration
}

func (e *robotsEntry) expired() bool {
	return time.Since(e.fetchedAt) > e.ttl
}

type robotsRules struct {
	disallowed []string
	allowed    []string
	crawlDelay time.Duration
	sitemap    []string
}

type domainRateLimiter struct {
	mu          sync.Mutex
	requests    []time.Time
	maxPerMin   int
	crawlDelay  time.Duration
	lastRequest time.Time
}

// Config configures the compliance engine.
type Config struct {
	UserAgent         string
	RobotsCacheTTL    time.Duration
	DefaultCrawlDelay time.Duration
	MaxReqsPerDomain  int
	BlockedDomains    []string
	BlockedIPRanges   []string
	AllowedDomains    []string // empty = no domain allowlist
}

// NewEngine creates a new compliance engine.
func NewEngine(cfg Config, limiter *ratelimit.Limiter, log *logger.Logger) (*Engine, error) {
	e := &Engine{
		userAgent:         cfg.UserAgent,
		robotsCacheTTL:    cfg.RobotsCacheTTL,
		defaultCrawlDelay: cfg.DefaultCrawlDelay,
		maxReqsPerDomain:  cfg.MaxReqsPerDomain,
		blockedDomains:    make(map[string]bool),
		allowedDomains:    make(map[string]bool),
		limiter:           limiter,
		log:               log,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, d := range cfg.BlockedDomains {
		e.blockedDomains[strings.ToLower(d)] = true
	}
	for _, d := range cfg.AllowedDomains {
		e.allowedDomains[strings.ToLower(d)] = true
	}

	for _, cidr := range cfg.BlockedIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse blocked CIDR %q: %w", cidr, err)
		}
		e.blockedCIDRs = append(e.blockedCIDRs, network)
	}

	return e, nil
}

// CheckURL performs all compliance checks for a URL before navigation.
// Returns a Decision indicating whether access is allowed.
func (e *Engine) CheckURL(ctx context.Context, rawURL string) (*Decision, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &Decision{Allowed: false, Reason: "invalid URL: " + err.Error()}, nil
	}

	// ─── Protocol check ───────────────────────────────────────────────────────
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &Decision{Allowed: false, Reason: fmt.Sprintf("protocol %q not allowed (only http/https)", parsed.Scheme)}, nil
	}

	hostname := strings.ToLower(parsed.Hostname())

	// ─── Domain allowlist ─────────────────────────────────────────────────────
	if len(e.allowedDomains) > 0 {
		if !e.isDomainAllowed(hostname) {
			return &Decision{Allowed: false, Reason: "domain not in allowlist"}, nil
		}
	}

	// ─── Domain blocklist ─────────────────────────────────────────────────────
	if e.isDomainBlocked(hostname) {
		return &Decision{Allowed: false, Reason: "domain is blocked"}, nil
	}

	// ─── IP resolution and SSRF protection ───────────────────────────────────
	if decision, err := e.checkIPAddresses(ctx, hostname); err != nil || !decision.Allowed {
		if err != nil {
			return &Decision{Allowed: false, Reason: "DNS resolution failed: " + err.Error()}, nil
		}
		return decision, nil
	}

	// ─── Robots.txt compliance ────────────────────────────────────────────────
	rules, err := e.fetchRobots(ctx, parsed.Scheme+"://"+parsed.Host)
	if err != nil {
		e.log.Warn("failed to fetch robots.txt, allowing with caution",
			logger.Str("host", parsed.Host),
			logger.Err(err))
		// Allow but note the failure; we err on the side of caution
		// but don't block because robots.txt may genuinely not exist
	} else if rules != nil {
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		if !e.isPathAllowed(rules, path) {
			return &Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("path %q is disallowed by robots.txt for this site", path),
			}, nil
		}
	}

	// ─── Rate limiting ────────────────────────────────────────────────────────
	if e.limiter != nil {
		result, err := e.limiter.AllowDomain(ctx, hostname, e.maxReqsPerDomain, time.Minute)
		if err == nil && !result.Allowed {
			return &Decision{
				Allowed:  false,
				Reason:   fmt.Sprintf("rate limit: must wait %v before next request to %s", result.RetryAfter, hostname),
				WaitTime: result.RetryAfter,
			}, nil
		}
	}

	return &Decision{Allowed: true}, nil
}

// ─── IP Check / SSRF Prevention ──────────────────────────────────────────────

func (e *Engine) checkIPAddresses(ctx context.Context, hostname string) (*Decision, error) {
	// Reject raw IP addresses that look private
	if ip := net.ParseIP(hostname); ip != nil {
		if e.isPrivateIP(ip) {
			return &Decision{Allowed: false, Reason: "direct private IP access blocked (SSRF protection)"}, nil
		}
		return &Decision{Allowed: true}, nil
	}

	// Resolve hostname and check all returned IPs
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup: %w", err)
	}

	for _, addr := range ips {
		if e.isPrivateIP(addr.IP) {
			return &Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("hostname %s resolves to private IP %s (SSRF protection)", hostname, addr.IP),
			}, nil
		}
		for _, network := range e.blockedCIDRs {
			if network.Contains(addr.IP) {
				return &Decision{
					Allowed: false,
					Reason:  fmt.Sprintf("IP %s is in blocked range %s", addr.IP, network),
				}, nil
			}
		}
	}

	return &Decision{Allowed: true}, nil
}

func (e *Engine) isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// ─── Domain Checks ───────────────────────────────────────────────────────────

func (e *Engine) isDomainBlocked(hostname string) bool {
	// Exact match
	if e.blockedDomains[hostname] {
		return true
	}
	// Check parent domains
	parts := strings.Split(hostname, ".")
	for i := range parts {
		parent := strings.Join(parts[i:], ".")
		if e.blockedDomains[parent] {
			return true
		}
	}
	return false
}

func (e *Engine) isDomainAllowed(hostname string) bool {
	if len(e.allowedDomains) == 0 {
		return true
	}
	if e.allowedDomains[hostname] {
		return true
	}
	parts := strings.Split(hostname, ".")
	for i := range parts {
		parent := strings.Join(parts[i:], ".")
		if e.allowedDomains[parent] {
			return true
		}
	}
	return false
}

// ─── Robots.txt ──────────────────────────────────────────────────────────────

func (e *Engine) fetchRobots(ctx context.Context, baseURL string) (*robotsRules, error) {
	cacheKey := baseURL

	if v, ok := e.robotsCache.Load(cacheKey); ok {
		entry := v.(*robotsEntry)
		if !entry.expired() {
			return entry.rules, nil
		}
	}

	robotsURL := baseURL + "/robots.txt"
	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", e.userAgent)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No robots.txt = allow all
		entry := &robotsEntry{rules: nil, fetchedAt: time.Now(), ttl: e.robotsCacheTTL}
		e.robotsCache.Store(cacheKey, entry)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt returned %d", resp.StatusCode)
	}

	rules, err := parseRobots(resp.Body, e.userAgent)
	if err != nil {
		return nil, fmt.Errorf("parse robots.txt: %w", err)
	}

	entry := &robotsEntry{rules: rules, fetchedAt: time.Now(), ttl: e.robotsCacheTTL}
	e.robotsCache.Store(cacheKey, entry)

	return rules, nil
}

// parseRobots parses robots.txt and returns rules applicable to our user agent.
func parseRobots(body io.Reader, userAgent string) (*robotsRules, error) {
	rules := &robotsRules{}
	scanner := bufio.NewScanner(io.LimitReader(body, 1<<16)) // 64KB limit

	// Determine which user-agent block applies to us
	// We look for our specific agent name, then "*"
	type block struct {
		agents     []string
		disallowed []string
		allowed    []string
		crawlDelay time.Duration
	}

	var blocks []block
	var currentBlock *block

	uaLower := strings.ToLower(userAgent)
	// Extract our bot name (first word before slash or space)
	ourBotName := strings.ToLower(strings.Split(strings.Split(userAgent, "/")[0], " ")[0])

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first colon
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		// Remove inline comments
		if i := strings.Index(value, "#"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}

		switch field {
		case "user-agent":
			if currentBlock != nil {
				blocks = append(blocks, *currentBlock)
			}
			currentBlock = &block{agents: []string{strings.ToLower(value)}}
		case "disallow":
			if currentBlock != nil && value != "" {
				currentBlock.disallowed = append(currentBlock.disallowed, value)
			}
		case "allow":
			if currentBlock != nil && value != "" {
				currentBlock.allowed = append(currentBlock.allowed, value)
			}
		case "crawl-delay":
			if currentBlock != nil {
				var secs float64
				fmt.Sscanf(value, "%f", &secs)
				currentBlock.crawlDelay = time.Duration(secs * float64(time.Second))
			}
		case "sitemap":
			rules.sitemap = append(rules.sitemap, value)
		}
	}

	if currentBlock != nil {
		blocks = append(blocks, *currentBlock)
	}

	// Find the most specific matching block
	var matchedBlock *block
	for i := range blocks {
		b := &blocks[i]
		for _, agent := range b.agents {
			if agent == "*" {
				if matchedBlock == nil {
					matchedBlock = b
				}
			} else if strings.Contains(uaLower, agent) || strings.Contains(agent, ourBotName) {
				matchedBlock = b // specific match wins
				goto found
			}
		}
	}
found:

	if matchedBlock != nil {
		rules.disallowed = matchedBlock.disallowed
		rules.allowed = matchedBlock.allowed
		rules.crawlDelay = matchedBlock.crawlDelay
	}

	return rules, nil
}

// isPathAllowed checks whether a path is allowed under the robots rules.
// Implements the standard longest-match-wins algorithm.
func (e *Engine) isPathAllowed(rules *robotsRules, path string) bool {
	// Find the longest matching rule
	bestMatchLen := -1
	bestMatchAllow := true // default: allow

	for _, d := range rules.disallowed {
		if pathMatches(path, d) && len(d) > bestMatchLen {
			bestMatchLen = len(d)
			bestMatchAllow = false
		}
	}
	for _, a := range rules.allowed {
		if pathMatches(path, a) && len(a) > bestMatchLen {
			bestMatchLen = len(a)
			bestMatchAllow = true
		}
	}

	return bestMatchAllow
}

func pathMatches(path, pattern string) bool {
	// Handle $ anchor
	if strings.HasSuffix(pattern, "$") {
		return path == strings.TrimSuffix(pattern, "$")
	}
	// Handle * wildcard (simple prefix matching for now)
	if idx := strings.Index(pattern, "*"); idx >= 0 {
		prefix := pattern[:idx]
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, pattern)
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

// Note: Rate limiting is now handled by internal/ratelimit.
// getRateLimiter, checkRateLimit, and recordRequest have been removed.

// ─── URL Sanitization ─────────────────────────────────────────────────────────

// SanitizeURL normalizes a URL and returns error if it's malformed or dangerous.
func SanitizeURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http/https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	// Remove credentials from URL
	parsed.User = nil

	// Remove fragment (not needed for scraping, can expose internal IDs)
	parsed.Fragment = ""

	return parsed.String(), nil
}
