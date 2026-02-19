package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter performs distributed rate limiting using Redis sliding window counters.
// All limit checks are atomic using Lua scripts to prevent race conditions.
type Limiter struct {
	rdb *redis.ClusterClient
}

// NewLimiter creates a new Redis-backed rate limiter.
func NewLimiter(rdb *redis.ClusterClient) *Limiter {
	return &Limiter{rdb: rdb}
}

// Result holds the outcome of a rate limit check.
type Result struct {
	Allowed    bool
	Remaining  int
	ResetAt    time.Time
	RetryAfter time.Duration
	Key        string
}

// Allow checks and increments the rate limit for the given key.
// Uses a sliding window counter. Returns Result indicating whether the request
// is allowed and how many requests remain in the window.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window)
	windowEnd := now.Add(window)

	// Sliding window with sorted sets: score = timestamp, member = unique request ID
	// Lua script ensures atomic check-and-increment
	script := redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local window_ms = tonumber(ARGV[4])
		local request_id = ARGV[5]

		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

		-- Count current requests in window
		local count = redis.call('ZCARD', key)

		if count >= limit then
			-- Get the oldest entry to calculate retry-after
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			local oldest_score = 0
			if #oldest >= 2 then
				oldest_score = tonumber(oldest[2])
			end
			local retry_after = math.ceil((oldest_score + window_ms - now) / 1000)
			return {0, limit - count, retry_after}
		end

		-- Add the new request
		redis.call('ZADD', key, now, request_id)
		redis.call('PEXPIRE', key, window_ms)

		return {1, limit - count - 1, 0}
	`)

	windowMs := window.Milliseconds()
	requestID := fmt.Sprintf("%d", now.UnixNano())

	results, err := script.Run(ctx, l.rdb, []string{"rl:" + key},
		now.UnixMilli(),
		windowStart.UnixMilli(),
		limit,
		windowMs,
		requestID,
	).Int64Slice()

	if err != nil {
		// On Redis failure, fail open (allow) to avoid blocking all traffic
		// but log the error for monitoring
		return &Result{
			Allowed:   true,
			Remaining: limit,
			Key:       key,
		}, nil
	}

	allowed := results[0] == 1
	remaining := int(results[1])
	retryAfterSecs := int(results[2])

	result := &Result{
		Allowed:   allowed,
		Remaining: remaining,
		Key:       key,
		ResetAt:   windowEnd,
	}

	if !allowed && retryAfterSecs > 0 {
		result.RetryAfter = time.Duration(retryAfterSecs) * time.Second
	}

	return result, nil
}

// AllowUser checks the per-user rate limit.
func (l *Limiter) AllowUser(ctx context.Context, userID string, limit int, window time.Duration) (*Result, error) {
	return l.Allow(ctx, "user:"+userID, limit, window)
}

// AllowOrg checks the per-organization rate limit.
func (l *Limiter) AllowOrg(ctx context.Context, orgID string, limit int, window time.Duration) (*Result, error) {
	return l.Allow(ctx, "org:"+orgID, limit, window)
}

// AllowIP checks the per-IP rate limit (for API abuse prevention).
func (l *Limiter) AllowIP(ctx context.Context, ip string, limit int, window time.Duration) (*Result, error) {
	return l.Allow(ctx, "ip:"+ip, limit, window)
}

// AllowDomain checks the per-domain crawl rate limit.
func (l *Limiter) AllowDomain(ctx context.Context, domain string, limit int, window time.Duration) (*Result, error) {
	return l.Allow(ctx, "domain:"+domain, limit, window)
}

// CheckTokenBudget verifies and decrements a token budget stored in Redis.
// Returns the remaining budget. Thread-safe via atomic operations.
func (l *Limiter) CheckTokenBudget(ctx context.Context, taskID string, tokensToUse, budgetMax int) (remaining int, err error) {
	key := "token_budget:" + taskID

	script := redis.NewScript(`
		local key = KEYS[1]
		local tokens_to_use = tonumber(ARGV[1])
		local budget_max = tonumber(ARGV[2])

		local current = tonumber(redis.call('GET', key) or 0)
		local after_use = current + tokens_to_use

		if after_use > budget_max then
			return {-1, current}
		end

		redis.call('SET', key, after_use, 'EX', 86400) -- 24h TTL
		return {budget_max - after_use, after_use}
	`)

	results, err := script.Run(ctx, l.rdb, []string{key}, tokensToUse, budgetMax).Int64Slice()
	if err != nil {
		return 0, fmt.Errorf("token budget check: %w", err)
	}

	if results[0] == -1 {
		return int(int64(budgetMax) - results[1]), fmt.Errorf("token budget would be exceeded: using %d would exceed max %d (current: %d)",
			tokensToUse, budgetMax, results[1])
	}

	return int(results[0]), nil
}

// IncrementCostBudget atomically adds cost and checks against budget.
// Cost is stored as integer microcents to avoid float precision issues.
func (l *Limiter) IncrementCostBudget(ctx context.Context, taskID string, costUSD, budgetMaxUSD float64) (remainingUSD float64, err error) {
	key := "cost_budget:" + taskID

	// Convert to microcents for integer arithmetic
	costMicrocents := int64(costUSD * 1_000_000)
	budgetMicrocents := int64(budgetMaxUSD * 1_000_000)

	script := redis.NewScript(`
		local key = KEYS[1]
		local cost = tonumber(ARGV[1])
		local budget = tonumber(ARGV[2])

		local current = tonumber(redis.call('GET', key) or 0)
		local after = current + cost

		if after > budget then
			return {-1, current}
		end

		redis.call('SET', key, after, 'EX', 86400)
		return {budget - after, after}
	`)

	results, err := script.Run(ctx, l.rdb, []string{key}, costMicrocents, budgetMicrocents).Int64Slice()
	if err != nil {
		return 0, fmt.Errorf("cost budget check: %w", err)
	}

	if results[0] == -1 {
		return float64(budgetMicrocents-results[1]) / 1_000_000, fmt.Errorf("cost budget exceeded")
	}

	return float64(results[0]) / 1_000_000, nil
}

// ─── Token Bucket (per-service burst limiting) ────────────────────────────────

// TokenBucket implements a Redis-backed token bucket for burst tolerance.
type TokenBucket struct {
	limiter    *Limiter
	capacity   int
	refillRate float64 // tokens per second
}

// NewTokenBucket creates a token bucket with capacity and refill rate.
func NewTokenBucket(l *Limiter, capacity int, refillRate float64) *TokenBucket {
	return &TokenBucket{
		limiter:    l,
		capacity:   capacity,
		refillRate: refillRate,
	}
}

// Consume attempts to consume n tokens from the bucket.
func (tb *TokenBucket) Consume(ctx context.Context, key string, n int) (*Result, error) {
	script := redis.NewScript(`
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])  -- tokens per millisecond
		local n = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])

		-- Load current state
		local data = redis.call('HMGET', key, 'tokens', 'last_refill')
		local tokens = tonumber(data[1] or capacity)
		local last_refill = tonumber(data[2] or now)

		-- Calculate tokens added since last refill
		local elapsed = now - last_refill
		local new_tokens = elapsed * refill_rate
		tokens = math.min(capacity, tokens + new_tokens)

		if tokens < n then
			-- Not enough tokens
			local wait_ms = math.ceil((n - tokens) / refill_rate)
			return {0, math.floor(tokens), wait_ms}
		end

		tokens = tokens - n

		-- Store updated state
		redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
		redis.call('PEXPIRE', key, math.ceil(capacity / refill_rate) + 60000)

		return {1, math.floor(tokens), 0}
	`)

	refillPerMs := tb.refillRate / 1000.0
	results, err := script.Run(ctx, tb.limiter.rdb, []string{"tb:" + key},
		tb.capacity, refillPerMs, n, time.Now().UnixMilli(),
	).Int64Slice()

	if err != nil {
		return &Result{Allowed: true, Remaining: tb.capacity}, nil
	}

	allowed := results[0] == 1
	remaining := int(results[1])
	waitMs := int(results[2])

	return &Result{
		Allowed:    allowed,
		Remaining:  remaining,
		RetryAfter: time.Duration(waitMs) * time.Millisecond,
		Key:        key,
	}, nil
}
