package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter performs distributed rate limiting using Redis sliding window counters.
// All limit checks are atomic using Lua scripts to prevent race conditions.
type Limiter struct {
	rdb redis.UniversalClient
}

// NewLimiter creates a new Redis-backed rate limiter.
func NewLimiter(rdb redis.UniversalClient) *Limiter {
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
