package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const rateLimitTTLSeconds = 120

// rateLimitScript atomically increments the per-minute subject counter and ensures
// a bounded 120-second TTL so rate-limit keys never leak in Redis.
var rateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 or redis.call("TTL", KEYS[1]) < 0 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`)

func newRedisClient(addr string) *redis.Client {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, "redis://") || strings.HasPrefix(addr, "rediss://") {
		opts, err := redis.ParseURL(addr)
		if err != nil {
			slog.Warn("invalid REDIS_ADDR url, disabling redis rate limiter", "err", err)
			return nil
		}
		opts.DialTimeout = 500 * time.Millisecond
		opts.ReadTimeout = 300 * time.Millisecond
		opts.WriteTimeout = 300 * time.Millisecond
		if opts.PoolSize == 0 {
			opts.PoolSize = 16
		}
		return redis.NewClient(opts)
	}
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  500 * time.Millisecond,
		ReadTimeout:  300 * time.Millisecond,
		WriteTimeout: 300 * time.Millisecond,
		PoolSize:     16,
	})
}

// limited reports whether this subject exceeded the per-minute Redis counter.
// An unconfigured or unreachable Redis fails open.
func (g *gateway) limited(ctx context.Context, subject string) bool {
	if g == nil || subject == "" {
		return false
	}
	if g.rateLimitCheck != nil {
		return g.rateLimitCheck(ctx, subject)
	}
	if g.rdb == nil {
		return false
	}
	rlCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	key := "secflow:rl:" + subject + ":" + time.Now().UTC().Format("200601021504")
	n, err := rateLimitScript.Run(rlCtx, g.rdb, []string{key}, rateLimitTTLSeconds).Int()
	if err != nil {
		slog.Warn("redis rate limit check failed", "err", err)
		return false
	}
	limit := 120
	if raw := os.Getenv("RATE_LIMIT_PER_MINUTE"); raw != "" {
		if v, parseErr := strconv.Atoi(raw); parseErr == nil && v > 0 {
			limit = v
		}
	}
	return n > limit
}
