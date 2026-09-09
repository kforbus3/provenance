// Package ratelimit provides a small, dependency-free per-key token-bucket
// limiter and HTTP middleware. It is used to throttle abusive clients by IP
// when the app is exposed to the internet — complementing per-account lockout,
// which it does not replace. Keys are resolved from the request's RemoteAddr,
// which chi's RealIP middleware populates from X-Forwarded-For when the app sits
// behind a trusted reverse proxy.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a per-key token bucket: each key refills at `rate` tokens/sec up to
// `burst`. Allow() consumes one token. Stale keys are pruned periodically.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

// New builds a limiter allowing perMinute requests per key with the given burst.
// A perMinute of 0 disables limiting (Allow always returns true).
func New(perMinute, burst int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMinute) / 60.0,
		burst:   float64(burst),
	}
	if perMinute > 0 {
		go l.cleanupLoop()
	}
	return l
}

// Enabled reports whether the limiter actually enforces a limit.
func (l *Limiter) Enabled() bool { return l.rate > 0 }

// Allow reports whether a request for key may proceed, consuming one token.
func (l *Limiter) Allow(key string) bool {
	if l.rate <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	// Refill based on elapsed time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		l.mu.Lock()
		for k, b := range l.buckets {
			if b.last.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// KeyFromRequest extracts the client IP (host portion) for rate-limit keying.
func KeyFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
