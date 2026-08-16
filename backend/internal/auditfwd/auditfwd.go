// Package auditfwd forwards Fleet's audit events to an external collector —
// syslog (RFC 5424 over UDP/TCP) or a generic HTTP JSON endpoint — so they can
// land in a SIEM. It is best-effort and never blocks the audit write: the store
// calls Forward in a goroutine for each appended event. The hash-chained copy
// in Postgres remains the system of record.
package auditfwd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/ssrf"
	"github.com/kforbus3/Moorgate/backend/internal/store"
)

const settingKey = "audit_forward"

// Retry-queue tuning. Forwarding is best-effort and off the request path, but a
// transient collector outage must NOT silently lose events: failed sends are retried
// with capped exponential backoff from a bounded queue, and only an overflowing queue
// (sustained outage) drops — always with a logged warning.
const (
	queueCapacity = 2048
	maxRetries    = 5
	baseBackoff   = 500 * time.Millisecond
	maxBackoff    = 30 * time.Second
)

// Config is the persisted forwarding configuration.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`     // syslog | http
	Address  string `json:"address"`  // host:port (syslog) or URL (http)
	Protocol string `json:"protocol"` // udp | tcp (syslog only)

	// TLS wraps a syslog target in TLS (RFC 5425, octet-counted framing). For http
	// targets use an https:// URL instead — the HTTP client handles TLS there.
	TLS bool `json:"tls,omitempty"`
	// InsecureSkipVerify disables certificate verification for a TLS syslog target
	// (self-signed collectors in a lab). Leave false in production.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// CACertPEM optionally trusts a specific CA (PEM) for a TLS syslog target, so a
	// private collector CA need not be installed system-wide.
	CACertPEM string `json:"caCertPem,omitempty"`
	// Token, when set, authenticates http forwards as "Authorization: Bearer <token>"
	// so a collector can reject unauthenticated posts.
	Token string `json:"token,omitempty"`
}

// Forwarder sends audit events to the configured sink.
type Forwarder struct {
	store    *store.Store
	log      *slog.Logger
	client   *http.Client
	hostname string

	mu       sync.Mutex
	cached   Config
	cachedAt time.Time
	cacheTTL time.Duration

	queue   chan models.AuditEvent
	dropped atomic.Uint64
}

func New(st *store.Store, log *slog.Logger) *Forwarder {
	host, _ := os.Hostname()
	if host == "" {
		host = "fleet-terminal"
	}
	f := &Forwarder{
		store: st, log: log, hostname: host,
		client:   ssrf.SafeClient(5 * time.Second),
		cacheTTL: 30 * time.Second,
		queue:    make(chan models.AuditEvent, queueCapacity),
	}
	// Single background worker: serializes retries/backoff so a slow collector can't
	// spawn unbounded goroutines. The queue bounds memory; overflow is logged, never
	// dropped silently.
	go f.worker()
	return f
}

// LoadConfig reads the stored config (zero value if unset).
func (f *Forwarder) LoadConfig(ctx context.Context) Config {
	var c Config
	if raw, err := f.store.GetSetting(ctx, settingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// validateTarget rejects SSRF destinations (metadata, loopback, and other
// disallowed ranges per the ssrf policy) for a forwarding config. Shared by the
// save path, the live send path, and the test button so the guard can't be
// bypassed by persisting a config that never went through SendTest.
func validateTarget(cfg Config) error {
	if strings.ToLower(cfg.Type) == "http" {
		return ssrf.ValidateURL(cfg.Address)
	}
	return ssrf.ValidateHostPort(cfg.Address)
}

// SaveConfig persists the config and refreshes the cache.
func (f *Forwarder) SaveConfig(ctx context.Context, c Config) error {
	// Validate the destination before it is persisted and starts receiving every
	// audit event; an empty address on a disabled config is allowed (clearing it).
	if c.Enabled && strings.TrimSpace(c.Address) != "" {
		if err := validateTarget(c); err != nil {
			return err
		}
	}
	if err := f.store.SetSetting(ctx, settingKey, c); err != nil {
		return err
	}
	f.mu.Lock()
	f.cached, f.cachedAt = c, time.Now()
	f.mu.Unlock()
	return nil
}

func (f *Forwarder) config() Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.cachedAt) < f.cacheTTL {
		return f.cached
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f.cached, f.cachedAt = f.LoadConfig(ctx), time.Now()
	return f.cached
}

// Forward enqueues one audit event for delivery if forwarding is enabled. It never
// blocks the caller (the store invokes it per appended event): the event is handed to
// a bounded retry queue drained by a background worker. A full queue (sustained
// collector outage) is the only drop, and it is logged — never silent.
func (f *Forwarder) Forward(e models.AuditEvent) {
	cfg := f.config()
	if !cfg.Enabled || strings.TrimSpace(cfg.Address) == "" {
		return
	}
	select {
	case f.queue <- e:
	default:
		n := f.dropped.Add(1)
		f.log.Warn("audit forward queue full; event NOT delivered to SIEM",
			"action", e.Action, "totalDropped", n, "queueCapacity", queueCapacity)
	}
}

// worker drains the retry queue, delivering each event with bounded retries.
func (f *Forwarder) worker() {
	for e := range f.queue {
		f.deliver(e)
	}
}

// deliver sends one event, retrying transient failures with capped exponential
// backoff. After the last attempt it logs and gives up rather than dropping silently.
func (f *Forwarder) deliver(e models.AuditEvent) {
	backoff := baseBackoff
	for attempt := 1; attempt <= maxRetries; attempt++ {
		cfg := f.config()
		if !cfg.Enabled || strings.TrimSpace(cfg.Address) == "" {
			return // disabled/cleared while queued: stop trying
		}
		err := f.send(cfg, e)
		if err == nil {
			return
		}
		if attempt == maxRetries {
			f.log.Error("audit forward giving up after retries; event NOT delivered to SIEM",
				"type", cfg.Type, "action", e.Action, "attempts", attempt, "err", err)
			return
		}
		f.log.Warn("audit forward failed; will retry", "type", cfg.Type,
			"attempt", attempt, "err", err)
		time.Sleep(backoff)
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// SendTest delivers a synthetic event to verify configuration, returning the
// send error (nil on success).
func (f *Forwarder) SendTest(cfg Config) error {
	// The test address comes straight from the request body; refuse SSRF targets
	// (metadata/loopback) before connecting.
	if err := validateTarget(cfg); err != nil {
		return err
	}
	return f.send(cfg, models.AuditEvent{
		Action: "audit.forward_test", ActorName: "system", TargetKind: "system",
		Detail: map[string]any{"message": "Fleet audit forwarding test"}, CreatedAt: time.Now(),
	})
}

func (f *Forwarder) send(cfg Config, e models.AuditEvent) error {
	// Defense in depth: validate the destination on the live path too. SafeClient
	// only re-checks redirects, not the initial target, and a config persisted
	// before this guard (or by any other path) must still be refused here.
	if err := validateTarget(cfg); err != nil {
		return err
	}
	payload, _ := json.Marshal(e)
	switch strings.ToLower(cfg.Type) {
	case "http":
		req, err := http.NewRequest(http.MethodPost, cfg.Address, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if tok := strings.TrimSpace(cfg.Token); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("collector returned %d", resp.StatusCode)
		}
		return nil
	default: // syslog
		return f.sendSyslog(cfg, e, payload)
	}
}

// sendSyslog emits an RFC 5424 message over UDP, TCP, or TCP+TLS. Plain UDP/TCP use
// newline framing (RFC 6587 non-transparent); TLS uses octet-counted framing
// (RFC 5425), which is what TLS syslog collectors expect. The event JSON is the
// free-form MSG; PRI is local0.info.
func (f *Forwarder) sendSyslog(cfg Config, e models.AuditEvent, payload []byte) error {
	const pri = 16*8 + 6 // facility local0 (16), severity informational (6)
	ts := e.CreatedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	msgid := e.Action
	if msgid == "" {
		msgid = "-"
	}
	msg := fmt.Sprintf("<%d>1 %s %s fleet-terminal - %s - %s",
		pri, ts.Format(time.RFC3339), f.hostname, msgid, payload)

	conn, err := f.dialSyslog(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	var framed string
	if cfg.TLS {
		framed = fmt.Sprintf("%d %s", len(msg), msg) // octet-counting (RFC 5425)
	} else {
		framed = msg + "\n" // non-transparent framing
	}
	_, err = conn.Write([]byte(framed))
	return err
}

// dialSyslog opens the transport for a syslog target: UDP, TCP, or TCP+TLS. TLS is
// only valid over a stream transport, so it forces TCP.
func (f *Forwarder) dialSyslog(cfg Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if cfg.TLS {
		tc, err := f.tlsConfig(cfg)
		if err != nil {
			return nil, err
		}
		return tls.DialWithDialer(dialer, "tcp", cfg.Address, tc)
	}
	proto := strings.ToLower(cfg.Protocol)
	if proto != "tcp" {
		proto = "udp"
	}
	return dialer.Dial(proto, cfg.Address)
}

// tlsConfig builds the client TLS config for a syslog target: ServerName from the
// address host, an optional pinned CA (CACertPEM), and an optional insecure escape
// hatch for lab collectors.
func (f *Forwarder) tlsConfig(cfg Config) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		host = cfg.Address
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // opt-in, documented, off by default
	}
	if pem := strings.TrimSpace(cfg.CACertPEM); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("audit forward: invalid CACertPEM")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}
