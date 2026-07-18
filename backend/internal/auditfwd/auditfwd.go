// Package auditfwd forwards Fleet's audit events to an external collector —
// syslog (RFC 5424 over UDP/TCP) or a generic HTTP JSON endpoint — so they can
// land in a SIEM. It is best-effort and never blocks the audit write: the store
// calls Forward in a goroutine for each appended event. The hash-chained copy
// in Postgres remains the system of record.
package auditfwd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/ssrf"
	"github.com/fleet-terminal/backend/internal/store"
)

const settingKey = "audit_forward"

// Config is the persisted forwarding configuration.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`     // syslog | http
	Address  string `json:"address"`  // host:port (syslog) or URL (http)
	Protocol string `json:"protocol"` // udp | tcp (syslog only)
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
}

func New(st *store.Store, log *slog.Logger) *Forwarder {
	host, _ := os.Hostname()
	if host == "" {
		host = "fleet-terminal"
	}
	return &Forwarder{
		store: st, log: log, hostname: host,
		client:   ssrf.SafeClient(5 * time.Second),
		cacheTTL: 30 * time.Second,
	}
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

// Forward sends one audit event if forwarding is enabled. Safe to call from a
// goroutine; errors are logged only.
func (f *Forwarder) Forward(e models.AuditEvent) {
	cfg := f.config()
	if !cfg.Enabled || strings.TrimSpace(cfg.Address) == "" {
		return
	}
	if err := f.send(cfg, e); err != nil {
		f.log.Warn("audit forward failed", "type", cfg.Type, "err", err)
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

// sendSyslog emits an RFC 5424 message (newline-framed) over UDP or TCP. The
// event JSON is the free-form MSG; PRI is local0.info.
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
	line := fmt.Sprintf("<%d>1 %s %s fleet-terminal - %s - %s\n",
		pri, ts.Format(time.RFC3339), f.hostname, msgid, payload)

	proto := strings.ToLower(cfg.Protocol)
	if proto != "tcp" {
		proto = "udp"
	}
	conn, err := net.DialTimeout(proto, cfg.Address, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(line))
	return err
}
