package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// notifyChannel is the Postgres LISTEN/NOTIFY channel the backplane fans events over.
const notifyChannel = "fleet_events"

// controlTerminate is a cross-instance control action asking the owning instance to
// force-close a session's live connections.
const controlTerminate = "terminate"

// envelope is one message on the backplane. For a normal event, Type/Data (and
// UserID/Session for session-scoped visibility) are set. For a control message,
// Control/Target are set. Origin identifies the publishing instance so it can skip
// re-delivering its own messages (already delivered locally at publish time).
type envelope struct {
	Origin  string          `json:"o,omitempty"`
	Type    string          `json:"t,omitempty"`
	Data    json.RawMessage `json:"d,omitempty"`
	UserID  string          `json:"u,omitempty"`
	Session bool            `json:"s,omitempty"`
	Control string          `json:"c,omitempty"`
	Target  string          `json:"tg,omitempty"`
}

// Backplane bridges the per-instance Hub across instances using Postgres
// LISTEN/NOTIFY — no extra infrastructure beyond the database Fleet already
// requires. It publishes local broadcasts to every instance and delivers remote
// broadcasts to this instance's clients.
type Backplane struct {
	pool    *pgxpool.Pool
	origin  string
	hub     *Hub
	log     *slog.Logger
	control func(action, target string) // handles control messages (set by the server)
}

// NewBackplane constructs a backplane for the given instance identity.
func NewBackplane(pool *pgxpool.Pool, origin string, hub *Hub, log *slog.Logger) *Backplane {
	return &Backplane{pool: pool, origin: origin, hub: hub, log: log}
}

// SetControlHandler registers the handler invoked for cross-instance control
// messages (e.g. terminate). Set once at startup before serving.
func (b *Backplane) SetControlHandler(fn func(action, target string)) { b.control = fn }

// publish sends an envelope to all instances (best-effort). Delivery to local
// clients has already happened at the call site, so publish is purely the fan-out to
// peers; this instance skips its own copy on receipt via Origin.
func (b *Backplane) publish(env envelope) {
	env.Origin = b.origin
	payload, err := json.Marshal(env)
	if err != nil || len(payload) > 7000 { // NOTIFY payload cap is 8000 bytes
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := b.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, string(payload)); err != nil {
		b.log.Debug("ws backplane publish failed", "err", err)
	}
}

// Run holds a dedicated connection listening for notifications and dispatching them
// to local clients until ctx is cancelled. It reconnects with backoff on error.
func (b *Backplane) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := b.listen(ctx); err != nil && ctx.Err() == nil {
			b.log.Warn("ws backplane listen error, reconnecting", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (b *Backplane) listen(ctx context.Context) error {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var env envelope
		if json.Unmarshal([]byte(n.Payload), &env) != nil {
			continue
		}
		b.dispatch(env)
	}
}

// dispatch delivers a received envelope to local clients (or the control handler),
// skipping envelopes this instance published itself.
func (b *Backplane) dispatch(env envelope) {
	if env.Origin == b.origin {
		return // already delivered locally at publish time
	}
	if env.Control != "" {
		if b.control != nil {
			b.control(env.Control, env.Target)
		}
		return
	}
	if env.Session {
		uid, _ := uuid.Parse(env.UserID)
		b.hub.fanout(env.Type, env.Data, sessionAllow(uid))
		return
	}
	b.hub.fanout(env.Type, env.Data, nil)
}

// toRaw marshals event data to a RawMessage for transport, so the receiving instance
// re-emits byte-identical JSON. On error it yields JSON null.
func toRaw(data any) json.RawMessage {
	b, err := json.Marshal(data)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
