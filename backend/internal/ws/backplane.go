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

// controlShadowSub / controlShadowUnsub announce (and withdraw) an instance's
// interest in shadowing a session whose PTY lives on another instance. The owning
// instance responds by mirroring that session's live frames onto the backplane.
const (
	controlShadowSub   = "shadow_sub"
	controlShadowUnsub = "shadow_unsub"
)

// shadowChunk bounds the raw output bytes carried in one shadow frame so the
// base64-encoded NOTIFY payload stays under Postgres's 8000-byte limit.
const shadowChunk = 4096

// shadowFrame carries one piece of a shadowed session's live output/resize across
// instances. Data is base64-encoded by the JSON marshaller.
type shadowFrame struct {
	SID  string `json:"i"`
	Kind string `json:"k"`
	Data []byte `json:"d,omitempty"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
}

// envelope is one message on the backplane. For a normal event, Type/Data (and
// UserID/Session for session-scoped visibility) are set. For a control message,
// Control/Target are set. For a shadow relay frame, Shadow is set. Origin identifies
// the publishing instance so it can skip re-delivering its own messages (already
// delivered locally at publish time).
type envelope struct {
	Origin  string          `json:"o,omitempty"`
	Type    string          `json:"t,omitempty"`
	Data    json.RawMessage `json:"d,omitempty"`
	UserID  string          `json:"u,omitempty"`
	Session bool            `json:"s,omitempty"`
	Control string          `json:"c,omitempty"`
	Target  string          `json:"tg,omitempty"`
	Shadow  *shadowFrame    `json:"sh,omitempty"`
}

// Backplane bridges the per-instance Hub across instances using Postgres
// LISTEN/NOTIFY — no extra infrastructure beyond the database Fleet already
// requires. It publishes local broadcasts to every instance and delivers remote
// broadcasts to this instance's clients.
type Backplane struct {
	pool      *pgxpool.Pool
	origin    string
	hub       *Hub
	log       *slog.Logger
	control   func(action, target string)                             // control messages (set by server)
	shadowCtl func(action string, sid uuid.UUID, origin string)       // shadow sub/unsub (owner side)
	shadowFn  func(sid uuid.UUID, kind string, data []byte, c, r int) // shadow frame delivery (watcher side)
	shadowOut chan envelope                                           // async send buffer for shadow frames
}

// NewBackplane constructs a backplane for the given instance identity.
func NewBackplane(pool *pgxpool.Pool, origin string, hub *Hub, log *slog.Logger) *Backplane {
	return &Backplane{pool: pool, origin: origin, hub: hub, log: log, shadowOut: make(chan envelope, 512)}
}

// SetControlHandler registers the handler invoked for cross-instance control
// messages (e.g. terminate). Set once at startup before serving.
func (b *Backplane) SetControlHandler(fn func(action, target string)) { b.control = fn }

// SetShadowHandlers wires the cross-instance live-shadow bridge: ctl handles a peer's
// shadow subscribe/unsubscribe (owner side), frame delivers a relayed frame to local
// watchers (watcher side). Set once at startup.
func (b *Backplane) SetShadowHandlers(
	ctl func(action string, sid uuid.UUID, origin string),
	frame func(sid uuid.UUID, kind string, data []byte, cols, rows int),
) {
	b.shadowCtl, b.shadowFn = ctl, frame
}

// PublishShadowSub announces (want=true) or withdraws (want=false) this instance's
// interest in shadowing sid. Broadcast to all instances; only the owner acts.
func (b *Backplane) PublishShadowSub(sid uuid.UUID, want bool) {
	action := controlShadowUnsub
	if want {
		action = controlShadowSub
	}
	b.publish(envelope{Control: action, Target: sid.String()})
}

// PublishShadowFrame mirrors one live frame of a locally-owned session to peers,
// chunking output so each NOTIFY stays under the payload cap. Non-blocking: frames
// are dropped rather than stalling the PTY when the send buffer is full or the DB is
// slow (consistent with the slow-watcher drop policy).
func (b *Backplane) PublishShadowFrame(sid uuid.UUID, kind string, data []byte, cols, rows int) {
	sidStr := sid.String()
	if kind != "o" || len(data) <= shadowChunk {
		b.enqueueShadow(envelope{Shadow: &shadowFrame{SID: sidStr, Kind: kind, Data: data, Cols: cols, Rows: rows}})
		return
	}
	for off := 0; off < len(data); off += shadowChunk {
		end := off + shadowChunk
		if end > len(data) {
			end = len(data)
		}
		b.enqueueShadow(envelope{Shadow: &shadowFrame{SID: sidStr, Kind: "o", Data: data[off:end]}})
	}
}

func (b *Backplane) enqueueShadow(env envelope) {
	select {
	case b.shadowOut <- env:
	default: // buffer full: drop this frame rather than block the producing PTY
	}
}

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
	go b.drainShadow(ctx) // async publisher for mirrored shadow frames
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

// drainShadow publishes buffered shadow frames on a dedicated goroutine so the PTY
// output path is never blocked on a database round-trip.
func (b *Backplane) drainShadow(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-b.shadowOut:
			b.publish(env)
		}
	}
}

// dispatch delivers a received envelope to local clients (or the control handler),
// skipping envelopes this instance published itself.
func (b *Backplane) dispatch(env envelope) {
	if env.Origin == b.origin {
		return // already delivered locally at publish time
	}
	if env.Shadow != nil {
		if b.shadowFn != nil {
			if sid, err := uuid.Parse(env.Shadow.SID); err == nil {
				b.shadowFn(sid, env.Shadow.Kind, env.Shadow.Data, env.Shadow.Cols, env.Shadow.Rows)
			}
		}
		return
	}
	if env.Control == controlShadowSub || env.Control == controlShadowUnsub {
		if b.shadowCtl != nil {
			if sid, err := uuid.Parse(env.Target); err == nil {
				b.shadowCtl(env.Control, sid, env.Origin)
			}
		}
		return
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
