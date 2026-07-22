// Package link is the multiplexed control channel between a hub and a site. The
// site dials the hub over WSS; both ends wrap the connection in a yamux session.
// Either side can open streams: the hub opens streams to proxy management/live
// requests INTO the site; the site opens streams to PUSH read-model updates to
// the hub. One yamux stream = one logical connection (HTTP round-trip, WS session,
// or SFTP stream); closing the stream closes it in both directions.
package link

import (
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// Session wraps a live yamux session for one site.
type Session struct {
	SiteID uuid.UUID
	mux    *yamux.Session
}

// OpenStream opens a new multiplexed stream (net.Conn).
func (s *Session) OpenStream() (*yamux.Stream, error) { return s.mux.OpenStream() }

// AcceptStream blocks for the next stream opened by the peer.
func (s *Session) AcceptStream() (*yamux.Stream, error) { return s.mux.AcceptStream() }

// Close tears down the session.
func (s *Session) Close() error { return s.mux.Close() }

// IsClosed reports whether the underlying session has gone away.
func (s *Session) IsClosed() bool { return s.mux.IsClosed() }

// CloseChan is closed when the session goes away, so a blocked loop can react to
// a teardown (e.g. a local key rotation closing the link) without waiting for its
// next timer tick.
func (s *Session) CloseChan() <-chan struct{} { return s.mux.CloseChan() }

// Wrap builds a yamux Session over a websocket connection. server=true on the
// hub (accepting), false on the site (dialing).
func Wrap(siteID uuid.UUID, ws *websocket.Conn, server bool) (*Session, error) {
	nc := newWSConn(ws)
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	var mux *yamux.Session
	var err error
	if server {
		mux, err = yamux.Server(nc, cfg)
	} else {
		mux, err = yamux.Client(nc, cfg)
	}
	if err != nil {
		return nil, err
	}
	return &Session{SiteID: siteID, mux: mux}, nil
}

// Registry tracks live site sessions on the hub, keyed by site_id.
type Registry struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*Session
}

func NewRegistry() *Registry {
	return &Registry{sessions: map[uuid.UUID]*Session{}}
}

// Put registers a session, closing any prior one for the same site.
func (r *Registry) Put(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.sessions[s.SiteID]; old != nil {
		_ = old.Close()
	}
	r.sessions[s.SiteID] = s
}

// Get returns the live session for a site, if any.
func (r *Registry) Get(siteID uuid.UUID) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[siteID]
	if ok && s.IsClosed() {
		return nil, false
	}
	return s, ok
}

// Remove drops (and closes) a site's session.
func (r *Registry) Remove(siteID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.sessions[siteID]; s != nil {
		_ = s.Close()
		delete(r.sessions, siteID)
	}
}

// SiteIDs lists sites with a live session.
func (r *Registry) SiteIDs() []uuid.UUID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]uuid.UUID, 0, len(r.sessions))
	for id, s := range r.sessions {
		if !s.IsClosed() {
			out = append(out, id)
		}
	}
	return out
}
