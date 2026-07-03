// Package ws provides a WebSocket hub for pushing real-time events (host status,
// session activity) to connected dashboards.
package ws

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fleet-terminal/backend/internal/app"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Event is a typed message broadcast to clients.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// Hub fans out events to all connected clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
}

// NewHub constructs an empty Hub.
func NewHub() *Hub { return &Hub{clients: make(map[*client]struct{})} }

// Broadcast sends an event to every connected client (best-effort, non-blocking).
func (h *Hub) Broadcast(eventType string, data any) {
	h.fanout(eventType, data, nil)
}

// BroadcastSession sends a session-activity event only to clients that may see
// it: the session's own user, or a client holding Session.Replay (which can list
// all sessions anyway). Everyone else is skipped, so one user's activity does not
// leak to every connected dashboard.
func (h *Hub) BroadcastSession(eventType string, userID uuid.UUID, data any) {
	h.fanout(eventType, data, func(c *client) bool {
		return c.allSessions || c.userID == userID
	})
}

// fanout marshals once and delivers to every client for which allow (if non-nil)
// returns true.
func (h *Hub) fanout(eventType string, data any, allow func(*client) bool) {
	payload, err := json.Marshal(Event{Type: eventType, Data: data})
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		if allow != nil && !allow(c) {
			continue
		}
		select {
		case c.send <- payload:
		default:
			// Slow client: drop the message rather than block the hub.
		}
	}
}

func (h *Hub) add(c *client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
	h.mu.Unlock()
}

type client struct {
	conn *websocket.Conn
	send chan []byte
	// userID and allSessions decide which session-activity events this client may
	// receive (see BroadcastSession). allSessions is true for Session.Replay
	// holders (and super admins / Admin.All, which Has covers).
	userID      uuid.UUID
	allSessions bool
}

// Mount attaches the events WebSocket endpoint. Clients authenticate with a
// short-lived access token passed as a query parameter.
func Mount(r chi.Router, d *app.Deps, hub *Hub) {
	r.Get("/events/ws", func(w http.ResponseWriter, req *http.Request) {
		token := req.URL.Query().Get("token")
		p, err := d.Auth.AuthenticateToken(req.Context(), token)
		if err != nil || p == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		c := &client{
			conn: conn, send: make(chan []byte, 32),
			userID:      p.UserID,
			allSessions: p.Has("Session.Replay"),
		}
		hub.add(c)
		go c.writePump()
		c.readPump(hub)
	})
}

func (c *client) readPump(h *Hub) {
	defer func() {
		h.remove(c)
		_ = c.conn.Close()
	}()
	// This is a push-only feed; clients send nothing but pongs. Cap inbound frames
	// so a client can't force a large allocation, and require periodic pongs so an
	// idle/half-open connection is reaped instead of lingering.
	c.conn.SetReadLimit(1024)
	_ = c.conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *client) writePump() {
	ping := time.NewTicker(54 * time.Second)
	defer ping.Stop()
	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ping.C:
			// Keeps the read deadline alive via the client's pong, and detects a
			// dead peer promptly.
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
