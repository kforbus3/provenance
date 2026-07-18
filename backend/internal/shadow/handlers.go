// Package shadow serves read-only live "shadowing" of an active terminal session
// over a WebSocket — real-time four-eyes oversight of privileged access. The
// watcher receives the same output and resize events as the operator but can send
// no input. Gated by Session.Watch.
package shadow

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Mount attaches the watch WebSocket endpoint. Auth is via a query-param token
// (browsers cannot set headers on a WebSocket), like the terminal endpoint.
func Mount(r chi.Router, d *app.Deps) {
	h := &handler{d: d}
	r.Get("/sessions/{id}/watch", h.watch)
}

type handler struct{ d *app.Deps }

type controlMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
	Data string `json:"data,omitempty"`
}

func (h *handler) watch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, err := h.d.Auth.AuthenticateToken(ctx, r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !principal.Has("Session.Watch") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sid, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad session id", http.StatusBadRequest)
		return
	}
	if h.d.Watch == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(512) // watchers send nothing meaningful

	frames, size, unsub := h.d.Watch.Subscribe(sid)
	defer unsub()

	// Record that oversight occurred — who watched which session, and when.
	_, _ = h.d.Store.AppendAudit(ctx, models.AuditEvent{
		ActorID: &principal.UserID, ActorName: principal.Username, Action: "session.watch",
		TargetKind: "ssh_session", TargetID: sid.String(),
	})

	// All writes happen from this goroutine's loop, so no write serialization is
	// needed. Seed the watcher with the current size (if known).
	if size[0] > 0 && size[1] > 0 {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(controlMsg{Type: "resize", Cols: size[0], Rows: size[1]}))
	} else {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(controlMsg{Type: "info", Data: "Waiting for session activity…"}))
	}

	// Reader goroutine: watchers are read-only, but we still read to notice a
	// close and to let the library answer pings. Inbound data is ignored.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(54 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ping.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		case f, ok := <-frames:
			if !ok {
				return
			}
			var werr error
			switch f.Kind {
			case "o":
				werr = conn.WriteMessage(websocket.BinaryMessage, f.Data)
			case "r":
				werr = conn.WriteMessage(websocket.TextMessage, mustJSON(controlMsg{Type: "resize", Cols: f.Cols, Rows: f.Rows}))
			case "end":
				_ = conn.WriteMessage(websocket.TextMessage, mustJSON(controlMsg{Type: "ended", Data: "The session has ended."}))
				return
			}
			if werr != nil {
				return
			}
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
