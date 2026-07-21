package enrollment

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var agentUpgrader = websocket.Upgrader{
	ReadBufferSize:  8192,
	WriteBufferSize: 8192,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// agentEnrollReq is the first (text) frame the operator's bridge sends, carrying
// the same parameters as the HTTP enroll body (minus any secret material — the
// private key stays on the operator's machine).
type agentEnrollReq struct {
	BootstrapUser string `json:"bootstrapUser"`
	SudoPassword  string `json:"sudoPassword"`
	WGEndpoint    string `json:"wgEndpoint"`
	ViaJump       bool   `json:"viaJump"`
}

// enrollAgent bootstraps a host using the operator's SSH agent, forwarded over
// this WebSocket. The backend remains the SSH client: when its handshake needs a
// signature, agent.NewClient sends an agent request as a BINARY frame, which the
// operator's bridge pipes to their local agent; the signature returns the same
// way. The private key never leaves the operator's machine. TEXT frames carry
// the initial params (client->server) and the final result (server->client).
func (h *handler) enrollAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, err := h.d.Auth.AuthenticateToken(ctx, r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !principal.Has("Host.Enroll") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Bypasses RequireAuth — scope to the caller's tenant so the host lookup and
	// enrollment writes aren't RLS-denied under multi-tenancy.
	ctx = h.d.Auth.TenantScope(ctx, principal)
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad host id", http.StatusBadRequest)
		return
	}
	host, err := h.d.Store.GetHost(ctx, hostID)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	conn, err := agentUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// First frame: enrollment parameters (text/JSON).
	mt, data, err := conn.ReadMessage()
	if err != nil || mt != websocket.TextMessage {
		_ = sendResult(conn, nil, "expected initial parameters frame")
		return
	}
	var req agentEnrollReq
	if err := json.Unmarshal(data, &req); err != nil {
		_ = sendResult(conn, nil, "invalid parameters: "+err.Error())
		return
	}

	// Wrap subsequent BINARY frames as a byte stream for the SSH agent protocol.
	stream := &wsAgentStream{conn: conn}
	ag := agent.NewClient(stream)
	authMethod := ssh.PublicKeysCallback(ag.Signers)

	res, err := h.svc.Enroll(ctx, principal.SessionID, host, &principal.UserID,
		AgentParams(authMethod, req.BootstrapUser, req.SudoPassword, req.WGEndpoint, req.ViaJump))
	if err != nil {
		_ = sendResult(conn, res, err.Error())
		return
	}
	_ = sendResult(conn, res, "")
}

// sendResult serializes the enrollment outcome to the bridge as a text frame.
func sendResult(conn *websocket.Conn, res *Result, errMsg string) error {
	payload := map[string]any{"type": "result"}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	if res != nil {
		payload["job"] = res.Job
		payload["wgAddress"] = res.WGAddr
		payload["hostPublicKey"] = res.HostPub
	}
	b, _ := json.Marshal(payload)
	return conn.WriteMessage(websocket.TextMessage, b)
}

// wsAgentStream presents the WebSocket's binary frames as an io.ReadWriter so
// golang.org/x/crypto/ssh/agent can speak the agent protocol over it. The SSH
// handshake drives Read/Write sequentially from a single goroutine; a mutex
// guards writes defensively against the final result frame.
type wsAgentStream struct {
	conn *websocket.Conn
	wmu  sync.Mutex
	buf  []byte
}

func (s *wsAgentStream) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		mt, data, err := s.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			continue // ignore stray control/text frames
		}
		s.buf = data
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *wsAgentStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
