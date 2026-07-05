package federation

import (
	"bufio"
	"encoding/json"
	"io"
)

// Frame is the first line on every hub↔site yamux stream: a newline-delimited
// JSON header describing what the stream carries, followed by the raw body.
type Frame struct {
	// Kind selects the stream's purpose:
	//   "http"  — one HTTP round-trip proxied into the site's router.
	//   "ws"    — a WebSocket proxy (terminal): bidirectional framed relay.
	//   "sftp"  — a streaming HTTP body (SFTP up/download).
	//   "push"  — site→hub read-model push (JSON messages until close).
	//   "ping"  — liveness heartbeat.
	Kind string `json:"kind"`

	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Header  map[string]string `json:"header,omitempty"`
	BodyLen int               `json:"len,omitempty"` // exact request-body length that follows

	// ServiceToken authenticates the hub as a service principal (hub-signed).
	ServiceToken string `json:"svc,omitempty"`
	// ActorAssertion is the hub-signed acting-user assertion (for user actions).
	ActorAssertion string `json:"actor,omitempty"`
}

// WriteFrame writes a header line to w.
func WriteFrame(w io.Writer, f *Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ReadFrame reads one header line from r. The returned *bufio.Reader must be used
// for any subsequent body reads (it may hold buffered bytes past the newline).
func ReadFrame(r io.Reader) (*Frame, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, nil, err
	}
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, nil, err
	}
	return &f, br, nil
}

// PushMsg is one site→hub read-model update on a "push" stream.
type PushMsg struct {
	Type string          `json:"type"` // host.snapshot | host.status | session | audit | ...
	Data json.RawMessage `json:"data"`
}

// RespHeader is the newline-delimited JSON the site writes back on an http stream
// before the response body.
type RespHeader struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// WriteRespHeader writes a response header line.
func WriteRespHeader(w io.Writer, h *RespHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadRespHeader reads the response header line; the returned reader holds any
// buffered body bytes.
func ReadRespHeader(r io.Reader) (*RespHeader, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, nil, err
	}
	var h RespHeader
	if err := json.Unmarshal(line, &h); err != nil {
		return nil, nil, err
	}
	return &h, br, nil
}
