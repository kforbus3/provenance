package federation

import (
	"bufio"
	"context"
	"io"
)

// serveHubStream dispatches a hub-initiated proxy stream on the site. The full
// path — verify the hub service token + acting-user assertion against the pinned
// hub key, synthesize an *auth.Principal from the assertion, and serve the
// request through the site's own router (s.siteHandler) via a stream-backed
// ResponseWriter — is Phase F3/F4. This scaffold acknowledges the stream and
// closes it so a hub that probes the site does not hang.
//
// Managed mode gate: the site only ever honors assertions when it has a joined
// hub record with managed_mode=true and the hub signature verifies; that check
// lands with the dispatch implementation.
func (s *Service) serveHubStream(ctx context.Context, f *Frame, body *bufio.Reader, stream io.ReadWriteCloser) {
	switch f.Kind {
	case "http", "ws", "sftp":
		_ = WriteFrame(stream, &Frame{Kind: "error"})
		_, _ = io.WriteString(stream, `{"error":"site ingress dispatch is implemented in phase F3/F4"}`)
	default:
		// Unknown/ping: drain and close.
		_, _ = io.Copy(io.Discard, body)
	}
}
