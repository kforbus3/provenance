package federation

import (
	"encoding/binary"
	"errors"
	"io"
)

// WebSocket-over-tunnel message framing. A terminal session's browser WebSocket
// messages are relayed across a yamux stream as [type:1][len:4 BE][payload]. The
// type byte matches gorilla's constants (TextMessage=1, BinaryMessage=2) so the
// terminal relay sees identical message types on either transport.
const (
	msgText   = 1
	msgBinary = 2
	maxWSMsg  = 1 << 20 // 1 MiB, mirrors the browser terminal read limit
)

func writeWSMessage(w io.Writer, mt int, data []byte) error {
	var hdr [5]byte
	hdr[0] = byte(mt)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func readWSMessage(r io.Reader) (int, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxWSMsg {
		return 0, nil, errors.New("federation: ws frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return int(hdr[0]), buf, nil
}

// streamWSTransport adapts a tunnel stream to terminal.WSTransport on the site,
// so the site's terminal relay drives it exactly like a browser WebSocket.
type streamWSTransport struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (t *streamWSTransport) ReadMessage() (int, []byte, error) { return readWSMessage(t.r) }
func (t *streamWSTransport) WriteMessage(mt int, data []byte) error {
	return writeWSMessage(t.w, mt, data)
}
func (t *streamWSTransport) Close() error { return t.c.Close() }
