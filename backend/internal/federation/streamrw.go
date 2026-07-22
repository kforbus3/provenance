package federation

import (
	"io"
	"net/http"
)

// streamResponseWriter is an http.ResponseWriter that streams the response of a
// site-dispatched request directly onto the yamux stream: it writes the framed
// RespHeader once (on the first WriteHeader/Write), then copies the body through
// with no buffering. This keeps large SFTP downloads/tars off the hub's heap.
type streamResponseWriter struct {
	w           io.Writer
	header      http.Header
	wroteHeader bool
	status      int
}

func newStreamRW(w io.Writer) *streamResponseWriter {
	return &streamResponseWriter{w: w, header: http.Header{}, status: http.StatusOK}
}

func (s *streamResponseWriter) Header() http.Header { return s.header }

func (s *streamResponseWriter) WriteHeader(status int) {
	if s.wroteHeader {
		return
	}
	s.status = status
	s.wroteHeader = true
	h := map[string]string{}
	for k := range s.header {
		h[k] = s.header.Get(k)
	}
	_ = WriteRespHeader(s.w, &RespHeader{Status: status, Header: h})
}

func (s *streamResponseWriter) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.w.Write(p)
}

// Flush is a no-op passthrough so streaming handlers (SFTP) don't buffer; the
// yamux stream writes are already flushed per-write.
func (s *streamResponseWriter) Flush() {}

// finish ensures a header is emitted even for handlers that wrote nothing (e.g.
// a 204 or an empty body).
func (s *streamResponseWriter) finish() {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
}
