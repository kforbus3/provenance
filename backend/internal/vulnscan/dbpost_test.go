package vulnscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/config"
)

// A database operation must outlive the inbound request's deadline.
//
// Every route is behind middleware.Timeout(60s) (api/server.go), so the context
// a handler is given is cancelled after a minute. dbPost built a client with a
// 20-minute timeout and then passed that inbound context straight to it, which
// cancels the outbound call regardless of what the client's own timeout says.
//
// The grype vulnerability database is hundreds of megabytes and is unpacked
// after it lands, so it takes minutes. Every online update therefore failed at
// exactly sixty seconds with
//
//	Online update failed: scanner unreachable: Post ".../db/update":
//	context deadline exceeded
//
// and a hint suggesting the scanner could not reach the internet.
//
// It could. The download had already started and it FINISHED -- /db/status
// showed a valid database built that morning. The operation worked and the
// reporting of it did not, which is the worst version of this: an operator is
// told to go and find a database archive to import by hand, for a database they
// already have.
func TestDBPostSurvivesInboundDeadline(t *testing.T) {
	// A scanner that takes longer than the inbound deadline, as the real one does.
	const scannerWork = 300 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(scannerWork)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"output":"updated"}`))
	}))
	defer srv.Close()

	s := &Service{cfg: &config.Config{GrypeScannerURL: srv.URL}}

	// The inbound request's context, already on a short fuse.
	ctx, cancel := context.WithTimeout(context.Background(), scannerWork/3)
	defer cancel()

	out, err := s.dbPost(ctx, "/db/update", nil, "application/json")
	if err != nil {
		t.Fatalf("dbPost gave up when the INBOUND context expired, which is the "+
			"bug: the scanner was still working and would have finished. err = %v", err)
	}
	if !strings.Contains(out, "updated") {
		t.Errorf("output = %q, want the scanner's response", out)
	}

	// And the inbound context really did expire, so the test is proving what it
	// claims rather than passing because the fuse was long enough.
	if ctx.Err() == nil {
		t.Error("the inbound context never expired; this test proved nothing")
	}
}

// A timeout and an unreachable scanner are different problems with different
// answers -- retry, versus go and find a database archive. Calling both
// "unreachable" is what sent an operator looking for a network fault that did
// not exist.
func TestDBPostDistinguishesTimeoutFromUnreachable(t *testing.T) {
	s := &Service{cfg: &config.Config{GrypeScannerURL: "http://127.0.0.1:1"}} // nothing listens
	_, err := s.dbPost(context.Background(), "/db/update", nil, "application/json")
	if err == nil {
		t.Fatal("expected an error connecting to a closed port")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("a refused connection should say unreachable, got: %v", err)
	}
}
