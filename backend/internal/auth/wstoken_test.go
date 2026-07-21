package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWSToken(t *testing.T) {
	var s Service

	// Subprotocol path: token after the "fleet-bearer" marker; server echoes the marker.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/x", nil)
	r.Header.Set("Sec-WebSocket-Protocol", "fleet-bearer, abc.def.ghi")
	tok, hdr := s.WSToken(r)
	if tok != "abc.def.ghi" {
		t.Fatalf("subprotocol token = %q, want abc.def.ghi", tok)
	}
	if hdr == nil || hdr.Get("Sec-WebSocket-Protocol") != "fleet-bearer" {
		t.Fatalf("respHeader = %v, want echo of fleet-bearer marker", hdr)
	}

	// The token must never be echoed back in the response (would re-leak it).
	if got := hdr.Get("Sec-WebSocket-Protocol"); got == "abc.def.ghi" {
		t.Fatal("response subprotocol must not contain the token")
	}

	// Query-param fallback: no subprotocol → read ?token=, no response header.
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/terminal/x?token=qtok", nil)
	tok2, hdr2 := s.WSToken(r2)
	if tok2 != "qtok" {
		t.Fatalf("query token = %q, want qtok", tok2)
	}
	if hdr2 != nil {
		t.Fatalf("query path respHeader = %v, want nil", hdr2)
	}

	// Marker present but no following value → not treated as a token.
	r3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r3.Header.Set("Sec-WebSocket-Protocol", "fleet-bearer")
	if tok3, _ := s.WSToken(r3); tok3 != "" {
		t.Fatalf("lone marker token = %q, want empty", tok3)
	}
}
