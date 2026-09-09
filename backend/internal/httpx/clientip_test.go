package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPReadsRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.10.0.77:51234"
	if got := ClientIP(r); got != "10.10.0.77" {
		t.Errorf("got %q, want 10.10.0.77", got)
	}
}

// The bug this closes. Four of the six copies this replaces read the left-most
// X-Forwarded-For entry — the one the caller writes — so any authenticated user
// could choose the address recorded against their own Kubernetes exec, database
// query, SFTP transfer or ad-hoc command.
//
// The realIP middleware has already resolved XFF, and only for a trusted peer.
// Reading the header again here would undo that.
func TestClientIPIgnoresAForgedForwardedForHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:44444"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("got %q, want 203.0.113.9 — the header is caller-supplied and "+
			"must not override the address the connection came from", got)
	}
}

func TestClientIPReturnsEmptyRatherThanRubbish(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "not-an-address"
	if got := ClientIP(r); got != "" {
		t.Errorf("got %q, want empty — an audit record that admits it does not "+
			"know beats one asserting something false", got)
	}
}

// IPv6 keeps its colons; only the port separator is stripped.
func TestClientIPHandlesIPv6(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:8443"
	if got := ClientIP(r); got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}
