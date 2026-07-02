package api

import (
	"net/http"
	"testing"
)

func TestClientFromXFF(t *testing.T) {
	// Trust the 10/8 range (a stand-in for the reverse-proxy network).
	mw := realIP([]string{"10.0.0.0/8"})
	var got string
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	}))

	call := func(remote, xff string) string {
		got = ""
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		h.ServeHTTP(nil, r)
		return got
	}

	// Untrusted public peer: XFF is IGNORED (can't spoof), RemoteAddr kept.
	if a := call("203.0.113.9:5555", "1.1.1.1"); a != "203.0.113.9:5555" {
		t.Errorf("untrusted peer XFF should be ignored, got %q", a)
	}
	// Trusted proxy: single XFF entry is the client.
	if a := call("10.0.0.5:5555", "198.51.100.7"); a != "198.51.100.7:0" {
		t.Errorf("trusted proxy should use XFF client, got %q", a)
	}
	// Trusted proxy, chained: right-most untrusted entry wins over a spoofed left one.
	if a := call("10.0.0.5:5555", "6.6.6.6, 198.51.100.7, 10.0.0.9"); a != "198.51.100.7:0" {
		t.Errorf("should take right-most untrusted, got %q", a)
	}
	// Trusted peer but no XFF: keep RemoteAddr.
	if a := call("10.0.0.5:5555", ""); a != "10.0.0.5:5555" {
		t.Errorf("no XFF should keep RemoteAddr, got %q", a)
	}
}
