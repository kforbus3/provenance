package wsorigin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowed(t *testing.T) {
	const public = "https://fleet.example.com:8443"

	req := func(origin string) *http.Request {
		r := httptest.NewRequest("GET", "/ws", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}

	cases := []struct {
		name, origin, public string
		want                 bool
	}{
		{"no origin (non-browser client) allowed", "", public, true},
		{"matching origin allowed", "https://fleet.example.com:8443", public, true},
		{"matching origin different case allowed", "https://Fleet.Example.com:8443", public, true},
		{"different host rejected", "https://evil.example.com", public, false},
		{"different scheme rejected", "http://fleet.example.com:8443", public, false},
		{"different port rejected", "https://fleet.example.com:9999", public, false},
		{"origin present but public URL empty fails closed", "https://fleet.example.com:8443", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Allowed(req(c.origin), c.public); got != c.want {
				t.Errorf("Allowed(origin=%q, public=%q) = %v, want %v", c.origin, c.public, got, c.want)
			}
			// Check must agree with Allowed.
			if got := Check(c.public)(req(c.origin)); got != c.want {
				t.Errorf("Check(%q)(origin=%q) = %v, want %v", c.public, c.origin, got, c.want)
			}
		})
	}
}
