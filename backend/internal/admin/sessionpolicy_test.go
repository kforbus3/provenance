package admin

import (
	"encoding/json"
	"testing"
)

func TestValidateSessionPolicy(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		saverIP string
		wantErr bool
	}{
		{"empty policy ok", `{"ipAllowlist":[],"maxConcurrentSessions":0}`, "10.0.0.1", false},
		{"allowlist includes saver", `{"ipAllowlist":["10.0.0.0/8"]}`, "10.0.0.5", false},
		{"allowlist excludes saver → lockout", `{"ipAllowlist":["10.0.0.0/8"]}`, "192.168.1.1", true},
		{"bad cidr", `{"ipAllowlist":["10.0.0.0/99"]}`, "10.0.0.1", true},
		{"bad ip", `{"ipAllowlist":["notanip"]}`, "10.0.0.1", true},
		{"negative limit", `{"maxConcurrentSessions":-1}`, "10.0.0.1", true},
		{"bare ip saver match", `{"ipAllowlist":["10.0.0.5"]}`, "10.0.0.5", false},
		{"malformed json", `{`, "10.0.0.1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := validateSessionPolicy(json.RawMessage(c.body), c.saverIP)
			if (msg != "") != c.wantErr {
				t.Errorf("validateSessionPolicy(%s) msg=%q, wantErr=%v", c.body, msg, c.wantErr)
			}
		})
	}
}
