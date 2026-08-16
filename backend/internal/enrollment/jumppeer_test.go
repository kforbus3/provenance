package enrollment

import (
	"strings"
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/config"
)

func peerScript(t *testing.T) string {
	t.Helper()
	s := &Service{cfg: &config.Config{WGInterface: "wgfleet"}}
	return s.jumpPeerScript("containers", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"jumphost.example.com:51820", "10.100.0.24")
}

// The persisted peer fragment MUST carry the endpoint and keepalive, not just the
// key and allowed IPs. Without them a jump-host rebuild restores a mute hub: it can
// no longer initiate to any host, so a host whose own Endpoint is unreachable is
// carried by nothing and goes permanently dark after an unrelated redeploy.
func TestJumpPeerScriptPersistsEndpoint(t *testing.T) {
	got := peerScript(t)

	conf := got[strings.Index(got, "cat > /etc/wireguard/peers/"):]
	for _, want := range []string{
		"Endpoint = jumphost.example.com:51820",
		"PersistentKeepalive = 25",
		"AllowedIPs = 10.100.0.24/32",
		"PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("persisted peer fragment missing %q\n--- fragment ---\n%s", want, conf)
		}
	}
}

// The runtime `wg set` must still carry the same endpoint, so connectivity is
// immediate at enrollment rather than waiting on the first restart.
func TestJumpPeerScriptRuntimeSetKeepsEndpoint(t *testing.T) {
	got := peerScript(t)
	if !strings.Contains(got, "endpoint 'jumphost.example.com:51820'") {
		t.Errorf("runtime wg set lost its endpoint:\n%s", got)
	}
	if !strings.Contains(got, "persistent-keepalive 25") {
		t.Errorf("runtime wg set lost its keepalive:\n%s", got)
	}
}

// The fragment is written with a quoted heredoc, so the endpoint must land
// literally — no shell expansion of anything it happens to contain.
func TestJumpPeerScriptFragmentHeredocIsQuoted(t *testing.T) {
	got := peerScript(t)
	if !strings.Contains(got, "<<'EOF'") {
		t.Error("peer fragment heredoc is unquoted; contents would be shell-expanded")
	}
}
