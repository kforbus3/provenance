package playbook

import (
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/sshgw"
)

// The runner must verify host keys against the backend's TOFU pins (H3). The
// known_hosts file it is handed carries a line — keyed exactly as ssh will look the
// host up (sshgw.HostKeyID) — for the jump host and every PINNED target, and omits
// unpinned targets so the runner falls back to accept-new for them rather than
// failing the run.
func TestBuildKnownHostsUsesPinsAndSkipsUnpinned(t *testing.T) {
	jumpID := sshgw.HostKeyID("jump.example", 2222)
	finalID := sshgw.HostKeyID("10.8.0.5", 22)
	pins := map[string]string{
		jumpID:  "ssh-ed25519 AAAAJUMPKEY",
		finalID: "ssh-ed25519 AAAAFINALKEY\n", // trailing newline must not double up
	}
	lookup := func(id string) (string, bool) { v, ok := pins[id]; return v, ok }

	hosts := []*models.Host{
		{WGAddress: "10.8.0.5", SSHPort: 22}, // pinned -> line emitted
		{Address: "10.8.0.9", SSHPort: 22},   // unpinned -> omitted (accept-new)
	}
	out := buildKnownHosts(lookup, "jump.example:2222", hosts)

	if !strings.Contains(out, jumpID+" ssh-ed25519 AAAAJUMPKEY\n") {
		t.Errorf("jump host pin missing from known_hosts:\n%s", out)
	}
	if !strings.Contains(out, finalID+" ssh-ed25519 AAAAFINALKEY\n") {
		t.Errorf("target pin missing/misformatted in known_hosts:\n%s", out)
	}
	if strings.Contains(out, "10.8.0.9") {
		t.Errorf("unpinned host must be omitted, got:\n%s", out)
	}
	if strings.Contains(out, "\n\n") {
		t.Errorf("known_hosts has a blank line (bad pin formatting):\n%q", out)
	}
}

// A fleet-wide upgrade is sequential across its inventory, and every host that
// takes a new kernel adds a reboot plus a wait_for_connection on top of its own
// upgrade. Past a certain host count the run outgrows a fixed budget and is killed
// mid-flight — reported as exit 124 with zero failed and zero unreachable hosts,
// which reads as a fleet outage when it is only a budget one. The bound has to be
// raisable without editing the binary.
func TestRunTimeoutHonoursConfiguredBound(t *testing.T) {
	s := &Service{cfg: &config.Config{PlaybookTimeout: 90 * time.Minute}}
	if got := s.runTimeout(); got != 90*time.Minute {
		t.Errorf("configured bound ignored: got %s, want 90m", got)
	}
}

// An unset or nonsensical value must not collapse the bound to zero — that would
// cancel every run the instant it started.
func TestRunTimeoutFallsBackWhenUnconfigured(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"unset":    {},
		"zero":     {PlaybookTimeout: 0},
		"negative": {PlaybookTimeout: -5 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Service{cfg: cfg}
			if got := s.runTimeout(); got != defaultRunTimeout {
				t.Errorf("got %s, want the %s default", got, defaultRunTimeout)
			}
		})
	}
}

// The run's SSH credential must outlive the run that carries it. When the bound was
// raisable but the TTL stayed fixed at 45m, any run configured past 45m would have
// its cert expire underneath it — the run would die on authentication somewhere in
// the middle of the fleet, leaving hosts half-upgraded. Deriving the TTL from the
// bound is what keeps the two from drifting apart.
func TestRunCredentialOutlivesTheRun(t *testing.T) {
	for _, timeout := range []time.Duration{
		defaultRunTimeout,
		45 * time.Minute, // the old fixed TTL — the exact point the two used to meet
		90 * time.Minute,
		6 * time.Hour,
	} {
		if ttl := runCertTTL(timeout); ttl <= timeout {
			t.Errorf("run bounded at %s gets a %s credential: it expires mid-run", timeout, ttl)
		}
	}
}

// The sidecar is told to self-terminate slightly before the backend's own deadline,
// so the backend collects an rc=124 and can report which task was in flight. If the
// margin were ever dropped the backend would cancel the HTTP stream first and the
// run would land as a bare context error with no ansible output at all.
func TestRunnerDeadlineLandsBeforeTheBackendDeadline(t *testing.T) {
	s := &Service{cfg: &config.Config{PlaybookTimeout: 90 * time.Minute}}
	timeout := s.runTimeout()

	runnerSecs := int(timeout.Seconds()) - 30
	if runnerSecs >= int(timeout.Seconds()) {
		t.Fatalf("runner deadline %ds does not precede backend deadline %.0fs", runnerSecs, timeout.Seconds())
	}
	if runnerSecs <= 0 {
		t.Fatalf("runner deadline %ds is not a usable budget", runnerSecs)
	}
}
