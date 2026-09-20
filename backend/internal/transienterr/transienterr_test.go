package transienterr

import (
	"os/exec"
	"strings"
	"testing"
)

// The message that actually halted a production rollout.
func TestTheRateLimitThatHaltedARollout(t *testing.T) {
	const real = `f6a4c3e338ed Download complete 0B
09c32a2c2d0b Downloading 6.158MB
1fd3dd5e1b01 Downloading 0B
toomanyrequests: retry-after: 548.005µs, allowed: 44000/minute

[exit code 1]`
	if !Is(real) {
		t.Error("a registry rate limit asking to be retried in 548 MICROseconds was " +
			"treated as a permanent failure; that is what ended the llama.cpp rollout")
	}
}

func TestPermanentFailuresAreNotRetried(t *testing.T) {
	// Every one of these is an answer. Asking again produces the same answer
	// later, and buries it under two more copies of itself.
	final := []string{
		"unauthorized: authentication required",
		"denied: requested access to the resource is denied",
		"manifest unknown: manifest unknown",
		"pull access denied for private/thing, repository does not exist",
		"no such image: ghcr.io/nope/nope:v1",
		"yaml: line 12: did not find expected key",
		"service \"web\" has neither an image nor a build context specified",
		"dependency failed to start: container keycloak-db is unhealthy",
		"Error response from daemon: no such container",
		"invalid reference format",
	}
	for _, m := range final {
		if Is(m) {
			t.Errorf("would retry a permanent failure: %q", m)
		}
	}
}

func TestTransientFailuresAreRetried(t *testing.T) {
	transient := []string{
		"failed to do request: Head \"https://registry-1.docker.io/v2/\": net/http: TLS handshake timeout",
		"dial tcp 1.2.3.4:443: i/o timeout",
		"read tcp 10.10.0.9:52134->104.18.0.1:443: read: connection reset by peer",
		"failed to copy: httpReadSeeker: failed open: unexpected EOF",
		"received unexpected HTTP status: 503 Service Unavailable",
		"error pulling image configuration: download failed after attempts=1",
		"Get \"https://ghcr.io/v2/\": context deadline exceeded",
		"toomanyrequests: You have reached your pull rate limit.",
	}
	for _, m := range transient {
		if !Is(m) {
			t.Errorf("would NOT retry a transient failure: %q", m)
		}
	}
}

// The tokens are compiled into a shell `case` statement. A glob character in one
// would silently widen the pattern -- "*" matching everything would make every
// failure retryable, which is the opposite of the point.
func TestTokensAreShellSafe(t *testing.T) {
	for _, tok := range Tokens {
		if tok == "" {
			t.Error("empty token: as a shell pattern it matches every failure")
			continue
		}
		if strings.ToLower(tok) != tok {
			t.Errorf("token %q is not lowercase; the shell subject is lowercased before matching", tok)
		}
		if i := strings.IndexAny(tok, "*?[]|()\\\"'`$&;<>"); i >= 0 {
			t.Errorf("token %q contains shell pattern or quoting character %q", tok, tok[i])
		}
	}
}

func TestShellCaseCoversEveryToken(t *testing.T) {
	pat := ShellCase()
	for _, tok := range Tokens {
		if !strings.Contains(pat, "*'"+tok+"'*") {
			t.Errorf("token %q is missing from the shell case arm", tok)
		}
	}
	if strings.HasPrefix(pat, "|") || strings.HasSuffix(pat, "|") {
		t.Errorf("empty alternative in case pattern %q matches the empty string", pat)
	}
}

// The pattern list is compiled into a `case` arm in a real shell script. A token
// with a space in it, left unquoted, is not a loose pattern -- it is a syntax
// error that kills the entire deploy before anything is pulled. So the rendered
// arm is run.
func TestShellCaseIsValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	script := "set -eu\ncase \"$1\" in\n" + ShellCase() + ") echo RETRY ;;\n*) echo FINAL ;;\nesac\n"
	for _, tc := range []struct {
		subject string
		want    string
	}{
		{"toomanyrequests: retry-after: 548.005us, allowed: 44000/minute", "RETRY"},
		{"received unexpected http status: 503 service unavailable", "RETRY"},
		{"net/http: tls handshake timeout", "RETRY"},
		{"unauthorized: authentication required", "FINAL"},
		{"manifest unknown", "FINAL"},
	} {
		out, err := exec.Command("sh", "-c", script, "sh", tc.subject).CombinedOutput()
		if err != nil {
			t.Fatalf("the rendered case arm is not valid shell: %v\n%s\n--- script ---\n%s",
				err, out, script)
		}
		if got := strings.TrimSpace(string(out)); got != tc.want {
			t.Errorf("%q classified %s, want %s", tc.subject, got, tc.want)
		}
	}
}
