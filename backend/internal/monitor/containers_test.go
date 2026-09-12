package monitor

import (
	"strings"
	"testing"
)

// "Nothing is running" and "we were not allowed to look" must never render the
// same.
//
// Docker's socket is root-owned and every monitor probe runs WITHOUT sudo, so on
// a host whose monitor account is not in the docker group `docker ps` fails with
// a permission error. An empty list there would report a clean host — on exactly
// the machines carrying the most software, and in a product whose entire job is
// telling you what is on your fleet.
//
// This is the same failure that has cost this project real time in other forms: a
// silent empty result that looks like a good answer.
func TestParseContainersDistinguishesEmptyFromUnasked(t *testing.T) {
	cases := []struct {
		name, out, wantStatus string
		wantN                 int
	}{
		{"no runtime installed", "::NORUNTIME::\n", ContainersNoDocker, 0},
		{"installed but not permitted", "::NOACCESS::\n", ContainersNoAccess, 0},
		{"asked, and genuinely nothing running", "::OK::\n::IMAGES::\n", ContainersOK, 0},
		{"script did not run at all", "", ContainersUnreachable, 0},
		{"garbage with no marker", "bash: docker: command not found\n", ContainersUnreachable, 0},
	}
	for _, c := range cases {
		got, status, _ := parseContainers(c.out)
		if status != c.wantStatus {
			t.Errorf("%s: status = %q, want %q", c.name, status, c.wantStatus)
		}
		if len(got) != c.wantN {
			t.Errorf("%s: %d containers, want %d", c.name, len(got), c.wantN)
		}
	}
}

func TestParseContainers(t *testing.T) {
	out := "::OK::\n" +
		"abc123def456789\tnextcloud\tnextcloud:29-apache\trunning\tUp 3 days\t0.0.0.0:8080->80/tcp\n" +
		"beef00112233445\tgluetun\tqmcgaw/gluetun:latest\trunning\tUp 2 weeks\t\n" +
		"::IMAGES::\n" +
		"nextcloud:29-apache\tnextcloud@sha256:aaaa\n" +
		"qmcgaw/gluetun:latest\tqmcgaw/gluetun@sha256:bbbb\n"

	got, status, _ := parseContainers(out)
	if status != ContainersOK {
		t.Fatalf("status = %q", status)
	}
	if len(got) != 2 {
		t.Fatalf("got %d containers, want 2", len(got))
	}

	// The id is trimmed to what an operator sees in their own `docker ps`.
	if got[0].ID != "abc123def456" {
		t.Errorf("id = %q, want the 12-char form", got[0].ID)
	}
	if got[0].Name != "nextcloud" || got[0].State != "running" {
		t.Errorf("unexpected: %+v", got[0])
	}
	// The digest is the point of collecting this at all: a tag moves, so
	// "nextcloud:29-apache" does not say which one is running.
	if got[0].Digest != "sha256:aaaa" {
		t.Errorf("digest = %q, want the resolved digest", got[0].Digest)
	}
	if got[1].Digest != "sha256:bbbb" {
		t.Errorf("digest = %q", got[1].Digest)
	}
}

// A registry with a port is the case that breaks the obvious implementation.
func TestSplitImageRef(t *testing.T) {
	for _, c := range []struct{ ref, repo, tag string }{
		{"nginx", "nginx", "latest"},
		{"nginx:1.25", "nginx", "1.25"},
		{"qmcgaw/gluetun:latest", "qmcgaw/gluetun", "latest"},
		{"ghcr.io/owner/app:v2", "ghcr.io/owner/app", "v2"},
		// Splitting on the FIRST colon gives repo "registry.example.com" and tag
		// "5000/app" — wrong, and nobody notices until it is their registry.
		{"registry.example.com:5000/app", "registry.example.com:5000/app", "latest"},
		{"registry.example.com:5000/app:1.4", "registry.example.com:5000/app", "1.4"},
		// A digest-pinned reference carries no tag.
		{"nginx@sha256:abcd", "nginx", "latest"},
	} {
		repo, tag := splitImageRef(c.ref)
		if repo != c.repo || tag != c.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", c.ref, repo, tag, c.repo, c.tag)
		}
	}
}

// Six hosts on a nineteen-host fleet reported no_access, and the status said
// nothing about which of its two causes applied. They need opposite actions —
// an account missing from the socket's group is a one-line fix; a daemon that is
// not running is a different problem — so working it out meant an SSH session per
// host, which is the work this product exists to remove.
func TestTheReasonACollectionFailedIsCarriedNotDiscarded(t *testing.T) {
	cases := []struct {
		name, out, wantStatus, wantDetail string
	}{
		{
			"not in the socket's group",
			"::NOACCESS::fleet cannot use /var/run/docker.sock — it belongs to group docker; " +
				"add this account to that group (usermod -aG docker fleet) and reconnect\n",
			ContainersNoAccess,
			"usermod -aG docker fleet",
		},
		{
			"daemon not running",
			"::NOACCESS::no socket at /var/run/docker.sock — the daemon may not be running, " +
				"or may be rootless or remote (DOCKER_HOST=unset): Cannot connect\n",
			ContainersNoAccess,
			"the daemon may not be running",
		},
		{
			"daemon present but no client",
			"::NORUNTIME::a container socket exists at /var/run/docker.sock but no docker or " +
				"podman command is installed for this account\n",
			ContainersNoDocker,
			"no docker or podman command is installed",
		},
		{
			"genuinely no runtime",
			"::NORUNTIME::no container runtime is installed\n",
			ContainersNoDocker,
			"no container runtime is installed",
		},
	}
	for _, c := range cases {
		_, status, detail := parseContainers(c.out)
		if status != c.wantStatus {
			t.Errorf("%s: status = %q, want %q", c.name, status, c.wantStatus)
		}
		if !strings.Contains(detail, c.wantDetail) {
			t.Errorf("%s: detail = %q, want it to contain %q — without this an "+
				"operator has the same question they started with",
				c.name, detail, c.wantDetail)
		}
	}
}

func TestASuccessfulCollectionCarriesNoExcuse(t *testing.T) {
	// A detail on a working host would be noise shown next to a correct answer.
	_, status, detail := parseContainers("::OK::\n::IMAGES::\n")
	if status != ContainersOK || detail != "" {
		t.Errorf("status=%q detail=%q, want ok and empty", status, detail)
	}
}

// The script must actually emit what the parser reads. They are edited in
// different places and nothing else connects them: a marker that stops carrying
// its detail leaves every reason empty, and every test above still passes
// because they test the parser against hand-written strings.
func TestTheScriptEmitsDetailAlongsideEveryFailureMarker(t *testing.T) {
	for _, marker := range []string{"::NORUNTIME::", "::NOACCESS::"} {
		if !strings.Contains(containersScript, `echo "`+marker+`$_detail"`) {
			t.Errorf("the script emits %s without $_detail, so the reason never "+
				"reaches the operator", marker)
		}
	}
	if !strings.Contains(containersScript, "usermod -aG") {
		t.Error("the permission case should name the command that fixes it")
	}
}

// Six hosts on a nineteen-host fleet reported no_access — including the one
// actually called "docker". The advice was "add this account to the docker
// group", which is a root-equivalent membership nobody should have to grant just
// to SEE what is running. On this fleet the monitor account already had
// passwordless sudo on those hosts; the probe simply never used it.
func TestContainerCollectionFallsBackToPasswordlessSudo(t *testing.T) {
	// Unprivileged first: where the account IS in the group, nothing changes and
	// no sudo is invoked.
	if !strings.Contains(containersScript, `if ! $_rt ps --format '{{.ID}}' >/dev/null 2>&1; then`) {
		t.Error("the unprivileged attempt is no longer first")
	}
	if !strings.Contains(containersScript, "sudo -n $_rt ps") {
		t.Error("no sudo fallback — six hosts stay invisible over a group membership " +
			"they should not need")
	}
	// -n, or a host that would PROMPT hangs the sweep on a password nobody is
	// there to type.
	if strings.Contains(containersScript, "sudo $_rt") {
		t.Error("sudo without -n can prompt, which hangs the sweep")
	}
	// Whatever worked for the probe must be used for the real commands too,
	// or the check passes and the collection returns nothing.
	for _, cmd := range []string{"$_pre $_rt ps --no-trunc", "$_pre $_rt image inspect"} {
		if !strings.Contains(containersScript, cmd) {
			t.Errorf("%q does not carry the privilege the check established", cmd)
		}
	}
}

func TestTheNoAccessReasonMentionsBothWaysOut(t *testing.T) {
	// Group membership and NOPASSWD sudo are different trade-offs on different
	// hosts. Naming only one sends an operator to the wrong one.
	for _, want := range []string{"usermod -aG", "NOPASSWD sudo"} {
		if !strings.Contains(containersScript, want) {
			t.Errorf("the no-access reason does not mention %q", want)
		}
	}
}
