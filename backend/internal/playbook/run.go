package playbook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/credinject"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/notify"
	princ "github.com/kforbus3/Moorgate/backend/internal/principals"
	"github.com/kforbus3/Moorgate/backend/internal/sshgw"
)

const (
	// defaultRunTimeout bounds a run when FLEET_PLAYBOOK_TIMEOUT is unset or
	// unparseable. See config.PlaybookTimeout for why a large inventory outgrows it.
	defaultRunTimeout = 30 * time.Minute
	// runCertTTLMargin is how far the run credential outlives the run itself. The
	// cert only needs to outlive the run, so keep the margin tight — the run
	// credential is written to the out-of-process runner and is revoked on
	// completion, but a short TTL bounds the window if revocation hasn't yet
	// reached a host. Deriving the TTL from the run bound rather than fixing it
	// means raising the bound can't silently outlive the credential that carries
	// the run, which would strand it mid-flight with an expired cert.
	runCertTTLMargin = 15 * time.Minute
)

// runTimeout is the wall-clock bound for one run: the configured value, or the
// default when it is unset or nonsensical.
func (s *Service) runTimeout() time.Duration {
	if s.cfg != nil && s.cfg.PlaybookTimeout > 0 {
		return s.cfg.PlaybookTimeout
	}
	return defaultRunTimeout
}

// runCertTTL is the lifetime of the ephemeral credential minted for a run. It is
// derived from the run's own bound so the credential can never expire under a run
// that is still legitimately in flight.
func runCertTTL(timeout time.Duration) time.Duration {
	return timeout + runCertTTLMargin
}

// liveRun holds the in-memory, incrementally-growing output of a run in flight
// so the status endpoint can stream it to the browser by polling. On completion
// the output is persisted and the entry removed.
// maxPlaybookOutput bounds how much run output is buffered in memory and later
// persisted to the playbook_runs.output row. A chatty or malicious playbook could
// otherwise stream unbounded data and bloat both. Past the cap, output is dropped
// after a one-time truncation notice.
const maxPlaybookOutput = 4 << 20 // 4 MiB

type liveRun struct {
	mu        sync.Mutex
	buf       strings.Builder
	truncated bool
}

func (l *liveRun) append(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.truncated {
		return
	}
	if l.buf.Len()+len(s) > maxPlaybookOutput {
		if room := maxPlaybookOutput - l.buf.Len(); room > 0 {
			l.buf.WriteString(s[:room])
		}
		l.buf.WriteString("\n[output truncated: exceeded 4 MiB]\n")
		l.truncated = true
		return
	}
	l.buf.WriteString(s)
}

func (l *liveRun) snapshot() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// LiveOutput returns the current output for a running run, if it is in flight.
func (s *Service) LiveOutput(id uuid.UUID) (string, bool) {
	v, ok := s.live.Load(id)
	if !ok {
		return "", false
	}
	return v.(*liveRun).snapshot(), true
}

// runHost is one inventory entry sent to the sidecar. AuthMethod selects how the
// FINAL hop to this host authenticates: "fleet_cert" (default — the run's ephemeral
// Fleet certificate, for hosts that trust the Fleet CA) or a vaulted credential
// ("vault_ssh_key"/"vault_password") injected per-host, exactly as the terminal does,
// so appliances that don't trust the CA (routers, switches) can still be targeted.
// The jump-host hop always uses the Fleet certificate regardless.
type runHost struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	User       string `json:"user"`
	Port       int    `json:"port"`
	AuthMethod string `json:"authMethod,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"` // vault_ssh_key: the host's vaulted private key
	Password   string `json:"password,omitempty"`   // vault_password: the host's vaulted password
	// APITunnel asks the runner to open a local TCP port-forward to APIPort on this host
	// through the jump host (for RouterOS API management, where SSH exec is unusable). The
	// runner injects fleet_api_host/fleet_api_port so a community.routeros.api play reaches it.
	APITunnel bool `json:"apiTunnel,omitempty"`
	APIPort   int  `json:"apiPort,omitempty"`
}

// runRequest is the body posted to the sidecar's /run endpoint. The credential
// is ephemeral and scoped to this single run.
type runRequest struct {
	Playbook    string    `json:"playbook"`
	PrivateKey  string    `json:"privateKey"`
	Certificate string    `json:"certificate"`
	Hosts       []runHost `json:"hosts"`
	JumpHost    string    `json:"jumpHost"`
	JumpUser    string    `json:"jumpUser"`
	CheckMode   bool      `json:"checkMode"`
	Become      bool      `json:"become"`
	TimeoutSecs int       `json:"timeoutSecs"`
	// KnownHosts is an OpenSSH known_hosts file built from the backend's stored
	// host-key pins (TOFU) for the jump host and every target. The runner writes it
	// out and verifies against it (H3), instead of the old StrictHostKeyChecking=no
	// bypass. A host with no pin yet is simply absent — the runner accepts its key on
	// first contact (accept-new) and refuses any later change for the rest of the run.
	KnownHosts string `json:"knownHosts,omitempty"`
}

// hostAddress picks the address reachable through the jump host: the WireGuard
// overlay address first (as the scan path does), then the management address,
// then the hostname.
func hostAddress(h *models.Host) string {
	for _, a := range []string{h.WGAddress, h.Address, h.Hostname} {
		if strings.TrimSpace(a) != "" {
			return a
		}
	}
	return h.Hostname
}

// splitHostPort parses a "host:port" string, falling back to def when there is no
// (or an unparseable) port. Used to key the jump host's known_hosts entry.
func splitHostPort(hp string, def int) (string, int) {
	hp = strings.TrimSpace(hp)
	if hp == "" {
		return "", def
	}
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, def
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return host, def
	}
	return host, p
}

// buildKnownHosts renders an OpenSSH known_hosts file from the backend's stored
// host-key pins for the jump host and every target, keyed by the exact identity ssh
// looks a host up under (address + port, normalized the way the TOFU verifier pins
// it — see sshgw.HostKeyID). lookup returns the pinned authorized-key line and
// whether a pin exists. A host without a pin is omitted, so the runner (accept-new)
// trusts its key on first contact and refuses any later change; a host WITH a pin is
// strictly verified, which is what closes the H3 host-key-verification bypass.
func buildKnownHosts(lookup func(id string) (string, bool), jumpHost string, hosts []*models.Host) string {
	var b strings.Builder
	seen := map[string]bool{}
	add := func(addr string, port int) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		id := sshgw.HostKeyID(addr, port)
		if seen[id] {
			return
		}
		seen[id] = true
		line, ok := lookup(id)
		if !ok {
			return
		}
		line = strings.TrimRight(line, "\n")
		if line == "" {
			return
		}
		b.WriteString(id + " " + line + "\n")
	}
	jh, jp := splitHostPort(jumpHost, 22)
	add(jh, jp)
	for _, h := range hosts {
		add(hostAddress(h), h.SSHPort)
	}
	return b.String()
}

// Run executes a playbook against the given hosts, streaming output into the
// live buffer and persisting the result. It runs in its own goroutine with a
// fresh (restart-independent) context; the in-memory live buffer does not
// survive a restart, but FailStalePlaybookRuns reconciles the DB row.
func (s *Service) Run(parent context.Context, runID uuid.UUID, content string, hosts []*models.Host, checkMode bool) {
	timeout := s.runTimeout()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	live := &liveRun{}
	s.live.Store(runID, live)
	defer s.live.Delete(runID)

	if err := s.store.StartPlaybookRun(ctx, runID); err != nil {
		s.log.Error("playbook run: mark running", "err", err)
	}

	fail := func(msg string) {
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
		defer fcancel()
		out := live.snapshot()
		if out != "" {
			out += "\n"
		}
		out += msg
		_ = s.store.CompletePlaybookRun(fctx, runID, "failed", out, nil, msg)
	}

	base, err := s.runnerURL()
	if err != nil {
		fail(err.Error())
		return
	}

	// Mint an ephemeral key + cert for this run, scoped to exactly the target
	// hosts. The runner writes this private key to its own filesystem to drive
	// ansible, so a crafted playbook (e.g. a local_action reading the key) could
	// exfiltrate it; binding the cert to this run's target-host principals means a
	// leaked key only reaches hosts the run was already authorized for. "fleet"
	// authenticates the jump-host hop (the runner reaches every host via ProxyJump);
	// once hosts are locked down they trust only their scoped principal, so the run
	// cert cannot reach a non-target host even though it carries "fleet".
	runPrincipals := []string{princ.Global}
	for _, h := range hosts {
		runPrincipals = append(runPrincipals, princ.Host(h.ID))
	}
	mat, err := s.issuer.SystemKeyMaterial(ctx, runPrincipals, runCertTTL(timeout))
	if err != nil {
		fail(fmt.Sprintf("could not issue run credential: %v", err))
		return
	}
	// Revoke the run credential once the run finishes, so a key exfiltrated from
	// the runner stops working promptly (the KRL converges to hosts via the
	// periodic reconcile). Host scoping already bounds it to this run's targets.
	defer func() {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
		defer rcancel()
		if err := s.store.RevokeCertificate(rctx, mat.Serial, "playbook_run_complete"); err != nil {
			s.log.Warn("revoke run credential", "err", err, "serial", mat.Serial)
		}
	}()

	rhosts := make([]runHost, 0, len(hosts))
	for _, h := range hosts {
		rh := runHost{Name: h.Hostname, Address: hostAddress(h), User: h.SSHUser, Port: h.SSHPort, AuthMethod: "fleet_cert"}
		// RouterOS API device: have the runner tunnel its API port through the jump.
		if p := h.RouterOSAPIPort(); p > 0 {
			rh.APITunnel, rh.APIPort = true, p
		}
		// A vaulted host doesn't trust the Fleet CA, so authenticate its final hop with
		// the same injected credential the terminal uses. Open-policy secrets only; the
		// key/password is sent to the runner scoped to this run (see the security note
		// on the run credential above — the same exfiltration caveat applies).
		if h.AuthMethod == "vault_password" || h.AuthMethod == "vault_ssh_key" {
			key, kerr := s.cfg.VaultKey()
			if kerr != nil {
				fail(fmt.Sprintf("host %s: %v", h.Hostname, kerr))
				return
			}
			vmat, merr := credinject.MaterialForSystem(ctx, s.store, key, s.cfg.ExtSecret(), h)
			if merr != nil {
				fail(fmt.Sprintf("host %s: %v", h.Hostname, merr))
				return
			}
			if vmat != nil {
				rh.AuthMethod, rh.User, rh.PrivateKey, rh.Password = vmat.Method, vmat.LoginUser, vmat.PrivateKeyPEM, vmat.Password
			}
		}
		rhosts = append(rhosts, rh)
	}

	reqBody := runRequest{
		Playbook:    content,
		PrivateKey:  string(mat.PrivateKeyPEM),
		Certificate: string(mat.CertAuthorizedKey),
		Hosts:       rhosts,
		JumpHost:    s.cfg.JumpHost,
		JumpUser:    s.cfg.JumpUser,
		CheckMode:   checkMode,
		Become:      true,
		TimeoutSecs: int(timeout.Seconds()) - 30,
		// Host-key pins for the jump host + every target, so the runner verifies host
		// keys against the product's TOFU pins instead of disabling the check (H3).
		KnownHosts: buildKnownHosts(func(id string) (string, bool) {
			pin, ok, err := s.store.GetHostKey(ctx, id)
			if err != nil || !ok {
				return "", false
			}
			return pin.KeyLine, true
		}, s.cfg.JumpHost, hosts),
	}
	//nolint:gosec // PrivateKey is the per-run vault SSH key deliberately sent to the ansible-runner (internal network, token-authenticated) so it can drive the run
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/run", bytes.NewReader(body))
	if err != nil {
		fail(err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Authenticate to the runner with the shared secret so nothing else on the
	// container network can submit a playbook for execution (M2). Empty token keeps
	// the header off for dev/back-compat, where the runner also allows unauthenticated.
	if s.cfg.AnsibleRunnerToken != "" {
		req.Header.Set("X-Runner-Token", s.cfg.AnsibleRunnerToken)
	}

	// No client timeout on the streaming response; the context bounds the run.
	streamClient := &http.Client{}
	resp, err := streamClient.Do(req)
	if err != nil {
		fail(fmt.Sprintf("ansible runner unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		fail(fmt.Sprintf("ansible runner error (%d): %s", resp.StatusCode, strings.TrimSpace(string(buf[:n]))))
		return
	}

	// The sidecar streams NDJSON: {"line":"..."} for each output line, then a
	// final {"done":true,"rc":N}.
	var exitCode *int
	scanner := bufio.NewScanner(resp.Body)
	// Allow a single NDJSON frame up to the whole output budget: a long ansible
	// line (e.g. a big diff) must not trip bufio.ErrTooLong and abort the loop
	// before the terminal {"done"} frame, which would mislabel the run as never
	// having completed.
	scanner.Buffer(make([]byte, 0, 64*1024), maxPlaybookOutput)
	for scanner.Scan() {
		var ev struct {
			Line  string `json:"line"`
			Done  bool   `json:"done"`
			RC    int    `json:"rc"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue // ignore malformed frames
		}
		if ev.Done {
			rc := ev.RC
			exitCode = &rc
			if ev.Error != "" {
				live.append(ev.Error + "\n")
			}
			break
		}
		live.append(ev.Line + "\n")
	}
	if err := scanner.Err(); err != nil {
		live.append(fmt.Sprintf("\n[stream error: %v]\n", err))
	}

	status := "completed"
	errMsg := ""
	if exitCode == nil {
		status = "failed"
		errMsg = "run did not report completion"
		if ctx.Err() != nil {
			errMsg = fmt.Sprintf("run exceeded the %s timeout", timeout)
		}
	} else if *exitCode != 0 {
		status = "failed"
		errMsg = fmt.Sprintf("ansible-playbook exited %d", *exitCode)
	}

	pctx, pcancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer pcancel()
	if err := s.store.CompletePlaybookRun(pctx, runID, status, live.snapshot(), exitCode, errMsg); err != nil {
		s.log.Error("playbook run: persist result", "err", err, "run", runID)
	}

	if status == "failed" && s.nfy != nil {
		names := make([]string, 0, len(hosts))
		for _, h := range hosts {
			names = append(names, h.Hostname)
		}
		s.nfy.Notify(context.WithoutCancel(parent), notify.Event{
			Type: notify.EventPlaybookFailed, Severity: notify.SeverityError,
			Title: "Playbook run failed",
			Body:  fmt.Sprintf("A playbook run against %s failed: %s", strings.Join(names, ", "), errMsg),
		})
	}
}
