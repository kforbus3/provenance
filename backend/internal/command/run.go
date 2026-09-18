package command

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/commandpolicy"
	"github.com/kforbus3/provenance/backend/internal/credinject"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/notify"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
)

const (
	// runCertTTL is the jump-hop signer lifetime.
	runCertTTL = 45 * time.Minute
	// commandConcurrency bounds how many hosts run at once — one jump-host SSH
	// connection each, matching the monitor/winscript pools (under sshd MaxStartups).
	commandConcurrency = 6
	// perHostTimeout caps a single host's command; ad-hoc commands should be quick.
	perHostTimeout = 10 * time.Minute
	// maxCommandOutput caps the combined output buffered/persisted, so a chatty or
	// hostile host can't exhaust memory.
	maxCommandOutput = 4 << 20 // 4 MiB
)

// liveRun holds the incrementally-growing, size-capped output of a run in flight.
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
	if l.buf.Len()+len(s) > maxCommandOutput {
		if room := maxCommandOutput - l.buf.Len(); room > 0 {
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

// Run executes the command on every host, streaming per-host output into the live
// buffer and persisting the aggregate. It runs in its own goroutine with a fresh
// (restart-independent) context; FailStaleCommandRuns reconciles the DB row if the
// instance dies mid-run.
//
// sudo carries the requester's Host.Sudo tier. It is NOT a convenience flag: a run
// dials the same privileged account a terminal does, so without it a user denied
// Host.Sudo would get through the command runner exactly the root shell the
// permission is there to withhold. False lands the run in the host's login-only
// account, where `sudo` in the command itself fails as it should.
func (s *Service) Run(parent context.Context, runID uuid.UUID, command string, hosts []*models.Host, userID uuid.UUID, username string, sudo bool) {
	batches := (len(hosts) + commandConcurrency - 1) / commandConcurrency
	if batches < 1 {
		batches = 1
	}
	runTimeout := perHostTimeout*time.Duration(batches) + 2*time.Minute
	ctx, cancel := context.WithTimeout(parent, runTimeout)
	defer cancel()

	live := &liveRun{}
	s.live.Store(runID, live)
	defer s.live.Delete(runID)

	if err := s.store.StartCommandRun(ctx, runID); err != nil {
		s.log.Error("command run: mark running", "err", err)
	}

	var (
		mu        sync.Mutex
		anyFail   bool
		worstCode int
		sem       = make(chan struct{}, commandConcurrency)
		wg        sync.WaitGroup
	)
	for i := range hosts {
		h := hosts[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out, code, failed := s.runOne(ctx, command, h, userID, username, sudo)
			live.append(fmt.Sprintf("===== %s =====\n%s\n", h.Hostname, out))
			mu.Lock()
			if failed {
				anyFail = true
			}
			if code > worstCode {
				worstCode = code
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	status, errMsg := "completed", ""
	if anyFail {
		status, errMsg = "failed", "one or more hosts failed or were blocked by policy"
	}
	if ctx.Err() != nil {
		status, errMsg = "failed", fmt.Sprintf("run exceeded the %s timeout", runTimeout)
	}
	exitCode := worstCode
	// Detach from the run-timeout ctx (it may already be Done) but keep request
	// values so the final persist still runs under the caller's tenant scope.
	pctx, pcancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer pcancel()
	if err := s.store.CompleteCommandRun(pctx, runID, status, live.snapshot(), &exitCode, errMsg); err != nil {
		s.log.Error("command run: persist result", "err", err, "run", runID)
	}
}

// runOne evaluates the command against the host's command-control policy, then (if
// allowed) runs it over one jump-host SSH connection, returning the captured output,
// exit code, and whether it failed.
func (s *Service) runOne(ctx context.Context, command string, h *models.Host, userID uuid.UUID, username string, sudo bool) (string, int, bool) {
	// Command-control policy: the same governance as an interactive session.
	if out, code, failed, handled := s.applyPolicy(ctx, command, h, userID, username); handled {
		return out, code, failed
	}

	return s.execOn(ctx, command, h, sudo, userID)
}

// RunScript executes a script on a host for a PRODUCT feature -- a stack deploy,
// not a command somebody typed -- and deliberately skips the command-control
// policy.
//
// That policy governs what an operator may run interactively. Applying it here
// would let a rule written to stop a human doing something dangerous silently
// break a deployment instead, with the failure appearing as a stack that will not
// come up rather than as a refused command. The governance that belongs on a
// deploy is approval and rollout staging, which sit above this.
//
// Always the privileged tier: bringing a stack up needs the Docker socket.
func (s *Service) RunScript(ctx context.Context, script string, h *models.Host) (string, int, bool) {
	return s.execOn(ctx, script, h, true, uuid.Nil)
}

func (s *Service) execOn(ctx context.Context, command string, h *models.Host, sudo bool, userID uuid.UUID) (string, int, bool) {
	conn, derr := s.connect(ctx, h, sudo, userID)
	if derr != nil {
		return derr.Error(), -1, true
	}
	defer conn.Close()

	sess, serr := conn.Client.NewSession()
	if serr != nil {
		return "session: " + serr.Error(), -1, true
	}
	defer sess.Close()

	var buf cappedBuffer
	sess.Stdout = &buf
	sess.Stderr = &buf

	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return buf.String() + "\n[timed out]", -1, true
	case rerr := <-done:
		code := 0
		if rerr != nil {
			var ee *ssh.ExitError
			if errors.As(rerr, &ee) {
				code = ee.ExitStatus()
			} else {
				return buf.String() + "\n[error: " + rerr.Error() + "]", -1, true
			}
		}
		return buf.String() + fmt.Sprintf("\n[exit code %d]", code), code, code != 0
	}
}

// connect opens the SSH connection for a run, by whichever means the host
// actually authenticates.
//
// This used to be cert-only, and that made "Run command" quietly unusable for a
// whole class of host. Anything with auth_method vault_password or vault_ssh_key
// — in practice the network gear, because a switch will never trust our CA —
// failed here with "unable to authenticate, attempted methods [none publickey]":
// the credential was sitting in Provenance's vault and this path never asked for
// it. The terminal and the playbook runner both inject, so the same device was
// reachable from one page of the same product and unreachable from another, with
// an error that pointed at the device rather than at us.
//
// The requester's ID is passed through so a credential with a check-out policy is
// only injected while that person holds an active check-out — the rule the
// terminal enforces. A product-driven script (a stack deploy) has no requester
// and takes the system path, like the monitor.
func (s *Service) connect(ctx context.Context, h *models.Host, sudo bool, userID uuid.UUID) (*sshgw.Conn, error) {
	if needsInjection(h) {
		key, kerr := s.cfg.VaultKey()
		if kerr != nil {
			return nil, fmt.Errorf("credential injection failed: %w", kerr)
		}
		var (
			inj  *credinject.Injection
			ierr error
		)
		if userID == uuid.Nil {
			inj, ierr = credinject.ForSystem(ctx, s.store, key, s.cfg.ExtSecret(), h)
		} else {
			inj, ierr = credinject.For(ctx, s.store, key, s.cfg.ExtSecret(), h, userID)
		}
		if ierr != nil {
			return nil, fmt.Errorf("credential injection failed: %w", ierr)
		}
		if inj != nil {
			// The credential names the account, so the Host.Sudo tier has nothing to
			// select between: there is no "-login" companion account on a switch.
			// This is what the terminal does once injection applies.
			conn, derr := s.dialAuth(ctx, h, inj)
			if derr != nil {
				return nil, fmt.Errorf("host unreachable: %w", derr)
			}
			return conn, nil
		}
	}

	// Same privilege tier as a terminal: Host.Sudo lands in the privileged account,
	// everyone else in the host's login-only account. The jump hop always uses the
	// privileged system principals — the jump host trusts only "fleet" — while the
	// host hop carries the tier's principals, so sshd, not just this code, decides
	// which account opens.
	jumpSigner, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), runCertTTL)
	if err != nil {
		return nil, fmt.Errorf("could not issue jump credential: %w", err)
	}
	// Privileged runs present the same certificate to both hops; the login-only tier
	// needs its own, since its principals are not trusted by the jump host.
	loginUser, hostSigner := h.SSHUser, jumpSigner
	if !sudo {
		loginUser = h.SSHUser + "-login"
		if hostSigner, err = s.issuer.SystemSigner(ctx, s.issuer.SystemHostLoginPrincipals(h.ID), runCertTTL); err != nil {
			return nil, fmt.Errorf("could not issue host credential: %w", err)
		}
	}
	conn, derr := s.dial(ctx, jumpSigner, hostSigner, h, loginUser)
	if derr != nil {
		return nil, fmt.Errorf("host unreachable: %w", derr)
	}
	return conn, nil
}

// needsInjection says whether a host authenticates with something out of the
// vault rather than a certificate Provenance issues itself. Written as "not a
// certificate" rather than a list of vault methods so a method added later is
// treated as needing a credential — the safe direction, since the alternative is
// silently dialling with a certificate the host was never going to accept.
func needsInjection(h *models.Host) bool {
	return h.AuthMethod != "" && h.AuthMethod != "prov_cert"
}

// dialAuth opens a connection using an injected credential, trying the same
// address candidates as the certificate path.
func (s *Service) dialAuth(ctx context.Context, h *models.Host, inj *credinject.Injection) (*sshgw.Conn, error) {
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		c, derr := s.gw.DialSystemAuthViaJump(ctx, h.ID, addr, h.SSHPort, inj.LoginUser, inj.Auth)
		if derr == nil {
			return c, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable address")
	}
	return nil, lastErr
}

// dial opens a connection to the host (WireGuard overlay first, then management
// address / hostname), like the scan/support paths. loginUser names the account —
// the privileged one or the host's login-only one — and hostSigner carries the
// matching principals.
func (s *Service) dial(ctx context.Context, jumpSigner, hostSigner ssh.Signer, h *models.Host, loginUser string) (*sshgw.Conn, error) {
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		c, derr := s.gw.DialWithSigners(ctx, jumpSigner, hostSigner, addr, h.SSHPort, loginUser)
		if derr == nil {
			return c, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return nil, lastErr
}

// cappedBuffer accumulates command output up to maxCommandOutput, silently
// dropping the excess while still reporting full writes so the SSH copy never errors.
type cappedBuffer struct{ b strings.Builder }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxCommandOutput - c.b.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		c.b.Write(p[:room])
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.b.String() }

// applyPolicy evaluates the command against the host's rules. handled=true means a
// policy action (block, or approval without a waiver) short-circuited execution;
// the returned output/code/failed describe that outcome. handled=false means the
// command may run (no match, a flag rule, or an approval rule with an active waiver).
func (s *Service) applyPolicy(ctx context.Context, command string, h *models.Host, userID uuid.UUID, username string) (string, int, bool, bool) {
	specs, err := s.rulesForHost(ctx, h.ID)
	if err != nil || len(specs) == 0 {
		return "", 0, false, false
	}
	rule := commandpolicy.Evaluate(commandpolicy.Compile(specs), command)
	if rule == nil {
		return "", 0, false, false
	}
	switch rule.Action {
	case "flag":
		s.audit(userID, username, "command.flagged", h, rule.Name, command)
		s.notify(notify.EventCommandFlagged, notify.SeverityWarning, "Privileged command run",
			username+" ran a flagged command on "+h.Hostname+": "+command)
		return "", 0, false, false // allow
	case "block":
		s.audit(userID, username, "command.blocked", h, rule.Name, command)
		s.notify(notify.EventCommandBlocked, notify.SeverityWarning, "Command blocked by policy",
			username+" was blocked on "+h.Hostname+" ("+rule.Name+"): "+command)
		return "[blocked by command policy: " + rule.Name + "]", -1, true, true
	case "approval":
		ruleID := rule.ID
		if ok, _ := s.store.ActiveWaiver(ctx, userID, h.ID, &ruleID); ok {
			s.audit(userID, username, "command.approved_run", h, rule.Name, command)
			return "", 0, false, false // waiver held: allow
		}
		_, _ = s.store.CreateCommandApproval(ctx, &ruleID, userID, username, &h.ID, h.Hostname, command)
		s.audit(userID, username, "command.approval_requested", h, rule.Name, command)
		s.notify(notify.EventCommandApproval, notify.SeverityWarning, "Command awaiting approval",
			username+" requested approval to run on "+h.Hostname+" ("+rule.Name+"): "+command)
		return "[requires approval (" + rule.Name + "): a request was submitted. Once approved, run it again.]", -1, true, true
	}
	return "", 0, false, false
}

// rulesForHost converts the store rules to commandpolicy specs.
func (s *Service) rulesForHost(ctx context.Context, hostID uuid.UUID) ([]commandpolicy.Spec, error) {
	rules, err := s.store.RulesForHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	specs := make([]commandpolicy.Spec, 0, len(rules))
	for _, r := range rules {
		specs = append(specs, commandpolicy.Spec{ID: r.ID, Name: r.Name, Action: r.Action, Pattern: r.Pattern})
	}
	return specs, nil
}

func (s *Service) audit(userID uuid.UUID, username, action string, h *models.Host, rule, command string) {
	uid := userID
	_, _ = s.store.AppendAudit(context.Background(), models.AuditEvent{
		ActorID: &uid, ActorName: username, Action: action,
		TargetKind: "host", TargetID: h.ID.String(),
		Detail: map[string]any{"rule": rule, "command": command, "hostname": h.Hostname, "adhoc": true},
	})
}

func (s *Service) notify(typ string, sev notify.Severity, title, body string) {
	if s.nfy != nil {
		s.nfy.Notify(context.Background(), notify.Event{Type: typ, Severity: sev, Title: title, Body: body})
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
