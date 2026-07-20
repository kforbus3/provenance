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

	"github.com/fleet-terminal/backend/internal/commandpolicy"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/sshgw"
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
func (s *Service) Run(runID uuid.UUID, command string, hosts []*models.Host, userID uuid.UUID, username string) {
	batches := (len(hosts) + commandConcurrency - 1) / commandConcurrency
	if batches < 1 {
		batches = 1
	}
	runTimeout := perHostTimeout*time.Duration(batches) + 2*time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	live := &liveRun{}
	s.live.Store(runID, live)
	defer s.live.Delete(runID)

	if err := s.store.StartCommandRun(context.Background(), runID); err != nil {
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
			out, code, failed := s.runOne(ctx, command, h, userID, username)
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
	pctx, pcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer pcancel()
	if err := s.store.CompleteCommandRun(pctx, runID, status, live.snapshot(), &exitCode, errMsg); err != nil {
		s.log.Error("command run: persist result", "err", err, "run", runID)
	}
}

// runOne evaluates the command against the host's command-control policy, then (if
// allowed) runs it over one jump-host SSH connection, returning the captured output,
// exit code, and whether it failed.
func (s *Service) runOne(ctx context.Context, command string, h *models.Host, userID uuid.UUID, username string) (string, int, bool) {
	// Command-control policy: the same governance as an interactive session.
	if out, code, failed, handled := s.applyPolicy(ctx, command, h, userID, username); handled {
		return out, code, failed
	}

	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), runCertTTL)
	if err != nil {
		return "could not issue jump credential: " + err.Error(), -1, true
	}
	conn, derr := s.dial(ctx, signer, h)
	if derr != nil {
		return "host unreachable: " + derr.Error(), -1, true
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

// dial opens a privileged connection to the host (WireGuard overlay first, then
// management address / hostname), like the scan/support paths.
func (s *Service) dial(ctx context.Context, signer ssh.Signer, h *models.Host) (*sshgw.Conn, error) {
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		c, derr := s.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
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
