package winscript

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/winrm"
)

const (
	// runCertTTL is the jump-hop signer lifetime. The per-host WinRM timeout is
	// configurable in Settings (Store.ScriptTimeout); the whole-run timeout is
	// derived from it and the host/batch count at launch.
	runCertTTL = 45 * time.Minute

	// winScriptConcurrency bounds how many hosts run at once. Each host opens one
	// jump-host SSH connection (for the WinRM tunnel), so this stays well under the
	// jump's sshd MaxStartups, matching the monitor's pool.
	winScriptConcurrency = 6

	// maxScriptOutput caps the combined per-host output buffered in memory and
	// persisted to winscript_runs.output, so a chatty/hostile host can't exhaust it.
	maxScriptOutput = 4 << 20 // 4 MiB
)

// liveRun holds the incrementally-growing, size-capped output of a run in flight so
// the status endpoint can stream it by polling. Appends are atomic per host section.
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
	if l.buf.Len()+len(s) > maxScriptOutput {
		if room := maxScriptOutput - l.buf.Len(); room > 0 {
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

// firstWinAddr picks the address reachable through the jump host: the WireGuard
// overlay address first, then the management address, then the hostname.
func firstWinAddr(h *models.Host) string {
	for _, a := range []string{h.WGAddress, h.Address, h.Hostname} {
		if strings.TrimSpace(a) != "" {
			return a
		}
	}
	return h.Hostname
}

// Run executes a PowerShell script on the given Windows hosts, streaming per-host
// output into the live buffer and persisting the result. It runs in its own
// goroutine with a fresh (restart-independent) context; the in-memory buffer does
// not survive a restart, but FailStaleWinScriptRuns reconciles the DB row.
//
// userID is the requester: their identity gates each host's vaulted credential, so a
// check-out/approval-gated credential is only used while they hold an active check-out.
// A nil userID means a scheduled/unattended run, which — having no interactive
// check-out — uses only open-policy credentials (like the monitor's fact collection).
func (s *Service) Run(runID uuid.UUID, content string, hosts []*models.Host, userID *uuid.UUID) {
	// Per-host WinRM timeout is operator-configurable in Settings. The whole-run
	// timeout scales with how many concurrency-bounded batches the hosts take, plus
	// a buffer, so a large fleet isn't cut off mid-run.
	perHost := s.store.ScriptTimeout(context.Background())
	batches := (len(hosts) + winScriptConcurrency - 1) / winScriptConcurrency
	if batches < 1 {
		batches = 1
	}
	runTimeout := perHost*time.Duration(batches) + 5*time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	live := &liveRun{}
	s.live.Store(runID, live)
	defer s.live.Delete(runID)

	if err := s.store.StartWinScriptRun(context.Background(), runID); err != nil {
		s.log.Error("winscript run: mark running", "err", err)
	}

	complete := func(status, errMsg string, exitCode *int) {
		pctx, pcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer pcancel()
		if err := s.store.CompleteWinScriptRun(pctx, runID, status, live.snapshot(), exitCode, errMsg); err != nil {
			s.log.Error("winscript run: persist result", "err", err, "run", runID)
		}
	}

	vaultKey, err := s.cfg.VaultKey()
	if err != nil {
		live.append("credential vault is not configured: " + err.Error() + "\n")
		complete("failed", "vault not configured", nil)
		return
	}

	var (
		mu        sync.Mutex
		anyFail   bool
		worstCode int
		sem       = make(chan struct{}, winScriptConcurrency)
		wg        sync.WaitGroup
	)
	for i := range hosts {
		h := hosts[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out, code, failed := s.runOne(ctx, vaultKey, content, h, userID, perHost)
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
		status, errMsg = "failed", "one or more hosts failed"
	}
	if ctx.Err() != nil {
		status, errMsg = "failed", fmt.Sprintf("run exceeded the %s timeout", runTimeout)
	}
	exitCode := worstCode
	complete(status, errMsg, &exitCode)

	if status == "failed" && s.nfy != nil {
		names := make([]string, 0, len(hosts))
		for _, h := range hosts {
			names = append(names, h.Hostname)
		}
		s.nfy.Notify(context.Background(), notify.Event{
			Type: notify.EventScriptFailed, Severity: notify.SeverityError,
			Title: "PowerShell script run failed",
			Body:  fmt.Sprintf("A PowerShell run against %s failed: %s", strings.Join(names, ", "), errMsg),
		})
	}
}

// runOne executes the script on a single host and returns its captured output, exit
// code, and whether it failed. It opens exactly one jump-host connection and reuses it
// for the WinRM tunnel (same per-host cost as a monitor probe). A nil userID uses the
// open-policy credential path (scheduled/unattended runs).
func (s *Service) runOne(ctx context.Context, vaultKey []byte, content string, h *models.Host, userID *uuid.UUID, perHost time.Duration) (string, int, bool) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), runCertTTL)
	if err != nil {
		return "could not issue jump credential: " + err.Error(), -1, true
	}
	jump, err := s.gw.DialJumpWithSigner(ctx, signer)
	if err != nil {
		return "jump host unreachable: " + err.Error(), -1, true
	}
	defer jump.Close()

	var user, pass string
	if userID == nil {
		// Scheduled/unattended: only open-policy credentials, no interactive check-out.
		user, pass, err = credinject.PasswordForSystem(ctx, s.store, vaultKey, h)
	} else {
		user, pass, err = credinject.PasswordFor(ctx, s.store, vaultKey, h, *userID)
	}
	if err != nil {
		return "credential unavailable: " + err.Error(), -1, true
	}

	dial := func(_ /*network*/, addr string) (net.Conn, error) { return jump.DialContext(ctx, "tcp", addr) }
	stdout, stderr, code, err := winrm.RunScript(ctx, dial, firstWinAddr(h), user, pass, s.cfg.RDPWinRMPorts, content, perHost)
	if err != nil {
		return "winrm error: " + err.Error(), -1, true
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(stdout, "\n"))
	if strings.TrimSpace(stderr) != "" {
		b.WriteString("\n[stderr]\n")
		b.WriteString(strings.TrimRight(stderr, "\n"))
	}
	b.WriteString(fmt.Sprintf("\n[exit code %d]", code))
	return b.String(), code, code != 0
}
