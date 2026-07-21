package vault

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

// Notifier is the subset of the notification service the rotator needs.
type Notifier interface {
	Notify(ctx context.Context, ev notify.Event)
}

// Rotator performs unattended, scheduled rotation of vaulted password credentials.
// It reaches each credential's host through the jump hop with a short-lived SYSTEM
// certificate (no user session), changes the password, verifies it, and stores the
// new sealed version — the same change-and-verify contract as the on-demand rotate
// endpoint, minus the human.
type Rotator struct {
	store  *store.Store
	gw     *sshgw.Gateway
	cfg    *config.Config
	log    *slog.Logger
	notify Notifier
}

// NewRotator builds a Rotator.
func NewRotator(st *store.Store, gw *sshgw.Gateway, cfg *config.Config, log *slog.Logger, n Notifier) *Rotator {
	return &Rotator{store: st, gw: gw, cfg: cfg, log: log, notify: n}
}

// RunDue rotates every credential whose scheduled rotation is due, and returns how
// many succeeded. ctx must be RLS-bypass so due credentials across all tenants are
// visible; each version write inherits the credential's own tenant. A failure on one
// credential never aborts the rest.
func (rt *Rotator) RunDue(ctx context.Context) (int, error) {
	due, err := rt.store.DueVaultRotations(ctx, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	rotated := 0
	for i := range due {
		if err := rt.rotateOne(ctx, due[i]); err != nil {
			rt.log.Warn("vault: scheduled rotation failed", "credential", due[i].Name, "err", err)
			continue
		}
		rotated++
	}
	return rotated, nil
}

func (rt *Rotator) rotateOne(ctx context.Context, sec models.VaultSecret) error {
	if sec.Type != "password" {
		return fmt.Errorf("not a password credential")
	}
	hosts, err := rt.store.HostsUsingCredential(ctx, sec.ID)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		// Nothing to rotate against. Push the schedule forward so we don't re-check
		// every cycle, and surface it once.
		_ = rt.store.MarkVaultRotated(ctx, sec.ID, time.Now().UTC())
		rt.audit(ctx, "credential.rotate_skipped", sec, "", "no host attached")
		return fmt.Errorf("no host attached")
	}
	host := &hosts[0]

	key, err := rt.cfg.VaultKey()
	if err != nil {
		return err
	}
	sealed, err := rt.store.GetVaultSecretSealed(ctx, sec.ID)
	if err != nil {
		return err
	}
	oldPw, err := secretbox.Open(key, sealed)
	if err != nil {
		return err
	}
	loginUser := sec.Username
	if loginUser == "" {
		loginUser = host.SSHUser
	}
	newPw := randomPassword()
	sealedNew, err := secretbox.Seal(key, []byte(newPw))
	if err != nil {
		return err
	}

	// Store the new value first (vault current = new), then change on the host with
	// the OLD password. If the host change fails, revert so the vault matches the host.
	if _, err := rt.store.AddVaultSecretVersion(ctx, sec.ID, sealedNew, uuid.Nil); err != nil {
		return err
	}
	verified, cerr := changePasswordOnHost(host, loginUser, string(oldPw), newPw,
		func(addr, password string) (*sshgw.Conn, error) {
			return rt.gw.DialSystemPasswordViaJump(ctx, host.ID, addr, host.SSHPort, loginUser, password)
		})
	if cerr != nil {
		if sealedOld, e := secretbox.Seal(key, oldPw); e == nil {
			_, _ = rt.store.AddVaultSecretVersion(ctx, sec.ID, sealedOld, uuid.Nil)
		}
		// Back off: retry at the next scheduled time, not every check cycle.
		_ = rt.store.DeferVaultRotation(ctx, sec.ID)
		rt.audit(ctx, "credential.rotate_failed", sec, host.Hostname, cerr.Error())
		rt.notifyEv(ctx, notify.EventCredentialRotateFailed, notify.SeverityError,
			"Credential auto-rotation failed",
			fmt.Sprintf("Scheduled rotation of %q on %s failed (the credential was reverted): %v", sec.Name, host.Hostname, cerr))
		return cerr
	}
	if err := rt.store.MarkVaultRotated(ctx, sec.ID, time.Now().UTC()); err != nil {
		rt.log.Warn("vault: mark rotated", "credential", sec.Name, "err", err)
	}
	rt.audit(ctx, "credential.rotate", sec, host.Hostname, map[string]any{"scheduled": true, "verified": verified})
	rt.notifyEv(ctx, notify.EventCredentialRotated, notify.SeverityInfo,
		"Credential auto-rotated",
		fmt.Sprintf("Scheduled rotation of %q on %s completed (verified=%v).", sec.Name, host.Hostname, verified))
	return nil
}

func (rt *Rotator) audit(ctx context.Context, action string, sec models.VaultSecret, host string, extra any) {
	detail := map[string]any{"credential": sec.Name, "host": host, "actor": "system"}
	switch v := extra.(type) {
	case string:
		if v != "" {
			detail["detail"] = v
		}
	case map[string]any:
		for k, val := range v {
			detail[k] = val
		}
	}
	_, _ = rt.store.AppendAudit(ctx, models.AuditEvent{
		ActorName: "system", Action: action, TargetKind: "credential", TargetID: sec.ID.String(), Detail: detail,
	})
}

func (rt *Rotator) notifyEv(ctx context.Context, typ string, sev notify.Severity, title, body string) {
	if rt.notify != nil {
		rt.notify.Notify(ctx, notify.Event{Type: typ, Severity: sev, Title: title, Body: body})
	}
}

// changePasswordOnHost sets user's password to newPw over a connection produced by
// `dial` (which authenticates with the password it is given), verifying by re-dialing
// with newPw. Shared by the on-demand (session-authenticated) and scheduled
// (system-authenticated) rotation paths — only the dial differs. Returns
// (verified, err): a non-nil err means the host was NOT changed (caller reverts).
func changePasswordOnHost(host *models.Host, user, oldPw, newPw string, dial func(addr, password string) (*sshgw.Conn, error)) (bool, error) {
	var lastErr error
	for _, addr := range dedupeAddrs(host.WGAddress, host.Address, host.Hostname) {
		conn, derr := dial(addr, oldPw)
		if derr != nil {
			lastErr = derr
			continue
		}
		sess, serr := conn.Client.NewSession()
		if serr != nil {
			conn.Close()
			lastErr = serr
			continue
		}
		// Feed "user:newpassword" on stdin so the secret never appears in argv/ps.
		sess.Stdin = strings.NewReader(user + ":" + newPw + "\n")
		out, cerr := sess.CombinedOutput("sudo chpasswd")
		_ = sess.Close()
		conn.Close()
		if cerr != nil {
			return false, fmt.Errorf("chpasswd: %v: %s", cerr, strings.TrimSpace(string(out)))
		}
		if vconn, verr := dial(addr, newPw); verr == nil {
			vconn.Close()
			return true, nil
		}
		return false, nil // changed, but could not verify
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address for host")
	}
	return false, lastErr
}
