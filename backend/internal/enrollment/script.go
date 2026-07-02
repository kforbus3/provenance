package enrollment

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/krl"
	"github.com/fleet-terminal/backend/internal/models"
)

// EnrollScript generates a self-contained bootstrap script for the no-install
// flow. The operator pipes it through their OWN ssh:
//
//	curl -H 'Authorization: Bearer <token>' \
//	  https://fleet/api/v1/hosts/<id>/enroll/script | ssh user@host sudo bash
//
// The script installs the Fleet CA trust + WireGuard on the host and prints the
// host's WireGuard public key, which the operator pastes back into the UI
// (FinishScriptEnroll). No Fleet binary, password, or private key ever reaches
// the backend — the operator's existing ssh handles host authentication.
func (s *Service) EnrollScript(ctx context.Context, sessionID uuid.UUID, host *models.Host, actor *uuid.UUID, wgEndpointOverride string) (string, error) {
	loginUser := host.SSHUser
	if loginUser == "" {
		loginUser = "fleet"
	}

	// The jump host's WireGuard public key — the managed host peers to it.
	jumpAddr, jumpPort := splitHostPort(s.cfg.JumpHost, 22)
	jumpClient, err := s.gw.DialDirect(ctx, sessionID.String(), jumpAddr, jumpPort, s.cfg.JumpUser)
	if err != nil {
		return "", fmt.Errorf("connect jump host: %w", err)
	}
	defer jumpClient.Close()
	jumpPub, err := run(jumpClient, "sudo cat /etc/wireguard/publickey 2>/dev/null || cat /etc/wireguard/publickey")
	if err != nil || strings.TrimSpace(jumpPub) == "" {
		return "", orErr(err, "jump host has no WireGuard public key")
	}
	jumpPub = strings.TrimSpace(jumpPub)

	// Assign + persist the overlay address so this and the finish step agree, and
	// re-generating the script is idempotent.
	wgIP := strings.TrimSpace(host.WGAddress)
	if wgIP != "" {
		if !isOverlayAddr(wgIP, s.cfg.WGJumpIP) {
			return "", fmt.Errorf("WireGuard address %q is not in the overlay subnet %s", wgIP, s.cfg.WGSubnet)
		}
		if inUse, _ := s.store.WGAddressInUse(ctx, wgIP, host.ID); inUse {
			return "", fmt.Errorf("WireGuard address %s is already assigned to another host", wgIP)
		}
	} else {
		wgIP, err = s.store.NextFreeWGAddress(ctx, s.cfg.WGJumpIP)
		if err != nil {
			return "", err
		}
	}
	_ = s.store.SetHostWGAddress(ctx, host.ID, wgIP)

	caKeys, kerr := s.store.ListActiveCAPublicKeys(ctx, "user")
	if kerr != nil || len(caKeys) == 0 {
		return "", orErr(kerr, "no active user CA")
	}

	jumpEndpoint := strings.TrimSpace(wgEndpointOverride)
	if jumpEndpoint == "" {
		jumpEndpoint = s.store.WireGuardEndpoint(ctx)
	}
	if jumpEndpoint == "" {
		jumpEndpoint = s.cfg.WGJumpEndpoint
	}

	krlB64 := ""
	if krl.Available() {
		serials, _ := s.store.RevokedSerials(ctx)
		if b, e := krl.Build(caKeys, serials); e == nil {
			krlB64 = base64.StdEncoding.EncodeToString(b)
		}
	}

	_, _ = s.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: actor, Action: "host.enroll_script", TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"wgAddress": wgIP, "method": "pipe"},
	})

	return s.bootstrapScript(loginUser, strings.Join(caKeys, "\n"), wgIP, jumpPub, jumpEndpoint, krlB64), nil
}

// FinishScriptEnroll completes the no-install flow after the operator has run
// the bootstrap script: it adds the host (identified by the public key the
// operator pasted) as a peer on the jump host and verifies certificate login.
func (s *Service) FinishScriptEnroll(ctx context.Context, sessionID uuid.UUID, host *models.Host, actor *uuid.UUID, hostPub string) (*Result, error) {
	hostPub = strings.TrimSpace(hostPub)
	if hostPub == "" {
		return nil, fmt.Errorf("host public key is required (copy it from the bootstrap script output)")
	}
	wgIP := strings.TrimSpace(host.WGAddress)
	if wgIP == "" {
		return nil, fmt.Errorf("no overlay address assigned — generate and run the bootstrap script first")
	}
	mgmtAddr := host.Address
	if mgmtAddr == "" {
		mgmtAddr = host.Hostname
	}
	loginUser := host.SSHUser
	if loginUser == "" {
		loginUser = "fleet"
	}

	job, err := s.store.CreateEnrollmentJob(ctx, host.ID, fmt.Sprintf("%s:%d", mgmtAddr, host.SSHPort), "", actor)
	if err != nil {
		return nil, err
	}
	step := func(name, status, detail string) {
		_ = s.store.AppendEnrollmentStep(ctx, job.ID, models.EnrollmentStep{
			Name: name, Status: status, Detail: detail, Timestamp: time.Now(),
		})
	}
	fail := func(name string, err error) (*Result, error) {
		step(name, "failed", err.Error())
		_ = s.store.FinishEnrollmentJob(ctx, job.ID, "failed", err.Error())
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	jumpAddr, jumpPort := splitHostPort(s.cfg.JumpHost, 22)
	jumpClient, err := s.gw.DialDirect(ctx, sessionID.String(), jumpAddr, jumpPort, s.cfg.JumpUser)
	if err != nil {
		return fail("connect_jump_host", err)
	}
	defer jumpClient.Close()
	step("connect_jump_host", "ok", "jump host reachable")

	hostEndpoint := fmt.Sprintf("%s:%d", mgmtAddr, s.cfg.WGPort)
	if verr := validatePeerInputs(hostPub, hostEndpoint, wgIP); verr != nil {
		return fail("configure_jump_peer", verr)
	}
	jumpScript := s.jumpPeerScript(host.Hostname, hostPub, hostEndpoint, wgIP)
	if jout, jerr := run(jumpClient, "sudo sh -c "+shellQuote(jumpScript)); jerr != nil {
		return fail("configure_jump_peer", orErr(jerr, jout))
	}
	step("configure_jump_peer", "ok", fmt.Sprintf("peer %s allowed-ips %s/32", short(hostPub), wgIP))

	_ = s.store.SetHostEnrolled(ctx, host.ID, true)

	if id, verr := s.validateCertLogin(ctx, sessionID, wgIP, mgmtAddr, host.SSHPort, loginUser); verr == nil {
		step("verify_certificate_login", "ok", "cert login via jump host: "+oneLine(id))
	} else {
		step("verify_certificate_login", "skipped", verr.Error())
	}

	_ = s.store.FinishEnrollmentJob(ctx, job.ID, "succeeded", "")
	_, _ = s.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: actor, Action: "host.enroll", TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"wgAddress": wgIP, "hostPublicKey": hostPub, "method": "pipe", "jobId": job.ID},
	})
	final, _ := s.store.GetEnrollmentJob(ctx, job.ID)
	return &Result{Job: final, WGAddr: wgIP, HostPub: hostPub}, nil
}

// bootstrapScript assembles the host-side script from the same building blocks
// the over-SSH enrollment uses. Each phase runs in a subshell (so its `set -e`
// is scoped) and is checked for its success marker; the host's WireGuard public
// key is surfaced at the end for the operator to paste back.
func (s *Service) bootstrapScript(loginUser, caKeys, wgIP, jumpPub, jumpEndpoint, krlB64 string) string {
	phase := func(num, label, body, marker, failMsg string) string {
		check := ""
		if marker != "" {
			check = fmt.Sprintf("grep -q %s \"$F\" || { sed 's/^/  /' \"$F\"; echo '[fleet] FAILED: %s'; exit 1; }\n", marker, failMsg)
		}
		return fmt.Sprintf(`echo '[fleet] %s %s'
F=$(mktemp)
(
%s
) >"$F" 2>&1 || { sed 's/^/  /' "$F"; echo '[fleet] FAILED: %s'; exit 1; }
%s`, num, label, body, failMsg, check)
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Fleet Terminal — host bootstrap (no-install enrollment).\n")
	b.WriteString("# Run as root, e.g.:  curl ... | ssh USER@HOST sudo bash\n")
	b.WriteString("set -e\n")
	b.WriteString(`if [ "$(id -u)" != 0 ]; then echo '[fleet] must run as root (pipe through: ssh USER@HOST sudo bash)'; exit 1; fi` + "\n\n")

	b.WriteString(phase("1/4", "installing SSH certificate trust",
		s.caTrustScript(loginUser, caKeys), "CA_OK", "CA trust") + "\n")
	b.WriteString(phase("2/4", "installing WireGuard tooling",
		wgInstallScript, "WG_INSTALLED", "WireGuard install") + "\n")

	// Phase 3 captures the interface output to extract the host public key.
	b.WriteString(fmt.Sprintf(`echo '[fleet] 3/4 configuring WireGuard interface'
IFOUT=$(mktemp)
(
%s
) >"$IFOUT" 2>&1 || { sed 's/^/  /' "$IFOUT"; echo '[fleet] FAILED: WireGuard interface'; exit 1; }
HOSTPUB=$(sed -n 's/^HOSTPUB=//p' "$IFOUT")
WGADDR=$(sed -n 's/^WGADDR=//p' "$IFOUT")
[ -n "$HOSTPUB" ] || { sed 's/^/  /' "$IFOUT"; echo '[fleet] FAILED: no host public key produced'; exit 1; }
`, s.hostWGScript(wgIP, jumpPub, jumpEndpoint)))

	if krlB64 != "" {
		b.WriteString(fmt.Sprintf(`echo '[fleet] 4/4 enabling certificate revocation'
(
%s
) >/dev/null 2>&1 && echo '[fleet] revocation enforced' || echo '[fleet] WARN: revocation not enforced (continuing)'
`, s.krlInstallScript(krlB64)))
	}

	b.WriteString(`
echo ''
echo '==================== FLEET TERMINAL ===================='
echo "Bootstrap complete. Overlay address: $WGADDR"
echo ''
echo 'Paste this HOST PUBLIC KEY into the Finish step in the UI:'
echo ''
echo "    $HOSTPUB"
echo ''
echo '======================================================='
`)
	return b.String()
}
