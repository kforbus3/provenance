package enrollment

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
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

	return s.bootstrapScript(loginUser, strings.Join(caKeys, "\n"), wgIP, jumpPub, jumpEndpoint, krlB64, host.ID), nil
}

// EnrollScriptWindows generates a PowerShell script that joins a Windows host to the
// WireGuard overlay by dialing OUT to the jump host, so a remote Windows/RDP host is
// reachable through the jump host from anywhere — the same overlay model as Linux, but
// with no SSH/CA trust (Windows is reached over RDP/WinRM, not SSH). The operator runs
// it elevated on the host and pastes the reported public key back into Fleet
// (FinishScriptEnroll).
func (s *Service) EnrollScriptWindows(ctx context.Context, sessionID uuid.UUID, host *models.Host, actor *uuid.UUID, wgEndpointOverride string) (string, error) {
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

	// Assign + persist the overlay address so this and the finish step agree.
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

	jumpEndpoint := strings.TrimSpace(wgEndpointOverride)
	if jumpEndpoint == "" {
		jumpEndpoint = s.store.WireGuardEndpoint(ctx)
	}
	if jumpEndpoint == "" {
		jumpEndpoint = s.cfg.WGJumpEndpoint
	}

	_, _ = s.store.AppendAudit(ctx, models.AuditEvent{
		ActorID: actor, Action: "host.enroll_script", TargetKind: "host", TargetID: host.ID.String(),
		Detail: map[string]any{"wgAddress": wgIP, "method": "windows"},
	})

	return windowsWGScript(wgIP, jumpPub, jumpEndpoint, s.cfg.WGSubnet, s.cfg.WGPort), nil
}

// windowsWGScript builds the PowerShell that installs WireGuard for Windows, generates
// a keypair, writes a dial-out tunnel config, installs it as a persistent tunnel
// service, and prints the public key for the operator to hand back to Fleet.
func windowsWGScript(wgIP, jumpPub, jumpEndpoint, subnet string, listenPort int) string {
	return strings.NewReplacer(
		"__WGIP__", wgIP,
		"__JUMPPUB__", jumpPub,
		"__ENDPOINT__", jumpEndpoint,
		"__SUBNET__", subnet,
		"__LISTENPORT__", strconv.Itoa(listenPort),
	).Replace(windowsWGTemplate)
}

const windowsWGTemplate = `#Requires -RunAsAdministrator
# Fleet Terminal — Windows WireGuard enrollment. Run in an elevated PowerShell.
$ErrorActionPreference = "Stop"
$wgDir = "$env:ProgramFiles\WireGuard"

# 1. Install WireGuard for Windows if it isn't already present.
if (-not (Test-Path "$wgDir\wireguard.exe")) {
  Write-Host "Installing WireGuard for Windows..."
  try {
    winget install --id WireGuard.WireGuard -e --silent --accept-source-agreements --accept-package-agreements | Out-Null
  } catch {
    throw "WireGuard is not installed and automatic install failed. Install it from https://www.wireguard.com/install/ and re-run this script."
  }
}
$wg      = "$wgDir\wg.exe"
$wgquick = "$wgDir\wireguard.exe"

# 2. Generate a fresh WireGuard keypair.
$priv = (& $wg genkey).Trim()
$pub  = ($priv | & $wg pubkey).Trim()

# 3. Write the tunnel config. A fixed ListenPort lets the jump host reach this
#    host directly (e.g. on a shared LAN) exactly as it does a Linux host, so the
#    tunnel comes up even when the configured Endpoint isn't reachable from here
#    (a LAN host can't hairpin to its own public address). When the host is remote,
#    the outbound keepalive to Endpoint still establishes the tunnel.
$conf = @"
[Interface]
PrivateKey = $priv
Address = __WGIP__/32
ListenPort = __LISTENPORT__

[Peer]
PublicKey = __JUMPPUB__
Endpoint = __ENDPOINT__
AllowedIPs = __SUBNET__
PersistentKeepalive = 25
"@
$confPath = Join-Path $env:TEMP "fleet.conf"
Set-Content -Path $confPath -Value $conf -Encoding ascii

# 4. Install + start the tunnel as a service (auto-connects on boot).
try { & $wgquick /uninstalltunnelservice fleet 2>$null | Out-Null } catch {}
& $wgquick /installtunnelservice $confPath
Start-Sleep -Seconds 2
Remove-Item $confPath -Force -ErrorAction SilentlyContinue

# 5. Enable Remote Desktop and open the RDP port in Windows Firewall so Fleet can
#    broker sessions over the overlay (traffic arrives on the WireGuard interface from
#    the jump host). Best-effort; enrollment still succeeds if a step fails.
try {
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
  Write-Host "Remote Desktop enabled and firewall opened (TCP 3389)."
} catch {
  Write-Host "WARN: could not enable Remote Desktop: $($_.Exception.Message)"
}

# 6. Enable WinRM over HTTPS so Fleet can collect host facts (OS, CPU, memory, uptime)
#    securely. TLS on the 5986 listener means no plaintext and no AllowUnencrypted; the
#    traffic also stays inside the WireGuard tunnel. Best-effort: enrollment still
#    succeeds if this fails (facts just won't populate until WinRM is configured).
try {
  Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
  Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue | Where-Object { $_.Keys -contains "Transport=HTTPS" } | ForEach-Object { Remove-Item -Path ("WSMan:\localhost\Listener\" + $_.Name) -Recurse -Force -ErrorAction SilentlyContinue }
  $winrmCert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10)
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $winrmCert.Thumbprint -Force | Out-Null
  New-NetFirewallRule -DisplayName "Fleet WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
  Write-Host "WinRM HTTPS (5986) configured for Fleet fact collection."
} catch {
  Write-Host "WARN: could not configure WinRM HTTPS listener: $($_.Exception.Message)"
}

# 7. Print the public key to paste back into Fleet.
Write-Host ""
Write-Host "================ Fleet enrollment ================"
Write-Host "Configured on this host:"
Write-Host "  - WireGuard tunnel 'fleet' (UDP __LISTENPORT__, managed by WireGuard)"
Write-Host "  - Remote Desktop + firewall (TCP 3389)"
Write-Host "  - WinRM HTTPS listener + firewall (TCP 5986)"
Write-Host "All Fleet traffic reaches this host over the WireGuard interface."
Write-Host ""
Write-Host "Paste this WireGuard PUBLIC KEY back into Fleet:"
Write-Host $pub
Write-Host "=================================================="
`

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

	// The jump keeps a static endpoint (mgmtAddr:WGPort) so it can dial the host
	// directly — for a host that shares the jump's LAN this brings the tunnel up
	// even when the host's own configured Endpoint isn't reachable from where the
	// host sits (a LAN host can't hairpin to its own public address). Windows hosts
	// enroll with a matching fixed ListenPort so this works for them exactly as it
	// does for Linux; when the host is remote, its outbound keepalive establishes
	// the tunnel and WireGuard relearns the real endpoint from that handshake.
	hostEndpoint := fmt.Sprintf("%s:%d", mgmtAddr, s.cfg.WGPort)
	if verr := validatePeerInputs(hostPub, hostEndpoint, wgIP); verr != nil {
		return fail("configure_jump_peer", verr)
	}
	jumpScript := s.jumpPeerScript(host.Hostname, hostPub, hostEndpoint, wgIP)
	if jout, jerr := run(jumpClient, "sudo sh -c "+shellQuote(jumpScript)); jerr != nil {
		return fail("configure_jump_peer", orErr(jerr, jout))
	}
	step("configure_jump_peer", "ok", fmt.Sprintf("peer %s allowed-ips %s/32", short(hostPub), wgIP))

	// Persist the overlay public key so a standby jump host can rebuild peers on
	// failover (best-effort).
	if perr := s.store.SetHostWGPublicKey(ctx, host.ID, hostPub); perr != nil {
		s.log.Warn("persist host wg public key", "host", host.Hostname, "err", perr)
	}
	_ = s.store.SetHostEnrolled(ctx, host.ID, true)

	if host.Protocol == "rdp" {
		// Windows hosts have no SSH cert login; verify the RDP port is reachable over
		// the freshly-established overlay tunnel instead.
		port := host.RDPPort
		if port <= 0 {
			port = 3389
		}
		// Bound the check: the tunnel may still be settling (or the host firewall may
		// block 3389 over the WG interface), and DialContext through the jump host would
		// otherwise hang for minutes. A skip here doesn't fail enrollment.
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		conn, verr := jumpClient.DialContext(dctx, "tcp", net.JoinHostPort(wgIP, strconv.Itoa(port)))
		cancel()
		if verr == nil {
			_ = conn.Close()
			step("verify_rdp_overlay", "ok", fmt.Sprintf("rdp reachable at %s:%d over the overlay", wgIP, port))
		} else {
			step("verify_rdp_overlay", "skipped", verr.Error())
		}
	} else if id, verr := s.validateCertLogin(ctx, host.ID, wgIP, mgmtAddr, host.SSHPort, loginUser); verr == nil {
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
func (s *Service) bootstrapScript(loginUser, caKeys, wgIP, jumpPub, jumpEndpoint, krlB64 string, hostID uuid.UUID) string {
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
		s.caTrustScript(loginUser, caKeys, hostID), "CA_OK", "CA trust") + "\n")
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
