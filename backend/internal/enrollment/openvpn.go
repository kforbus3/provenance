package enrollment

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/models"
)

// enrollOpenVPN provisions the FIPS OpenVPN overlay for a host in place of
// WireGuard: it (idempotently) brings up the OpenVPN server on the jump host,
// assigns the host a static overlay address, issues the host an X.509 client
// certificate, pins that address to the cert on the jump server (ccd), and installs
// the tunnel on the host. It returns the assigned overlay address, which the caller
// stores in the same wg_address column WireGuard uses — so the SSH gateway dials the
// host identically regardless of overlay. It reports progress through `step` and runs
// privileged host scripts through `priv`.
//
// This path is taken only when FLEET_OVERLAY=openvpn; the WireGuard path is untouched.
func (s *Service) enrollOpenVPN(
	ctx context.Context,
	host *models.Host,
	jumpClient *ssh.Client,
	priv func(string) (string, error),
	params EnrollParams,
	step func(name, status, detail string),
) (overlayIP string, err error) {
	if s.ovpn == nil {
		return "", fmt.Errorf("OpenVPN overlay selected but not initialized (overlay PKI unavailable)")
	}

	// Assign the overlay address: honor an operator-specified one, else auto-assign
	// the next free address in the overlay subnet. Same subnet + free-address logic
	// as WireGuard, so addressing is uniform across overlays.
	overlayIP = strings.TrimSpace(host.WGAddress)
	if overlayIP != "" {
		if !isOverlayAddr(overlayIP, s.cfg.WGJumpIP) {
			return "", fmt.Errorf("overlay address %q is not in the overlay subnet %s", overlayIP, s.cfg.WGSubnet)
		}
		if inUse, _ := s.store.WGAddressInUse(ctx, overlayIP, host.ID); inUse {
			return "", fmt.Errorf("overlay address %s is already assigned to another host", overlayIP)
		}
	} else {
		overlayIP, err = s.store.NextFreeWGAddress(ctx, s.cfg.WGJumpIP)
		if err != nil {
			return "", err
		}
	}

	// 1) Ensure the jump-host OpenVPN server is provisioned and running. Idempotent:
	//    the script leaves an already-running server (and its live tunnels) untouched.
	caPEM, srvCert, srvKey, err := s.ovpn.EnsureJumpMaterial(ctx)
	if err != nil {
		return "", fmt.Errorf("issue jump server certificate: %w", err)
	}
	srvConf, err := s.ovpn.ServerConfig()
	if err != nil {
		return "", fmt.Errorf("build server config: %w", err)
	}
	jsScript := s.ovpn.JumpServerScript(caPEM, srvCert, srvKey, srvConf)
	if out, jerr := run(jumpClient, "sudo sh -c "+shellQuote(jsScript)); jerr != nil {
		return "", fmt.Errorf("start jump OpenVPN server: %v: %s", jerr, oneLine(out))
	} else if strings.Contains(out, "OVPN_SERVER_START_FAILED") {
		return "", fmt.Errorf("jump OpenVPN server failed to start: %s", oneLine(out))
	}
	step("configure_jump_server", "ok", "OpenVPN server ready on jump host")

	// 2) Issue the host its client certificate (CN bound to the host UUID) and pin its
	//    overlay address on the jump server via a ccd entry keyed by that CN.
	caPEM2, cliCert, cliKey, cn, err := s.ovpn.IssueHostMaterial(ctx, host.ID)
	if err != nil {
		return "", fmt.Errorf("issue host client certificate: %w", err)
	}
	ccdEntry, err := s.ovpn.CCDEntry(overlayIP)
	if err != nil {
		return "", fmt.Errorf("build ccd entry: %w", err)
	}
	if out, jerr := run(jumpClient, "sudo sh -c "+shellQuote(s.ovpn.JumpCCDScript(cn, ccdEntry))); jerr != nil {
		return "", fmt.Errorf("pin overlay address on jump: %v: %s", jerr, oneLine(out))
	}
	step("configure_overlay_route", "ok", fmt.Sprintf("pinned %s to %s", overlayIP, cn))

	// 3) Install openvpn + client material on the host and bring the tunnel up. The
	//    endpoint host follows the same precedence as WireGuard (per-enroll override
	//    -> DB setting -> config default); the port is always the overlay's OVPN port.
	endpoint := strings.TrimSpace(params.WGEndpoint)
	if endpoint == "" {
		endpoint = s.store.WireGuardEndpoint(ctx)
	}
	if endpoint == "" {
		endpoint = s.cfg.WGJumpEndpoint
	}
	clientConf := s.ovpn.ClientConfig(endpoint)
	hostScript := s.ovpn.HostInstallScript(caPEM2, cliCert, cliKey, clientConf)
	out, herr := priv(hostScript)
	if herr != nil || strings.Contains(out, "OVPN_INSTALL_FAILED") || !strings.Contains(out, "OVPN_HOST_CONFIGURED") {
		return "", fmt.Errorf("install OpenVPN on host: %v: %s", herr, oneLine(out))
	}
	gotIP := parseKV(out, "OVPN_HOST_IP")
	if gotIP == "" {
		gotIP = overlayIP
	}
	step("configure_host_overlay", "ok", fmt.Sprintf("OpenVPN tunnel up (addr %s)", gotIP))

	return overlayIP, nil
}
