package overlay

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Name implements Overlay.
func (o *OpenVPN) Name() string { return "openvpn" }

// EnsureServer implements Overlay: provision + (idempotently) start the OpenVPN server
// on the jump host, ensuring the overlay CA exists first.
func (o *OpenVPN) EnsureServer(ctx context.Context, jumpRun RunFunc) (string, error) {
	if err := o.pki.EnsureCA(ctx); err != nil {
		return "", fmt.Errorf("overlay PKI: %w", err)
	}
	caPEM, srvCert, srvKey, err := o.EnsureJumpMaterial(ctx)
	if err != nil {
		return "", fmt.Errorf("issue jump server certificate: %w", err)
	}
	srvConf, err := o.ServerConfig()
	if err != nil {
		return "", fmt.Errorf("build server config: %w", err)
	}
	// Always regenerate: the config names crl-verify, and openvpn will not start
	// without that file. An empty list is a valid signed CRL, which is what a fleet
	// with nothing revoked gets.
	crlPEM, err := o.pki.CRLPEM(ctx)
	if err != nil {
		return "", fmt.Errorf("build overlay CRL: %w", err)
	}
	out, err := jumpRun(o.JumpServerScript(caPEM, srvCert, srvKey, crlPEM, srvConf))
	if err != nil {
		return "", fmt.Errorf("start jump OpenVPN server: %v: %s", err, oneLine(out))
	}
	if strings.Contains(out, "OVPN_SERVER_START_FAILED") {
		return "", fmt.Errorf("jump OpenVPN server failed to start: %s", oneLine(out))
	}
	// Peer isolation is a security control. When it is REQUIRED (configured on) but the
	// jump host could not install the forwarding deny, fail the provisioning closed:
	// bringing the overlay up anyway would leave managed hosts able to reach each other,
	// which is precisely the posture isolation exists to prevent.
	if err := serverIsolationError(out, o.cfg.OverlayPeerIsolation); err != nil {
		return "", err
	}
	detail := "openvpn server ready on jump host"
	if strings.Contains(out, "OVPN_PEER_ISOLATION_FAILED") {
		// Reached only when isolation is disabled (serverIsolationError returned nil):
		// say so plainly rather than letting the absence go unrecorded.
		detail += " — WARNING: could not apply overlay peer isolation on the jump host; managed hosts can reach each other over the overlay"
	}
	return detail, nil
}

// serverIsolationError returns a hard, fail-closed error when peer isolation is
// required but the jump host reported it could not install the forwarding deny.
func serverIsolationError(out string, required bool) error {
	if required && strings.Contains(out, "OVPN_PEER_ISOLATION_FAILED") {
		return fmt.Errorf("overlay peer isolation is enabled but the jump host could not install the overlay "+
			"forwarding deny (%s); refusing to bring up an overlay on which managed hosts can reach each other",
			oneLine(out))
	}
	return nil
}

// hostConfiguredMarker is printed by HostInstallScript once the client material is in
// place and the tunnel has been started.
const hostConfiguredMarker = "OVPN_HOST_CONFIGURED"

// PrepareHost implements Overlay: issue the host client cert, pin its overlay IP on the
// jump server by cert CN (ccd), and return the host-side bring-up script.
func (o *OpenVPN) PrepareHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, jumpRun RunFunc) (HostBringup, error) {
	caPEM, cliCert, cliKey, cn, err := o.IssueHostMaterial(ctx, hostID)
	if err != nil {
		return HostBringup{}, fmt.Errorf("issue host client certificate: %w", err)
	}
	ccdEntry, err := o.CCDEntry(overlayIP)
	if err != nil {
		return HostBringup{}, fmt.Errorf("build ccd entry: %w", err)
	}
	if out, jerr := jumpRun(o.JumpCCDScript(cn, ccdEntry)); jerr != nil {
		return HostBringup{}, fmt.Errorf("pin overlay address on jump: %v: %s", jerr, oneLine(out))
	}
	return HostBringup{
		Script: o.HostInstallScript(caPEM, cliCert, cliKey, o.ClientConfig(endpoint), overlayIP),
		Marker: hostConfiguredMarker,
	}, nil
}

// ProvisionHost implements Overlay: prepare the host's certificate + address pin, then
// run the bring-up script on the host.
func (o *OpenVPN) ProvisionHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, hostRun, jumpRun RunFunc) (string, error) {
	hb, err := o.PrepareHost(ctx, hostID, overlayIP, endpoint, jumpRun)
	if err != nil {
		return "", err
	}
	out, herr := hostRun(hb.Script)
	if herr != nil || strings.Contains(out, "OVPN_INSTALL_FAILED") || !strings.Contains(out, hb.Marker) {
		return "", fmt.Errorf("install OpenVPN on host: %v: %s", herr, oneLine(out))
	}
	detail, err := checkHostBringup(out, overlayIP)
	if err != nil {
		return "", err
	}
	// Fail closed: OpenVPN has no AllowedIPs, so the host-side iptables filter is the
	// ONLY thing isolating this host at its own end. When isolation is required but the
	// host reports it was not applied, refuse the enrollment rather than silently
	// joining a host that other managed hosts can reach over the overlay.
	if err := hostIsolationError(out, o.cfg.OverlayPeerIsolation); err != nil {
		return "", err
	}
	return detail, nil
}

// hostIsolationError returns a hard, fail-closed error when peer isolation is required
// but the host bring-up output shows it could not be applied (iptables missing, or the
// rules did not take). It returns nil when isolation is not required or was applied.
func hostIsolationError(out string, required bool) error {
	if !required {
		return nil
	}
	if strings.Contains(out, "OVPN_IPTABLES_MISSING") || strings.Contains(out, "OVPN_ISOLATION_MISSING") {
		return fmt.Errorf("overlay peer isolation is enabled but was NOT applied on this host (%s); "+
			"refusing to enroll — the host would be able to reach, and be reached by, other managed hosts "+
			"over the overlay", oneLine(out))
	}
	return nil
}

// checkHostBringup turns the host bring-up script's output into a step detail, or an
// error. It reports the address the host ACTUALLY came up with rather than the one it
// was meant to get: a mismatch means the ccd pin did not apply (the server handed out
// a pool address instead), which leaves Fleet dialing an address nothing answers on,
// and an empty one means there is no tunnel at all however cleanly the script exited.
func checkHostBringup(out, overlayIP string) (string, error) {
	got := hostIP(out)
	switch {
	case got == "":
		return "", fmt.Errorf("the host brought up no OpenVPN tunnel%s. %s: %s",
			remoteSuffix(out), noTunnelHint, oneLine(out))
	case got != overlayIP:
		return "", fmt.Errorf(
			"OpenVPN tunnel came up at %s, not the assigned %s — the ccd pin for this host is not being applied",
			got, overlayIP)
	}
	detail := fmt.Sprintf("OpenVPN tunnel up (addr %s, observed on the host)", got)
	// Peer isolation fails open by design, which is precisely why its absence has to
	// be said out loud: the enrollment otherwise succeeds identically whether or not
	// this host can be reached by every other host on the overlay.
	switch {
	case strings.Contains(out, "OVPN_IPTABLES_MISSING"):
		detail += " — WARNING: iptables is not available on this host and could not be installed, " +
			"so overlay peer isolation is NOT applied; this host can reach, and be reached by, " +
			"other managed hosts over the overlay"
	case strings.Contains(out, "OVPN_ISOLATION_MISSING"):
		detail += " — WARNING: overlay peer isolation could not be applied on this host " +
			"(iptables is present but the rules did not take); this host can reach, and be " +
			"reached by, other managed hosts over the overlay"
	case strings.Contains(out, "OVPN_ISOLATION_OK"):
		detail += ", peer isolation applied"
	}
	return detail, nil
}

// hostIP reads the OVPN_HOST_IP=<addr> line the host bring-up script prints.
func hostIP(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "OVPN_HOST_IP="); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// noTunnelHint is what to check when a host's client starts but never receives an
// address. Every cause is the same shape — the client's UDP packets are not reaching
// the server — and none of them appear in the client's own log, which is why an
// operator reading "no tunnel" otherwise has nowhere to start.
const noTunnelHint = "the client could not reach the OpenVPN server, so it was never " +
	"assigned an address. Check that the server's UDP port is published by the jump host " +
	"(a jump-host compose change needs `make up-single`, not `make redeploy-single`), " +
	"forwarded on the firewall/router, and reachable from this host — a host on the same LAN " +
	"as the jump host may need the endpoint set to a LAN address, since many routers will not " +
	"hairpin a public one"

// remoteSuffix names the endpoint the client was told to dial, when the host reported
// it. That address is the subject of every check in noTunnelHint.
func remoteSuffix(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "OVPN_REMOTE="); ok {
			if r := strings.TrimSpace(rest); r != "" && r != ":" {
				return " at " + r
			}
		}
	}
	return ""
}
