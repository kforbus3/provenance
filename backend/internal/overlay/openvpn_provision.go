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
	out, err := jumpRun(o.JumpServerScript(caPEM, srvCert, srvKey, srvConf))
	if err != nil {
		return "", fmt.Errorf("start jump OpenVPN server: %v: %s", err, oneLine(out))
	}
	if strings.Contains(out, "OVPN_SERVER_START_FAILED") {
		return "", fmt.Errorf("jump OpenVPN server failed to start: %s", oneLine(out))
	}
	detail := "openvpn server ready on jump host"
	// Peer isolation is deliberately non-fatal (a jump host with no usable iptables
	// still serves the overlay), so say so plainly rather than letting a security
	// control fail into silence.
	if strings.Contains(out, "OVPN_PEER_ISOLATION_FAILED") {
		detail += " — WARNING: could not apply overlay peer isolation on the jump host; managed hosts can reach each other over the overlay"
	}
	return detail, nil
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
		Script: o.HostInstallScript(caPEM, cliCert, cliKey, o.ClientConfig(endpoint)),
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
	return fmt.Sprintf("OpenVPN tunnel up (addr %s)", overlayIP), nil
}
