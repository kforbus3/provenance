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
func (o *OpenVPN) EnsureServer(ctx context.Context, jumpRun RunFunc) error {
	if err := o.pki.EnsureCA(ctx); err != nil {
		return fmt.Errorf("overlay PKI: %w", err)
	}
	caPEM, srvCert, srvKey, err := o.EnsureJumpMaterial(ctx)
	if err != nil {
		return fmt.Errorf("issue jump server certificate: %w", err)
	}
	srvConf, err := o.ServerConfig()
	if err != nil {
		return fmt.Errorf("build server config: %w", err)
	}
	out, err := jumpRun(o.JumpServerScript(caPEM, srvCert, srvKey, srvConf))
	if err != nil {
		return fmt.Errorf("start jump OpenVPN server: %v: %s", err, oneLine(out))
	}
	if strings.Contains(out, "OVPN_SERVER_START_FAILED") {
		return fmt.Errorf("jump OpenVPN server failed to start: %s", oneLine(out))
	}
	return nil
}

// ProvisionHost implements Overlay: issue the host client cert, pin its overlay IP on
// the jump server by cert CN (ccd), and bring up the tunnel on the host.
func (o *OpenVPN) ProvisionHost(ctx context.Context, hostID uuid.UUID, overlayIP, endpoint string, hostRun, jumpRun RunFunc) (string, error) {
	caPEM, cliCert, cliKey, cn, err := o.IssueHostMaterial(ctx, hostID)
	if err != nil {
		return "", fmt.Errorf("issue host client certificate: %w", err)
	}
	ccdEntry, err := o.CCDEntry(overlayIP)
	if err != nil {
		return "", fmt.Errorf("build ccd entry: %w", err)
	}
	if out, jerr := jumpRun(o.JumpCCDScript(cn, ccdEntry)); jerr != nil {
		return "", fmt.Errorf("pin overlay address on jump: %v: %s", jerr, oneLine(out))
	}
	clientConf := o.ClientConfig(endpoint)
	out, herr := hostRun(o.HostInstallScript(caPEM, cliCert, cliKey, clientConf))
	if herr != nil || strings.Contains(out, "OVPN_INSTALL_FAILED") || !strings.Contains(out, "OVPN_HOST_CONFIGURED") {
		return "", fmt.Errorf("install OpenVPN on host: %v: %s", herr, oneLine(out))
	}
	return fmt.Sprintf("OpenVPN tunnel up (addr %s)", overlayIP), nil
}
