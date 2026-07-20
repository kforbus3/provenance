package overlay

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/overlaypki"
)

func testCfg() *config.Config {
	return &config.Config{
		WGSubnet:       "10.100.0.0/24",
		WGJumpIP:       "10.100.0.1",
		WGJumpEndpoint: "jump:1194",
		OVPNPort:       1194,
		Overlay:        "openvpn",
	}
}

func TestConfigGenerationShape(t *testing.T) {
	o := New(testCfg(), nil)
	srv, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server 10.100.0.0 255.255.255.0", "tls-groups secp256r1:secp384r1", "data-ciphers AES-256-GCM", "client-config-dir /etc/openvpn/fleet/ccd", "port 1194"} {
		if !contains(srv, want) {
			t.Errorf("server config missing %q", want)
		}
	}
	cli := o.ClientConfig("jump.example.com:1194")
	for _, want := range []string{"remote jump.example.com 1194", "remote-cert-tls server", "tls-groups secp256r1:secp384r1"} {
		if !contains(cli, want) {
			t.Errorf("client config missing %q", want)
		}
	}
	ccd, err := o.CCDEntry("10.100.0.50")
	if err != nil || ccd != "ifconfig-push 10.100.0.50 255.255.255.0\n" {
		t.Errorf("ccd entry = %q err=%v", ccd, err)
	}
}

// TestEmitOverlayConfigs writes the full jump-server + managed-host material (real
// generated configs + real PKI certs) to $FLEET_OVPN_TEST_OUT for the container
// integration harness. Skipped in normal runs.
func TestEmitOverlayConfigs(t *testing.T) {
	out := os.Getenv("FLEET_OVPN_TEST_OUT")
	if out == "" {
		t.Skip("set FLEET_OVPN_TEST_OUT to emit overlay configs")
	}
	const hostID = "11111111-2222-3333-4444-555555555555"
	overlayIP := "10.100.0.50"
	o := New(testCfg(), nil)

	caCert, caKey, caPEM, err := overlaypki.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, _, err := overlaypki.IssueFrom(caCert, caKey, "fleet-overlay-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, 24*time.Hour, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, _, err := overlaypki.IssueFrom(caCert, caKey, ClientCN(hostID), nil, nil, 24*time.Hour, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	srvConf, err := o.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	cliConf := o.ClientConfig(o.cfg.WGJumpEndpoint)
	ccd, err := o.CCDEntry(overlayIP)
	if err != nil {
		t.Fatal(err)
	}

	must := func(p string, b []byte) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(out, "ca.crt"), caPEM)
	must(filepath.Join(out, "server.crt"), srvCert)
	must(filepath.Join(out, "server.key"), srvKey)
	must(filepath.Join(out, "client.crt"), cliCert)
	must(filepath.Join(out, "client.key"), cliKey)
	must(filepath.Join(out, "server.conf"), []byte(srvConf))
	must(filepath.Join(out, "client.ovpn"), []byte(cliConf))
	must(filepath.Join(out, "ccd", ClientCN(hostID)), []byte(ccd))

	// The actual provisioning scripts Fleet runs over SSH on the jump host + managed
	// host (self-contained: install openvpn, write material, start the daemon).
	must(filepath.Join(out, "jump-server.sh"), []byte(o.JumpServerScript(caPEM, srvCert, srvKey, srvConf)))
	must(filepath.Join(out, "jump-ccd.sh"), []byte(o.JumpCCDScript(ClientCN(hostID), ccd)))
	must(filepath.Join(out, "host-install.sh"), []byte(o.HostInstallScript(caPEM, cliCert, cliKey, cliConf)))
	t.Logf("emitted overlay material + scripts (CN=%s, ip=%s) to %s", ClientCN(hostID), overlayIP, out)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
