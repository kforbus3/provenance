package overlaypki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChainVerifies proves the overlay CA, a server cert, and a client cert chain
// and verify with the correct key usages — the X.509 shape OpenVPN requires.
func TestChainVerifies(t *testing.T) {
	caCert, caKey, _, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	srvPEM, _, _, err := IssueFrom(caCert, caKey, "fleet-overlay-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	cliPEM, _, _, err := IssueFrom(caCert, caKey, "test-host", nil, nil, time.Hour, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	for name, pemBytes := range map[string][]byte{"server": srvPEM, "client": cliPEM} {
		leaf := parsePEM(t, pemBytes)
		eku := x509.ExtKeyUsageServerAuth
		if name == "client" {
			eku = x509.ExtKeyUsageClientAuth
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
			t.Errorf("%s cert failed to verify: %v", name, err)
		}
		if leaf.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("%s cert is not ECDSA", name)
		}
	}
}

// TestEmitOpenVPNCerts writes a full cert set to $FLEET_OVPN_TEST_OUT when set, so an
// integration harness can drive a real OpenVPN server/client with them. It's a no-op
// (skipped) in normal test runs.
func TestEmitOpenVPNCerts(t *testing.T) {
	out := os.Getenv("FLEET_OVPN_TEST_OUT")
	if out == "" {
		t.Skip("set FLEET_OVPN_TEST_OUT to emit OpenVPN cert files")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	caCert, caKey, caPEM, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, _, err := IssueFrom(caCert, caKey, "fleet-overlay-server", nil, []net.IP{net.ParseIP("172.30.0.2")}, 24*time.Hour, x509.ExtKeyUsageServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, cliKey, _, err := IssueFrom(caCert, caKey, "test-host", nil, nil, 24*time.Hour, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", caPEM)
	write("server.crt", srvCert)
	write("server.key", srvKey)
	write("client.crt", cliCert)
	write("client.key", cliKey)
	t.Logf("wrote OpenVPN cert set to %s", out)
}

func parsePEM(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("not valid PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
