package auditfwd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

func quietForwarder() *Forwarder {
	return &Forwarder{
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cacheTTL: time.Minute,
	}
}

// TestForwardQueueDropIsNotSilent proves a full queue (sustained collector outage)
// increments the dropped counter and logs, rather than silently losing events.
func TestForwardQueueDropIsNotSilent(t *testing.T) {
	f := quietForwarder()
	f.queue = make(chan models.AuditEvent, 2) // no worker draining it
	f.cached = Config{Enabled: true, Type: "http", Address: "https://collector.example.com"}
	f.cachedAt = time.Now()

	for i := 0; i < 5; i++ {
		f.Forward(models.AuditEvent{Action: "test.event"})
	}
	if got := f.dropped.Load(); got != 3 {
		t.Fatalf("dropped = %d, want 3 (2 queued, 3 overflow)", got)
	}
	if len(f.queue) != 2 {
		t.Fatalf("queue len = %d, want 2 (bounded)", len(f.queue))
	}
}

// TestForwardDisabledDoesNotQueue proves a disabled config drops without touching the
// queue or the drop counter.
func TestForwardDisabledDoesNotQueue(t *testing.T) {
	f := quietForwarder()
	f.queue = make(chan models.AuditEvent, 4)
	f.cached = Config{Enabled: false}
	f.cachedAt = time.Now()

	f.Forward(models.AuditEvent{Action: "test.event"})
	if len(f.queue) != 0 || f.dropped.Load() != 0 {
		t.Fatalf("disabled forwarder must not queue or drop; queue=%d dropped=%d", len(f.queue), f.dropped.Load())
	}
}

func TestTLSConfig(t *testing.T) {
	f := quietForwarder()

	// ServerName is taken from the host portion of host:port.
	tc, err := f.tlsConfig(Config{Address: "siem.example.com:6514", TLS: true})
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if tc.ServerName != "siem.example.com" {
		t.Fatalf("ServerName = %q, want siem.example.com", tc.ServerName)
	}
	if tc.MinVersion != 0x0303 { // TLS 1.2
		t.Fatalf("MinVersion = %x, want TLS1.2", tc.MinVersion)
	}

	// A valid CA PEM is loaded into the trust pool.
	caPEM := selfSignedCAPEM(t)
	tc, err = f.tlsConfig(Config{Address: "siem:6514", TLS: true, CACertPEM: caPEM})
	if err != nil {
		t.Fatalf("tlsConfig with CA: %v", err)
	}
	if tc.RootCAs == nil {
		t.Fatal("expected RootCAs to be set from CACertPEM")
	}

	// An invalid CA PEM is rejected (not silently ignored).
	if _, err := f.tlsConfig(Config{Address: "siem:6514", TLS: true, CACertPEM: "not a pem"}); err == nil {
		t.Fatal("expected error for invalid CACertPEM")
	}
}

func selfSignedCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
