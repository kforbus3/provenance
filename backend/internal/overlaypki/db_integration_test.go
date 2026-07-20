package overlaypki_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/overlaypki"
	"github.com/fleet-terminal/backend/internal/store"
)

// TestEnsureCAPersistsAndReloads proves the FIPS-boot contract against a real
// Postgres: EnsureCA generates the overlay CA once, persists the sealed key, and a
// second PKI instance (a simulated process restart) reloads the SAME CA by
// decrypting it — then issues a client cert that chains to the reloaded CA.
//
// Gated on FLEET_PKI_TEST_DB (a DSN to a throwaway Postgres with the overlay_ca table).
func TestEnsureCAPersistsAndReloads(t *testing.T) {
	dsn := os.Getenv("FLEET_PKI_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_PKI_TEST_DB to a Postgres DSN with the overlay_ca table")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	st := store.New(pool)
	cfg := &config.Config{CAKeyPassphrase: []byte("fips-overlay-test-passphrase-000")}

	// First boot: generate + persist.
	p1 := overlaypki.New(st, cfg)
	if err := p1.EnsureCA(ctx); err != nil {
		t.Fatalf("EnsureCA (first boot): %v", err)
	}
	fp1 := p1.Fingerprint()
	caPEM1 := string(p1.CACertPEM())
	if fp1 == "" || caPEM1 == "" {
		t.Fatal("first boot produced empty CA")
	}

	// Second boot (fresh instance = process restart): must RELOAD, not regenerate.
	p2 := overlaypki.New(st, cfg)
	if err := p2.EnsureCA(ctx); err != nil {
		t.Fatalf("EnsureCA (restart): %v", err)
	}
	if p2.Fingerprint() != fp1 {
		t.Fatalf("CA not reloaded: fingerprint changed %s -> %s (regenerated instead of decrypted)", fp1, p2.Fingerprint())
	}
	if string(p2.CACertPEM()) != caPEM1 {
		t.Fatal("reloaded CA cert differs from persisted one")
	}

	// Issue a client cert off the RELOADED CA and confirm it chains — proves the
	// sealed private key survived the DB round-trip and decrypts to a usable key.
	certPEM, _, _, err := p2.IssueClient("fleet-h-smoke", time.Hour)
	if err != nil {
		t.Fatalf("IssueClient off reloaded CA: %v", err)
	}
	leaf := mustParseCert(t, certPEM)
	caCert := mustParseCert(t, []byte(caPEM1))

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert does not chain to reloaded CA: %v", err)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("client key algorithm = %v, want ECDSA (FIPS)", leaf.PublicKeyAlgorithm)
	}
}

func mustParseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}
