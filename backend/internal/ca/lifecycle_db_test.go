package ca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/db"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// A CA rotation against a real database, across restarts: the new key must not sign
// until it is promoted -- not after a restart either, which reloads keys from the
// store -- and the signing key must be impossible to retire.
//
// The bug this replaces: the new key signed the instant it existed, before the jump
// host or any host trusted it, and no key could ever be retired.
func TestACARotationIsTrustedFirstSigningSecondRetiredLast(t *testing.T) {
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A throwaway database: start from no CA at all.
	if _, err := pool.Exec(ctx, `DELETE FROM ca_keys WHERE kind='user'`); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	cfg := &config.Config{CAKeyPassphrase: []byte("test-passphrase")}
	boot := func() *CA {
		c := New(st, cfg)
		if err := c.EnsureUserCA(ctx); err != nil {
			t.Fatalf("EnsureUserCA: %v", err)
		}
		return c
	}
	signedBy := func(c *CA) []byte {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(priv.Public())
		cert, err := c.SignUserCertificate(pub, "t", []string{"prov"}, 1, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return cert.SignatureKey.Marshal()
	}

	c := boot()
	oldID := c.ActiveID()
	oldKey := signedBy(c)

	if err := c.Rotate(ctx); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newID := c.PendingID()
	if newID == "" || newID == oldID {
		t.Fatalf("rotation made no pending key (pending=%q)", newID)
	}
	if c.ActiveID() != oldID || !bytes.Equal(signedBy(c), oldKey) {
		t.Fatal("the new key is signing before it was promoted -- the rotation window this replaces")
	}
	if keys, _ := st.ListActiveCAPublicKeys(ctx, "user"); len(keys) != 2 {
		t.Fatalf("both keys must be trusted during a rotation, got %d", len(keys))
	}
	if err := c.Rotate(ctx); !errors.Is(err, ErrRotationPending) {
		t.Fatalf("a second rotation while one is pending must be refused, got %v", err)
	}

	// A restart in the middle of the rotation keeps the old key signing.
	c = boot()
	if c.ActiveID() != oldID || c.PendingID() != newID || !bytes.Equal(signedBy(c), oldKey) {
		t.Fatalf("after a restart: signing=%s pending=%s -- a restart promoted the key early", c.ActiveID(), c.PendingID())
	}
	pendingCert, err := func() (*ssh.Certificate, error) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(priv.Public())
		return c.SignWithPending(pub, "check", []string{"prov"}, 2, time.Minute)
	}()
	if err != nil || bytes.Equal(pendingCert.SignatureKey.Marshal(), oldKey) {
		t.Fatal("SignWithPending must sign with the new key, for the jump-host check")
	}

	// Promote: the new key signs, and still does after a restart.
	if err := c.Promote(ctx); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if c.ActiveID() != newID || bytes.Equal(signedBy(c), oldKey) {
		t.Fatal("promotion did not switch the signer")
	}
	c = boot()
	if c.ActiveID() != newID || c.PendingID() != "" {
		t.Fatalf("after a restart: signing=%s pending=%s", c.ActiveID(), c.PendingID())
	}

	// The signing key cannot be retired; the old one can, and stops being trusted.
	newUUID, oldUUID := mustUUID(t, newID), mustUUID(t, oldID)
	if err := st.RetireCAKey(ctx, newUUID); err == nil {
		t.Fatal("the signing key was retired, leaving nothing to sign with")
	}
	if err := st.RetireCAKey(ctx, oldUUID); err != nil {
		t.Fatalf("retire the old key: %v", err)
	}
	if keys, _ := st.ListActiveCAPublicKeys(ctx, "user"); len(keys) != 1 {
		t.Fatalf("after retiring the old key exactly one key should be trusted, got %d", len(keys))
	}
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
