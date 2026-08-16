package store

import (
	"testing"
	"time"
)

// TestAuditMACKeyedVsKeyless proves the keyed chain is not reproducible without the
// key: the same event hashed keyless (alg=1) and keyed (alg=2) differ, and two
// different keys produce different MACs. This is the whole point of H2 — a party with
// DB write access can recompute a keyless SHA-256 but cannot forge the HMAC.
func TestAuditMACKeyedVsKeyless(t *testing.T) {
	prev := "0000"
	canon := auditCanonicalLegacy("", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`))

	keyless := auditMAC(auditAlgLegacy, nil, prev, canon)
	keyed := auditMAC(auditAlgHMAC, []byte("super-secret-key"), prev, canon)
	if keyless == keyed {
		t.Fatal("keyed HMAC must differ from keyless SHA-256 over the same record")
	}

	other := auditMAC(auditAlgHMAC, []byte("a-different-key"), prev, canon)
	if keyed == other {
		t.Fatal("different keys must produce different MACs")
	}

	// Determinism: same inputs, same MAC.
	if again := auditMAC(auditAlgHMAC, []byte("super-secret-key"), prev, canon); again != keyed {
		t.Fatal("HMAC must be deterministic for identical inputs")
	}
}

// TestAuditCanonicalHMACBindsMetadata proves seq, created_at and tenant_id are bound
// into the keyed canonical record. Before H2 these were EXCLUDED, so an attacker
// could rewrite them and recompute a valid chain. Changing any of them must change
// the MAC now.
func TestAuditCanonicalHMACBindsMetadata(t *testing.T) {
	key := []byte("k")
	ts := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	tenantA := "00000000-0000-0000-0000-000000000001"
	tenantB := "00000000-0000-0000-0000-000000000002"

	base := auditCanonicalHMAC(10, ts, tenantA, "", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`))
	baseMAC := auditMAC(auditAlgHMAC, key, "prev", base)

	cases := map[string]string{
		"seq":        auditCanonicalHMAC(11, ts, tenantA, "", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`)),
		"created_at": auditCanonicalHMAC(10, ts.Add(time.Second), tenantA, "", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`)),
		"tenant_id":  auditCanonicalHMAC(10, ts, tenantB, "", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`)),
	}
	for field, canon := range cases {
		if mac := auditMAC(auditAlgHMAC, key, "prev", canon); mac == baseMAC {
			t.Fatalf("changing %s must change the keyed MAC (it was not bound into the canonical record)", field)
		}
	}

	// created_at is normalized to UTC so an equivalent instant in another zone yields
	// the identical MAC (verify reads the row back and re-normalizes).
	loc := time.FixedZone("x", 3600)
	same := auditCanonicalHMAC(10, ts.In(loc), tenantA, "", "alice", "user.delete", "user", "u1", "1.2.3.4", []byte(`{}`))
	if mac := auditMAC(auditAlgHMAC, key, "prev", same); mac != baseMAC {
		t.Fatal("the same instant in a different zone must yield the same MAC (UTC normalization)")
	}
}

func TestSetAuditHMACKey(t *testing.T) {
	t.Cleanup(func() { SetAuditHMACKey(nil) })

	SetAuditHMACKey(nil)
	if currentAuditHMACKey() != nil {
		t.Fatal("empty key should leave the chain keyless")
	}

	k := []byte("secret")
	SetAuditHMACKey(k)
	got := currentAuditHMACKey()
	if string(got) != "secret" {
		t.Fatalf("key = %q, want secret", got)
	}
	// Stored copy must be independent of the caller's slice.
	k[0] = 'X'
	if string(currentAuditHMACKey()) != "secret" {
		t.Fatal("SetAuditHMACKey must copy the key, not alias the caller's slice")
	}
}
