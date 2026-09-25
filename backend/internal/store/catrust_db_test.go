package store

import (
	"testing"

	"github.com/google/uuid"
)

// What a host confirms is what the rotation gates read: a failed push must not erase
// the last confirmed set, and a host is in sync only when it confirmed the current one.
func TestHostCATrustIsRecordedPerHost(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "catrust-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE hosts SET enrolled=true WHERE id=$1`, h.ID); err != nil {
		t.Fatal(err)
	}
	find := func(want string) HostCATrust {
		all, err := s.HostsCATrust(ctx, want)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range all {
			if x.HostID == h.ID {
				return x
			}
		}
		t.Fatal("host not listed")
		return HostCATrust{}
	}
	oldSet := CATrustHash([]string{"ssh-ed25519 AAAAold"})
	newSet := CATrustHash([]string{"ssh-ed25519 AAAAold", "ssh-ed25519 AAAAnew comment"})
	if newSet != CATrustHash([]string{"ssh-ed25519 AAAAnew", "  ssh-ed25519 AAAAold  "}) {
		t.Fatal("order, comments and whitespace must not change the trusted-set hash")
	}

	if find(newSet).InSync {
		t.Fatal("a host that never confirmed anything is not in sync")
	}
	if err := s.RecordHostCATrust(ctx, h.ID, oldSet, ""); err != nil {
		t.Fatal(err)
	}
	if find(newSet).InSync || !find(oldSet).InSync {
		t.Fatal("a host confirming the old set is in sync with it and only it")
	}
	if err := s.RecordHostCATrust(ctx, h.ID, "", "unreachable: dial jump host"); err != nil {
		t.Fatal(err)
	}
	got := find(oldSet)
	if !got.InSync || got.Error == "" {
		t.Fatalf("a failed push must keep the last confirmed set and record why: %+v", got)
	}
	if err := s.RecordHostCATrust(ctx, h.ID, newSet, ""); err != nil {
		t.Fatal(err)
	}
	if got := find(newSet); !got.InSync || got.Error != "" {
		t.Fatalf("after confirming the new set: %+v", got)
	}
}
