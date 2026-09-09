package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// The gate deciding whether a host-group-scoped operator may act on a machine.
// It existed five times, byte-identical, under three names, and none of the
// five had a test.

type fakeHostStore struct {
	allow  bool
	err    error
	asked  int
	forUID uuid.UUID
}

func (f *fakeHostStore) UserCanAccessHost(_ context.Context, userID, _ uuid.UUID) (bool, error) {
	f.asked++
	f.forUID = userID
	return f.allow, f.err
}

func TestCanAccessHostAsksTheStoreForAScopedUser(t *testing.T) {
	uid := uuid.New()
	s := &fakeHostStore{allow: true}
	if !CanAccessHost(context.Background(), s, &Principal{UserID: uid}, uuid.New()) {
		t.Fatal("denied a user the store said may access the host")
	}
	if s.asked != 1 || s.forUID != uid {
		t.Errorf("asked %d times for %v; want once for %v", s.asked, s.forUID, uid)
	}
}

func TestCanAccessHostDeniesWhenTheStoreSaysNo(t *testing.T) {
	if CanAccessHost(context.Background(), &fakeHostStore{allow: false},
		&Principal{UserID: uuid.New()}, uuid.New()) {
		t.Fatal("allowed a host the store said is out of scope")
	}
}

// The one that matters. A store failure must deny: this is the only thing
// between a scoped operator and a host outside their groups, so failing open
// would silently grant access exactly when the database is unhealthy.
func TestCanAccessHostDeniesOnAStoreError(t *testing.T) {
	s := &fakeHostStore{allow: true, err: errors.New("connection refused")}
	if CanAccessHost(context.Background(), s, &Principal{UserID: uuid.New()}, uuid.New()) {
		t.Fatal("allowed access when the store errored — an access check must fail closed")
	}
}

// Short-circuited before the store is consulted, so a super admin still works
// when the lookup would fail.
func TestSuperAdminIsAllowedWithoutAskingTheStore(t *testing.T) {
	s := &fakeHostStore{allow: false, err: errors.New("down")}
	if !CanAccessHost(context.Background(), s, &Principal{UserID: uuid.New(), IsSuperAdmin: true}, uuid.New()) {
		t.Fatal("denied a super admin")
	}
	if s.asked != 0 {
		t.Errorf("consulted the store %d times for a super admin; want 0", s.asked)
	}
}

// An unauthenticated request must never reach the store with a zero user id,
// which would be a lookup for "the user whose id is all zeroes".
func TestNilPrincipalIsDeniedWithoutAskingTheStore(t *testing.T) {
	s := &fakeHostStore{allow: true}
	if CanAccessHost(context.Background(), s, nil, uuid.New()) {
		t.Fatal("allowed a nil principal")
	}
	if s.asked != 0 {
		t.Errorf("consulted the store for a nil principal")
	}
}
