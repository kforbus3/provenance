package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type fakeGrants struct {
	ok  bool
	err error
	n   int
}

func (f *fakeGrants) HasSudoGrant(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	f.n++
	return f.ok, f.err
}

func TestMaySudo(t *testing.T) {
	host := uuid.New()
	plain := &Principal{UserID: uuid.New(), Username: "op"}
	withPerm := &Principal{UserID: uuid.New(), Username: "admin",
		Permissions: map[string]bool{"Host.Sudo": true}}
	super := &Principal{UserID: uuid.New(), Username: "root", IsSuperAdmin: true}

	t.Run("standing permission does not need the store", func(t *testing.T) {
		st := &fakeGrants{}
		if !MaySudo(context.Background(), st, nil, withPerm, host) {
			t.Error("Host.Sudo must grant root")
		}
		if !MaySudo(context.Background(), st, nil, super, host) {
			t.Error("super admin must grant root")
		}
		// Cheap, and it matters: the common path must not hit the database.
		if st.n != 0 {
			t.Errorf("store consulted %d times for a standing permission; want 0", st.n)
		}
	})

	t.Run("an approved grant is what makes the tier usable", func(t *testing.T) {
		if MaySudo(context.Background(), &fakeGrants{ok: false}, nil, plain, host) {
			t.Error("a login-only user with no grant must not get root")
		}
		if !MaySudo(context.Background(), &fakeGrants{ok: true}, nil, plain, host) {
			t.Error("a login-only user WITH an active grant must get root — without " +
				"this the only route is a permanent fleet-wide role edit")
		}
	})

	// Failing open would turn a database blip into fleet-wide root. Users who are
	// meant to have sudo are unaffected: the standing permission is checked first
	// and never reaches the store.
	t.Run("a store that cannot answer denies", func(t *testing.T) {
		st := &fakeGrants{ok: true, err: errors.New("connection refused")}
		if MaySudo(context.Background(), st, nil, plain, host) {
			t.Error("a lookup error must deny, not grant")
		}
		if !MaySudo(context.Background(), st, nil, withPerm, host) {
			t.Error("a lookup error must not strip sudo from someone who has the permission")
		}
	})

	t.Run("nothing to check against", func(t *testing.T) {
		if MaySudo(context.Background(), &fakeGrants{ok: true}, nil, plain, uuid.Nil) {
			t.Error("no host id means no host-scoped grant can apply")
		}
		if MaySudo(context.Background(), nil, nil, plain, host) {
			t.Error("no store means no grant can be confirmed")
		}
		if MaySudo(context.Background(), &fakeGrants{ok: true}, nil, nil, host) {
			t.Error("no principal must never be root")
		}
	})
}
