package store

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The distinction this whole change exists for: the database accepting an
// UPDATE is not the same as the UPDATE doing anything.
//
// A revocation that matched no rows was previously reported to the operator as
// "access removed". Under row-level security it is worse still: a write blocked
// by tenant isolation matches nothing and is indistinguishable from success.
func TestAWriteThatMatchedNothingIsNotSuccess(t *testing.T) {
	if err := changed(pgconn.NewCommandTag("UPDATE 0"), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("zero rows returned %v, want ErrNotFound", err)
	}
	if err := changed(pgconn.NewCommandTag("DELETE 0"), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("zero-row delete returned %v, want ErrNotFound", err)
	}
}

func TestAWriteThatChangedSomethingSucceeds(t *testing.T) {
	for _, tag := range []string{"UPDATE 1", "DELETE 1", "UPDATE 7"} {
		if err := changed(pgconn.NewCommandTag(tag), nil); err != nil {
			t.Errorf("%q returned %v, want nil", tag, err)
		}
	}
}

// A real database error must not be relabelled as "not found": those need
// different responses, and a connection failure reported as a missing row sends
// the operator to look at their data instead of their database.
func TestADatabaseErrorIsNotTurnedIntoNotFound(t *testing.T) {
	boom := errors.New("connection refused")
	err := changed(pgconn.NewCommandTag("UPDATE 0"), boom)
	if !errors.Is(err, boom) {
		t.Errorf("got %v, want the original error", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a database error was reported as a missing row")
	}
}
