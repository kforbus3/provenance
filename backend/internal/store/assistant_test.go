package store

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBuildHostQueryWhere(t *testing.T) {
	max := 20.0
	uid := uuid.New()
	where, args := buildHostQueryWhere(HostQuery{
		Status:         "online",
		DiskFreePctMax: &max,
		UserID:         uid,
		IsSuperAdmin:   false,
	})

	if !strings.Contains(where, "COALESCE(s.status,'unknown')=$1") {
		t.Fatalf("missing status condition: %s", where)
	}
	if !strings.Contains(where, "m.min_disk_free_pct <= $2") {
		t.Fatalf("missing disk condition: %s", where)
	}
	// Non-super-admin must add the access-scope subquery bound to the user id.
	if !strings.Contains(where, "h.id IN (") || !strings.Contains(where, "ug.user_id=$3") {
		t.Fatalf("missing access scope: %s", where)
	}
	if len(args) != 3 || args[0] != "online" || args[1] != 20.0 || args[2] != uid {
		t.Fatalf("args = %v, want [online 20 %v]", args, uid)
	}
}

func TestBuildHostQueryWhereSuperAdmin(t *testing.T) {
	// Super admin: no access subquery, no filters -> empty WHERE.
	where, args := buildHostQueryWhere(HostQuery{IsSuperAdmin: true})
	if where != "" {
		t.Fatalf("super admin with no filters should have empty WHERE, got %q", where)
	}
	if len(args) != 0 {
		t.Fatalf("args = %v, want empty", args)
	}
}

func TestBuildHostQueryWhereScopeOnly(t *testing.T) {
	// No filters but scoped: just the access subquery as $1.
	where, args := buildHostQueryWhere(HostQuery{UserID: uuid.New()})
	if !strings.HasPrefix(where, "WHERE h.id IN (") {
		t.Fatalf("want scope-only WHERE, got %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args = %v, want 1 (user id)", args)
	}
}
