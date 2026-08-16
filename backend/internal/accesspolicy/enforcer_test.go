package accesspolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// fakeStore is a policyStore whose policy load can be made to fail, and which counts
// audit writes.
type fakeStore struct {
	policiesErr error
	audits      int
}

func (f *fakeStore) EnabledAccessPolicies(context.Context) ([]store.AccessPolicy, error) {
	return nil, f.policiesErr
}
func (f *fakeStore) UserRoleNames(context.Context, uuid.UUID) ([]string, error) { return nil, nil }
func (f *fakeStore) DisplayTimezone(context.Context) string                     { return "" }
func (f *fakeStore) AppendAudit(context.Context, models.AuditEvent) (*models.AuditEvent, error) {
	f.audits++
	return nil, nil
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// A policy-store error must FAIL CLOSED (deny), not silently drop all restrictions.
func TestCheckFailsClosedOnStoreError(t *testing.T) {
	e := NewEnforcer(&fakeStore{policiesErr: errors.New("db down")}, testLogger())
	d := e.Check(context.Background(), uuid.New(), false, HostAttrs{Environment: "production"})
	if !d.Denied {
		t.Fatal("a store error must deny the attempt (fail closed), got allow")
	}
	if d.Reason == "" {
		t.Error("a fail-closed deny should carry a reason")
	}
}

// Super admins keep their break-glass exemption even when the store is down.
func TestCheckSuperAdminExemptOnStoreError(t *testing.T) {
	e := NewEnforcer(&fakeStore{policiesErr: errors.New("db down")}, testLogger())
	if e.Check(context.Background(), uuid.New(), true, HostAttrs{}).Denied {
		t.Error("super admin must never be denied, even on a store error")
	}
}

// A fail-closed deny must be visible in the audit log.
func TestAuthorizeAuditsFailClosedDeny(t *testing.T) {
	fs := &fakeStore{policiesErr: errors.New("db down")}
	e := NewEnforcer(fs, testLogger())
	d := e.Authorize(context.Background(), ConnCtx{UserID: uuid.New(), Surface: "terminal"})
	if !d.Denied {
		t.Fatal("expected a fail-closed deny")
	}
	if fs.audits == 0 {
		t.Error("a fail-closed deny was not written to the audit log")
	}
}

// With no policies configured and a healthy store, nothing is denied.
func TestCheckAllowsWhenNoPolicies(t *testing.T) {
	e := NewEnforcer(&fakeStore{}, testLogger())
	if e.Check(context.Background(), uuid.New(), false, HostAttrs{Environment: "production"}).Denied {
		t.Error("no policies means no ABAC restriction; should allow")
	}
}
