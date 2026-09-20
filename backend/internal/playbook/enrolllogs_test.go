package playbook

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

func pb(name string, updated time.Time) *models.Playbook {
	return &models.Playbook{ID: uuid.New(), Name: name, UpdatedAt: updated}
}

// The device variants share every word with the Linux one. Picking "Enroll Syslog To
// Aldgate (OpenWrt)" for a Debian fleet would run a playbook whose tasks do not apply
// to a single selected host, and the run would look like a Provenance fault.
func TestPickLogEnrolmentPlaybookPrefersTheLinuxOne(t *testing.T) {
	now := time.Now()
	all := []*models.Playbook{
		pb("Enroll Syslog And SNMP To Aldgate (RouterOS)", now),
		pb("Enroll Syslog To Aldgate (OpenWrt)", now),
		pb("Enroll Syslog To Aldgate", now.Add(-72*time.Hour)), // oldest, and still right
		pb("Update Apt Packages", now),
	}
	got := pickLogEnrolmentPlaybook(all)
	if got == nil || got.Name != "Enroll Syslog To Aldgate" {
		t.Fatalf("picked %v, want the Linux enrollment playbook", got)
	}
}

// An operator who renamed it must still get the feature; "no playbook found" on a
// cosmetic rename is the kind of brittleness that makes a bulk action untrustworthy.
func TestPickLogEnrolmentPlaybookToleratesARename(t *testing.T) {
	now := time.Now()
	all := []*models.Playbook{
		pb("Site syslog forwarding", now.Add(-time.Hour)),
		pb("Site syslog forwarding v2", now), // more recently touched: the one they mean
		pb("Enroll Syslog To Aldgate (OpenWrt)", now),
	}
	got := pickLogEnrolmentPlaybook(all)
	if got == nil || got.Name != "Site syslog forwarding v2" {
		t.Fatalf("picked %v, want the most recently updated candidate", got)
	}
}

// Nothing imported must be nil -- NOT a wrong guess. The handler turns this into a
// message naming the file to import, and silently running "Update Apt Packages" on a
// selection of hosts instead would be a disaster.
func TestPickLogEnrolmentPlaybookReturnsNilWhenAbsent(t *testing.T) {
	now := time.Now()
	all := []*models.Playbook{
		pb("Update Apt Packages", now),
		pb("InstallQemuGuestAgent", now),
		pb("Enroll Syslog To Aldgate (RouterOS)", now), // device-only: not a substitute
	}
	if got := pickLogEnrolmentPlaybook(all); got != nil {
		t.Fatalf("picked %q with no Linux enrollment playbook imported", got.Name)
	}
	if got := pickLogEnrolmentPlaybook(nil); got != nil {
		t.Fatalf("picked %q from an empty install", got.Name)
	}
}

// The canonical name wins outright, whatever else is imported and however stale it is.
func TestPickLogEnrolmentPlaybookPrefersTheCanonicalName(t *testing.T) {
	now := time.Now()
	all := []*models.Playbook{
		pb("Some other syslog thing", now),
		pb("  enroll syslog to aldgate  ", now.Add(-999*time.Hour)),
	}
	got := pickLogEnrolmentPlaybook(all)
	if got == nil || got.Name != "  enroll syslog to aldgate  " {
		t.Fatalf("picked %v, want the canonical name regardless of age", got)
	}
}
