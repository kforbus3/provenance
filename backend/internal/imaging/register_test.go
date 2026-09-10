package imaging

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Registering an enrolled host as an updatable machine is the inverse of "add as
// host", and it exists because rollouts select from the machine table: a host
// with no record there is unreachable by one, including by a rollout that
// targets the whole fleet.
//
// The risk is not that it fails — a failure is visible and gets fixed. The risk
// is that it succeeds with a record that is subtly wrong, because a wrong record
// is indistinguishable from a right one until a rollout runs against it.

func host() *models.Host {
	return &models.Host{Hostname: "kiosk-04", Address: "10.0.4.21"}
}

const goodProbe = `ab_update=1
slot=B
id=7c:1e:52:aa:bb:cc
version=2026.09.1
arch=x86_64
hostname=kiosk-04
agent=yes
`

func TestRegisterReadsWhatTheMachineReports(t *testing.T) {
	m, err := machineFromProbe(goodProbe, host())
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if m.ID != "7c:1e:52:aa:bb:cc" {
		t.Errorf("id = %q, want the machine's own identity", m.ID)
	}
	if m.Slot != "B" {
		t.Errorf("slot = %q, want B — the slot it is actually running", m.Slot)
	}
	if m.Version != "2026.09.1" {
		t.Errorf("version = %q", m.Version)
	}
	if m.Arch != "x86_64" {
		t.Errorf("arch = %q", m.Arch)
	}
	// The address comes from the host record, not from the machine: the machine
	// knows its own addresses but not which one this server can reach it on,
	// and the host record is the one that has already been proven to work.
	if m.Address != "10.0.4.21" {
		t.Errorf("address = %q, want the host's reachable address", m.Address)
	}
}

// "observed" rather than "reported" is not cosmetic — it is shown in the UI, and
// it is the difference between a machine that called in and one that was gone
// and looked at. Registering fabricates neither.
func TestRegisterRecordsThatWeWentAndLooked(t *testing.T) {
	m, err := machineFromProbe(goodProbe, host())
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if m.ReportSource != "observed" {
		t.Errorf("reportSource = %q, want observed: nothing heard from this machine",
			m.ReportSource)
	}
}

// The failure this prevents is the expensive one. A host with no ab-update
// cannot install a bundle, but a record for it is a permanent member of every
// fleet-wide rollout — so it fails every one of them, forever, and each failure
// eats into a rollout's failure budget and can halt a rollout that was otherwise
// fine. Refusing at registration keeps that machine out of the blast radius.
func TestRegisterRefusesAHostThatIsNotAB(t *testing.T) {
	probe := strings.Replace(goodProbe, "ab_update=1", "ab_update=0", 1)
	m, err := machineFromProbe(probe, host())
	if err == nil {
		t.Fatalf("registered a host with no ab-update as %+v; it can only ever fail a rollout", m)
	}
	// The message has to say which host and that nothing changed — this runs
	// against a host someone believed was A/B, so "failed" alone is no help.
	if !strings.Contains(err.Error(), "kiosk-04") {
		t.Errorf("refusal does not name the host: %v", err)
	}
	if !strings.Contains(err.Error(), "Nothing was registered") {
		t.Errorf("refusal does not say the host is unchanged: %v", err)
	}
}

// An empty id is the quiet corruption. ReportMachine upserts by id, so a record
// saved under "" is joined by every other identity-less machine, and the first
// real check-in creates a second record for the same box — leaving two rows
// disagreeing about which slot is running. Better to refuse and say so.
func TestRegisterRefusesAMachineWithNoIdentity(t *testing.T) {
	probe := strings.Replace(goodProbe, "id=7c:1e:52:aa:bb:cc", "id=", 1)
	if m, err := machineFromProbe(probe, host()); err == nil {
		t.Fatalf("registered a machine with no identity as %q", m.ID)
	}
}

// A machine can be a legitimate A/B system and still not tell us everything:
// an unusual boot entry with no rauc.slot, a version file not yet written. That
// is a record with gaps, not a reason to refuse — the agent fills them in on its
// first check-in, and until then a rollout can still reach it.
func TestRegisterAcceptsAnIncompleteButIdentifiableMachine(t *testing.T) {
	m, err := machineFromProbe("ab_update=1\nid=aa:bb:cc:dd:ee:ff\nslot=\nversion=\n", host())
	if err != nil {
		t.Fatalf("refused a machine that has ab-update and an identity: %v", err)
	}
	if m.Slot != "" || m.Version != "" {
		t.Errorf("invented values it was not told: slot=%q version=%q", m.Slot, m.Version)
	}
}

// The probe runs through a shell over SSH, which appends and reorders nothing
// reliably: motd lines, sudo lectures and CRLF all end up in the same stream.
// Parsing has to survive that or registration fails on hosts that are fine.
func TestRegisterToleratesNoiseAroundTheProbeOutput(t *testing.T) {
	noisy := "Welcome to Ubuntu 24.04 LTS\r\n" + strings.ReplaceAll(goodProbe, "\n", "\r\n") +
		"\r\nConnection to kiosk-04 closed.\r\n"
	m, err := machineFromProbe(noisy, host())
	if err != nil {
		t.Fatalf("refused a good machine over a noisy channel: %v", err)
	}
	if m.Slot != "B" || m.ID != "7c:1e:52:aa:bb:cc" {
		t.Errorf("carriage returns leaked into the record: id=%q slot=%q", m.ID, m.Slot)
	}
}
