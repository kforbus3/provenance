package imaging

import (
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// store.UpdateHost is a whole-row write: every column in HostInput is assigned,
// so a field left unset is a field cleared. Changing one option therefore means
// copying all the others, and hand-listing them is a trap that had already
// sprung -- the first version of the pairing handler omitted WGAddress, so
// pairing a host with a Flipside machine would have erased its overlay address.
// That is how Moorgate reaches a host, so pairing one would have destroyed the
// ability to push to it, silently, while the page said "Paired."
//
// The specific bug is worth a test. The *class* is worth more: the next field
// added to HostInput will be forgotten the same way, and nothing about that
// failure is loud. So this walks the struct.

func TestHostInputCopiesEveryFieldThatCanBeCleared(t *testing.T) {
	credID := uuid.New()
	// Every field distinctly non-zero, so a field that is not copied comes back
	// as a zero value and is caught by name rather than by someone noticing.
	h := &models.Host{
		Hostname:     "web01",
		Description:  "a description",
		Environment:  "production",
		Owner:        "someone",
		Address:      "10.0.0.9",
		WGAddress:    "10.77.0.9",
		SSHPort:      2222,
		SSHUser:      "fleet",
		Tags:         []string{"prod", "web"},
		AuthMethod:   "vault_password",
		CredentialID: &credID,
		Protocol:     "ssh",
		RDPPort:      3390,
		RDPOptions:   models.RDPOptions{},
		Options:      models.HostOptions{DeviceType: "routeros", APIPort: 8728},
	}
	in := hostInputFrom(h)

	inVal := reflect.ValueOf(in)
	inType := inVal.Type()
	hostVal := reflect.ValueOf(*h)

	for i := range inType.NumField() {
		name := inType.Field(i).Name
		got := inVal.Field(i)

		hostField := hostVal.FieldByName(name)
		if !hostField.IsValid() {
			// A HostInput field with no counterpart on Host cannot be checked
			// this way, and is worth saying out loud rather than passing.
			t.Errorf("HostInput.%s has no matching field on Host; check by hand "+
				"whether hostInputFrom should be setting it", name)
			continue
		}
		if hostField.IsZero() {
			continue // nothing to lose
		}
		if got.IsZero() {
			t.Errorf("hostInputFrom does not copy %s: updating a host would clear it", name)
			continue
		}
		if !reflect.DeepEqual(got.Interface(), hostField.Interface()) {
			t.Errorf("hostInputFrom changed %s: got %v, host has %v",
				name, got.Interface(), hostField.Interface())
		}
	}
}

func TestPairingPreservesTheOverlayAddress(t *testing.T) {
	// The specific case, stated on its own because of what it costs: the
	// overlay address is how Moorgate reaches a host, so losing it while
	// pairing that host for updates removes exactly the capability the pairing
	// exists to enable.
	h := &models.Host{Hostname: "web01", WGAddress: "10.77.0.9", Address: "10.0.0.9"}
	in := hostInputFrom(h)
	in.Options.FlipsideMachineID = "aa:bb:cc:dd:ee:ff"

	if in.WGAddress != "10.77.0.9" {
		t.Fatalf("pairing would clear the overlay address (got %q)", in.WGAddress)
	}
	if in.Address != "10.0.0.9" {
		t.Fatalf("pairing would clear the fallback address (got %q)", in.Address)
	}
	if in.Options.FlipsideMachineID != "aa:bb:cc:dd:ee:ff" {
		t.Fatal("the pairing itself was not set")
	}
}
