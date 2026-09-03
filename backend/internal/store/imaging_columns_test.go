package store

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/kforbus3/blackfriars/backend/internal/models"
)

// ReportMachine is the only writer for most of a machine's record, and its
// statement names every column by hand. That makes one mistake very easy and
// completely silent: add a field to ImagingMachine, set it in a handler, and
// forget the SQL. The value is accepted, discarded, and read back as empty.
//
// It happened. `ImagedAt` and `BootedAt` existed on the model and in the
// migration, were set by the imager endpoints, and appeared in no statement --
// so the two moments that bracket an imaging run, the only record that answers
// "did the machine come back", were written to nothing at all.
//
// A round-trip test would be the obvious way to catch that, and it would need a
// Postgres. The DB-backed tests here are gated on a DSN and skip without one,
// and a test that skips in CI is a test that cannot fail. This reads the source
// instead: it needs nothing, runs everywhere, and fails on exactly the mistake.

// Fields deliberately not written by ReportMachine, each for a stated reason.
// Adding a name here is how you say "on purpose" -- and it is deliberately
// awkward, because it is also how you would hide the bug this test exists for.
var notReportedByAMachine = map[string]string{
	// A machine's own word about itself never sets these. They are an
	// operator's, and letting a report carry them would let anything on the
	// network put itself into a rollout it was never targeted by.
	"HostID": "set by LinkMachine; pairing is an operator's decision",
	"Label":  "set by SetMachineOperatorFields",
	"Held":   "set by SetMachineOperatorFields",

	// Written by the INSERT's own clause rather than the UPDATE's.
	"FirstSeen": "defaulted by the insert; it is the row's creation",
	"LastSeen":  "always now(), never taken from the caller",

	// Derived by the API layer from the host record and the clock; there are no
	// columns for these at all.
	"Presence":    "computed from LastSeen",
	"HostName":    "joined from the host",
	"Environment": "joined from the host",
	"Tags":        "joined from the host",
	"Reachable":   "computed from the host",
}

// snake turns a Go field name into the column name this schema would use.
func snake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	// The few that do not fall out of the rule.
	switch s := b.String(); s {
	case "i_d":
		return "id"
	case "host_i_d":
		return "host_id"
	case "boot_i_d":
		return "boot_id"
	default:
		return s
	}
}

func TestEveryImagingMachineFieldIsActuallyPersisted(t *testing.T) {
	src, err := os.ReadFile("imaging.go")
	if err != nil {
		t.Fatalf("reading the store source: %v", err)
	}
	// Just the ReportMachine function; other statements in this file mention
	// these columns and would mask a missing one.
	body := reportMachineBody(t, string(src))

	typ := reflect.TypeOf(models.ImagingMachine{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if why, ok := notReportedByAMachine[field.Name]; ok {
			t.Logf("skipping %s: %s", field.Name, why)
			continue
		}
		col := snake(field.Name)
		// Word-boundary match: `image` must not be satisfied by `imaged_at`,
		// which is the kind of near-miss that makes a test like this useless.
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(col) + `\b`).MatchString(body) {
			t.Errorf("ImagingMachine.%s has no column %q anywhere in ReportMachine, so "+
				"anything set there is silently discarded. Add it to the statement, or "+
				"add %s to notReportedByAMachine with the reason.",
				field.Name, col, field.Name)
		}
	}
}

// The columns must also be assigned on conflict, not merely inserted. A column
// present only in the INSERT is written the first time a machine is seen and
// never again -- which for a machine that has already checked in once is the
// same as not being written at all.
func TestReportedColumnsAreAlsoUpdatedOnConflict(t *testing.T) {
	src, err := os.ReadFile("imaging.go")
	if err != nil {
		t.Fatalf("reading the store source: %v", err)
	}
	body := reportMachineBody(t, string(src))
	idx := strings.Index(body, "DO UPDATE SET")
	if idx < 0 {
		t.Fatal("ReportMachine no longer has a DO UPDATE SET; this test needs rewriting")
	}
	update := body[idx:]

	typ := reflect.TypeOf(models.ImagingMachine{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if _, ok := notReportedByAMachine[field.Name]; ok {
			continue
		}
		col := snake(field.Name)
		if col == "id" {
			continue // the conflict target itself
		}
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(col) + `\s*=`).MatchString(update) {
			t.Errorf("column %q is never assigned in ReportMachine's DO UPDATE SET, so "+
				"ImagingMachine.%s is written only on a machine's very first report",
				col, field.Name)
		}
	}
}

func reportMachineBody(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, "func (s *Store) ReportMachine(")
	if start < 0 {
		t.Fatal("ReportMachine not found in internal/store/imaging.go")
	}
	rest := src[start:]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
