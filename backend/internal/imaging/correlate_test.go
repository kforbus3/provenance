package imaging

import (
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

// Correlation is the join between two systems that name the same machine
// differently, and every way it can be wrong is quiet. Pairing the wrong host
// with the wrong machine means an update lands somewhere nobody asked for;
// pairing none of them means a rollout silently never gets the push it was
// joined up to provide.

func host(name string, machineID string) models.Host {
	h := models.Host{ID: uuid.New(), Hostname: name}
	h.Options.FlipsideMachineID = machineID
	return h
}

func TestExplicitLinkWins(t *testing.T) {
	hosts := []models.Host{host("web01", "aa:bb:cc:dd:ee:01")}
	machines := []Machine{
		{ID: "aa:bb:cc:dd:ee:01", Hostname: "something-else"},
		{ID: "aa:bb:cc:dd:ee:02", Hostname: "web01"},
	}
	links, orphans := Correlate(hosts, machines)
	if len(links) != 1 || links[0].Machine == nil {
		t.Fatalf("expected one paired link, got %+v", links)
	}
	// The recorded link must beat the hostname, which here points at a
	// different machine entirely. If the name won, an update aimed at web01
	// would be sent to whichever machine happens to answer to that name today.
	if got := links[0].Machine.ID; got != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("hostname beat the explicit link: paired with %s", got)
	}
	if links[0].How != "linked" {
		t.Fatalf("how = %q, want linked", links[0].How)
	}
	if len(orphans) != 1 || orphans[0].ID != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("expected the unclaimed machine as an orphan, got %+v", orphans)
	}
}

func TestHostnameMatchIsLabelledAsAGuess(t *testing.T) {
	links, _ := Correlate(
		[]models.Host{host("web01", "")},
		[]Machine{{ID: "aa:bb", Hostname: "web01"}},
	)
	if links[0].Machine == nil {
		t.Fatal("hostname match did not pair")
	}
	// Labelled, not recorded: the UI offers to make it explicit, and a caller
	// that treats a guess as fact would pin the wrong machine forever.
	if links[0].How != "hostname" {
		t.Fatalf("how = %q, want hostname", links[0].How)
	}
}

func TestHostnameMatchIgnoresDomainAndCase(t *testing.T) {
	links, _ := Correlate(
		[]models.Host{host("Web01", "")},
		[]Machine{{ID: "aa:bb", Hostname: "web01.example.com"}},
	)
	if links[0].Machine == nil {
		t.Fatal("a machine reporting an FQDN did not match a short host name")
	}
}

func TestDuplicateHostnamesMatchNothing(t *testing.T) {
	// Two machines answering to the same name make the name useless as an
	// identifier. Picking one at random would be worse than admitting it:
	// half the time the update goes to the wrong machine, and nothing says so.
	links, orphans := Correlate(
		[]models.Host{host("web01", "")},
		[]Machine{{ID: "aa:bb", Hostname: "web01"}, {ID: "cc:dd", Hostname: "web01"}},
	)
	if links[0].Machine != nil {
		t.Fatalf("an ambiguous hostname was paired anyway, with %s", links[0].Machine.ID)
	}
	if len(orphans) != 2 {
		t.Fatalf("expected both ambiguous machines unclaimed, got %d", len(orphans))
	}
}

func TestOneMachineIsNotPairedTwice(t *testing.T) {
	// Two hosts, one machine. Whichever is paired, the other must be left
	// unpaired rather than both being told they own it -- a rollout would
	// otherwise nudge one host expecting to move the other.
	links, _ := Correlate(
		[]models.Host{host("web01", "aa:bb"), host("web01-old", "")},
		[]Machine{{ID: "aa:bb", Hostname: "web01"}},
	)
	paired := 0
	for _, l := range links {
		if l.Machine != nil {
			paired++
		}
	}
	if paired != 1 {
		t.Fatalf("one machine was paired with %d hosts", paired)
	}
}

func TestDanglingLinkIsNotSilentlyReplacedByAGuess(t *testing.T) {
	// The recorded machine is gone from Flipside -- re-imaged under a new id,
	// perhaps. Falling back to the hostname would quietly re-point the host at
	// a different machine; the link having stopped resolving is the thing worth
	// noticing.
	links, _ := Correlate(
		[]models.Host{host("web01", "gone")},
		[]Machine{{ID: "aa:bb", Hostname: "web01"}},
	)
	if links[0].Machine != nil {
		t.Fatalf("a dangling link fell back to a hostname guess (%s)", links[0].Machine.ID)
	}
	if links[0].How != "none" {
		t.Fatalf("how = %q, want none", links[0].How)
	}
}

func TestMachinesWithoutHostsAreReturned(t *testing.T) {
	// A machine Flipside knows about and Moorgate does not is usually one that
	// was imaged and never enrolled. Hiding it would hide the gap between the
	// two systems, which is precisely what the merged view exists to show.
	_, orphans := Correlate(nil, []Machine{{ID: "aa:bb", Hostname: "never-enrolled"}})
	if len(orphans) != 1 {
		t.Fatalf("expected the unenrolled machine to be reported, got %+v", orphans)
	}
}

func TestEmptyHostnamesDoNotMatchEachOther(t *testing.T) {
	// A host with no name and a machine that has not reported one are not the
	// same machine, and "" == "" would pair them.
	links, _ := Correlate([]models.Host{host("", "")}, []Machine{{ID: "aa:bb"}})
	if links[0].Machine != nil {
		t.Fatal("two empty hostnames were treated as a match")
	}
}
