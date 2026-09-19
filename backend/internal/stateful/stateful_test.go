package stateful

import (
	"testing"
)

func TestAMajorVersionBumpOfAStatefulImageIsRefused(t *testing.T) {
	// The exact move that took a Keycloak database down for twenty hours.
	if _, yes := MajorBump("postgres", "17.11-alpine", "18.6-alpine"); !yes {
		t.Error("postgres 17.11-alpine -> 18.6-alpine must be refused")
	}
	if _, yes := MajorBump("postgres", "16-alpine", "18-alpine"); !yes {
		t.Error("postgres 16-alpine -> 18-alpine must be refused")
	}
	if _, yes := MajorBump("mariadb", "11.4", "12.0"); !yes {
		t.Error("mariadb 11.4 -> 12.0 must be refused")
	}
}

func TestMinorAndPatchMovesOfStatefulImagesAreStillAllowed(t *testing.T) {
	// These carry the security fixes. Refusing them would make the guard worse
	// than the problem, by freezing databases on old patch levels.
	for _, c := range []struct{ from, to string }{
		{"17.11-alpine", "17.14-alpine"},
		{"17.11-alpine", "17.11-alpine"},
		{"16.2", "16.10"},
	} {
		if _, yes := MajorBump("postgres", c.from, c.to); yes {
			t.Errorf("postgres %s -> %s should be allowed", c.from, c.to)
		}
	}
}

func TestStatelessImagesAreNeverRefused(t *testing.T) {
	if _, yes := MajorBump("nginx", "1.24", "2.0"); yes {
		t.Error("nginx is not stateful; a major bump is an ordinary update")
	}
	// Shares a word with a database but keeps none of its data.
	if _, yes := MajorBump("my-postgres-backup", "1.0", "2.0"); yes {
		t.Error("substring matching would refuse unrelated images")
	}
	if _, yes := MajorBump("postgres-exporter", "1.0", "2.0"); yes {
		t.Error("postgres-exporter holds no data directory")
	}
}

func TestARegistryHostDoesNotHideAStatefulImage(t *testing.T) {
	for _, repo := range []string{
		"docker.io/library/postgres", "ghcr.io/postgres", "quay.io/postgres",
	} {
		if _, yes := MajorBump(repo, "17", "18"); !yes {
			t.Errorf("%s should still be recognised as postgres", repo)
		}
	}
}

func TestUnorderableTagsAreNotGuessedAt(t *testing.T) {
	// This refuses updates, so an unparseable tag must not be read as a major
	// change — that would block ordinary rebuilds.
	for _, c := range []struct{ from, to string }{
		{"latest", "latest"},
		{"stable", "18-alpine"},
		{"server-cuda-b10969", "server-cuda-b10975"},
	} {
		if _, yes := MajorBump("postgres", c.from, c.to); yes {
			t.Errorf("postgres %s -> %s is not orderable and must not be refused", c.from, c.to)
		}
	}
}

func TestARollbackIsNotRefusedAsAMajorBump(t *testing.T) {
	// Going backwards is a deliberate act, and not this check's business.
	if _, yes := MajorBump("postgres", "18-alpine", "17-alpine"); yes {
		t.Error("a rollback should not be refused by the forward-bump guard")
	}
}

func TestMajorVersionParsing(t *testing.T) {
	for _, c := range []struct {
		tag  string
		want int
		ok   bool
	}{
		{"17.11-alpine", 17, true},
		{"18-alpine", 18, true},
		{"v15.2", 15, true},
		{"8.0.36", 8, true},
		{"latest", 0, false},
		{"", 0, false},
		{"server-cuda-b10975", 0, false},
	} {
		got, ok := MajorVersion(c.tag)
		if got != c.want || ok != c.ok {
			t.Errorf("MajorVersion(%q) = (%d,%v), want (%d,%v)", c.tag, got, ok, c.want, c.ok)
		}
	}
}

// The guard has to stop a real rollout, not merely answer a question correctly.
// A rollout created before this rule existed is still in the database and will
// be picked up by a later tick, which is exactly how the Keycloak database was
// reached.
