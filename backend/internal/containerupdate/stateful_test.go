package containerupdate

import (
	"context"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

func TestADangerousPinInTheFileIsRefusedEvenWhenTheRolloutIsForSomethingElse(t *testing.T) {
	compose := "services:\n" +
		"  postgres:\n    image: postgres:18.6-alpine\n" +
		"  keycloak:\n    image: quay.io/keycloak/keycloak:26.7.4\n"
	running := []models.Container{
		{Name: "keycloak-db", Repository: "postgres", Tag: "17.11-alpine"},
		{Name: "keycloak", Repository: "quay.io/keycloak/keycloak", Tag: "26.7.3"},
	}
	why, bad := dangerousPin(compose, running)
	if !bad {
		t.Fatal("a file pinning postgres 18 over a running 17 was accepted")
	}
	for _, want := range []string{"postgres", "18.6-alpine", "17.11-alpine", "keycloak-db", "pg_upgrade"} {
		if !strings.Contains(why, want) {
			t.Errorf("the refusal does not mention %q, so it does not say what to fix:\n%s", want, why)
		}
	}
}

// The ordinary case must not be refused, or every deploy stops.

func TestAMatchingPinIsFine(t *testing.T) {
	compose := "services:\n" +
		"  postgres:\n    image: postgres:17.12-alpine\n" +
		"  keycloak:\n    image: quay.io/keycloak/keycloak:26.7.4\n"
	running := []models.Container{
		{Name: "keycloak-db", Repository: "postgres", Tag: "17.11-alpine"},
	}
	if why, bad := dangerousPin(compose, running); bad {
		t.Errorf("a minor bump within major 17 was refused: %s", why)
	}
}

// A stateless image crossing a major version is an ordinary update.

func TestANonStatefulMajorPinIsFine(t *testing.T) {
	compose := "services:\n  web:\n    image: nginx:2.0\n"
	running := []models.Container{{Name: "web", Repository: "nginx", Tag: "1.27"}}
	if why, bad := dangerousPin(compose, running); bad {
		t.Errorf("nginx 1 -> 2 was refused as if it owned its data: %s", why)
	}
}

// A registry host must not hide the match, or the check misses the very images
// it is for.

func TestTheRegistryHostDoesNotHideAStatefulImage(t *testing.T) {
	compose := "services:\n  db:\n    image: docker.io/library/postgres:18.6-alpine\n"
	running := []models.Container{{Name: "db", Repository: "postgres", Tag: "17.11-alpine"}}
	if _, bad := dangerousPin(compose, running); !bad {
		t.Error("docker.io/library/postgres was not matched against postgres")
	}
}

// Nothing running yet is not a conflict: a first deploy has no data directory
// to be incompatible with.

func TestNothingRunningIsNotDangerous(t *testing.T) {
	compose := "services:\n  db:\n    image: postgres:18.6-alpine\n"
	if _, bad := dangerousPin(compose, nil); bad {
		t.Error("a first deploy was refused")
	}
}

func TestTheEngineRefusesAStatefulMajorBumpItWasAskedToApply(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].Repository, f.rollouts[0].FromTag, f.rollouts[0].ToTag =
		"postgres", "17.11-alpine", "18.6-alpine"
	f.images[rid] = []store.RolloutImage{{
		Repository: "postgres", FromTag: "17.11-alpine", ToTag: "18.6-alpine"}}
	f.containers[ids[0]] = []models.Container{{
		Name: "keycloak-db", Image: "postgres:17.11-alpine",
		Repository: "postgres", Tag: "17.11-alpine"}}
	f.stacks[ids[0]] = []store.ContainerStack{{
		ID: f.stacks[ids[0]][0].ID, HostID: ids[0], Enabled: true,
		Compose: "services:\n  db:\n    image: postgres:17.11-alpine\n"}}

	d := &fakeDeployer{}
	newEngine(f, d, &fakeRunner{out: "::OK::\n"}).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State == store.UpdateHostVerified {
		t.Fatal("a postgres major bump was applied and verified")
	}
	if d.calls != 0 {
		t.Errorf("the deploy ran %d times; it must be refused before anything is changed", d.calls)
	}
	if !strings.Contains(h.Error, "crosses a major version") ||
		!strings.Contains(h.Error, "pg_upgrade") {
		t.Errorf("the error should say why and what it needs, got %q", h.Error)
	}
}

// The production failure this exists for, reproduced.
//
// A Keycloak rollout ran `docker compose up -d keycloak`; compose brought up its
// depends_on database too; the compose file still pinned postgres 18 against a
// version-17 data directory left by an earlier incident. Postgres 18 refuses a
// 17 data directory, so it crash-looped, the dependency never went healthy and
// Keycloak never started. Nothing in the rollout was a Postgres bump -- which is
// exactly why isStatefulMajorBump did not see it.
