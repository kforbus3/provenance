package store

import (
	"testing"

	"github.com/google/uuid"
)

// The update the screen offers names a from-tag no container is running.
//
// Pinning a compose file to the version a container is ALREADY on recreates
// nothing, so between the pin and the next deploy the file says
// bazarr:v1.6.0-ls356 while the container is still on :latest. The registry
// check follows the file -- that is the version the operator chose -- so the
// rollout they are offered has a from-tag of v1.6.0-ls356.
//
// Matching only the running tag answered "no host is running
// lscr.io/linuxserver/bazarr:v1.6.0-ls356" and refused to create the rollout,
// for an update the screen had just offered.
func TestAHostCountsWhenItsComposeFileNamesTheTag(t *testing.T) {
	const repo = "lscr.io/linuxserver/bazarr"
	docker := uuid.New()

	runs := map[uuid.UUID]map[string]bool{docker: {repo: true}} // running :latest
	stacks := []hostCompose{{
		HostID:  docker,
		Compose: "services:\n  bazarr:\n    image: " + repo + ":v1.6.0-ls356\n",
	}}
	images := []RolloutImage{{Repository: repo, FromTag: "v1.6.0-ls356", ToTag: "v1.6.0-ls363"}}

	got := matchDeclaringHosts(runs, stacks, images)
	if len(got) != 1 || got[0] != docker {
		t.Fatalf("got %v, want the host whose compose names the tag", got)
	}
}

func TestAComposeFileCannotStartAServiceTheHostIsNotRunning(t *testing.T) {
	// A compose file may name a service that is scaled to zero or commented out
	// of the running project. Creating a rollout against it would start
	// something nobody asked to start.
	const repo = "team/app"
	host := uuid.New()

	runs := map[uuid.UUID]map[string]bool{host: {"other/thing": true}}
	stacks := []hostCompose{{
		HostID:  host,
		Compose: "services:\n  app:\n    image: " + repo + ":1.0.0\n",
	}}
	images := []RolloutImage{{Repository: repo, FromTag: "1.0.0", ToTag: "1.1.0"}}

	if got := matchDeclaringHosts(runs, stacks, images); len(got) != 0 {
		t.Errorf("got %v, want none — nothing on this host runs %s", got, repo)
	}
}

func TestADifferentTagInTheComposeFileDoesNotMatch(t *testing.T) {
	// The host has moved past this rollout. It must not be enrolled only to be
	// skipped as superseded on every tick.
	const repo = "team/app"
	host := uuid.New()

	runs := map[uuid.UUID]map[string]bool{host: {repo: true}}
	stacks := []hostCompose{{
		HostID:  host,
		Compose: "services:\n  app:\n    image: " + repo + ":2.0.0\n",
	}}
	images := []RolloutImage{{Repository: repo, FromTag: "1.0.0", ToTag: "1.1.0"}}

	if got := matchDeclaringHosts(runs, stacks, images); len(got) != 0 {
		t.Errorf("got %v, want none — this file names 2.0.0", got)
	}
}

func TestAHostIsListedOnceAcrossSeveralStacks(t *testing.T) {
	const repo = "team/app"
	host := uuid.New()
	runs := map[uuid.UUID]map[string]bool{host: {repo: true}}
	stacks := []hostCompose{
		{HostID: host, Compose: "services:\n  a:\n    image: " + repo + ":1.0.0\n"},
		{HostID: host, Compose: "services:\n  b:\n    image: " + repo + ":1.0.0\n"},
	}
	images := []RolloutImage{{Repository: repo, FromTag: "1.0.0", ToTag: "1.1.0"}}

	if got := matchDeclaringHosts(runs, stacks, images); len(got) != 1 {
		t.Errorf("got %v, want the host once", got)
	}
}
