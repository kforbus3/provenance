package containerupdate

import (
	"context"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The Keycloak incident, reproduced.
//
// postgres 17.11-alpine -> 18.6-alpine was applied to a PG 17 data directory.
// The new binary refuses the directory and exits, so the container restarts
// forever -- but `docker ps` still lists it, carrying the NEW image and the NEW
// digest. Verification read that and recorded the host as verified while the
// database was down. It stayed down for twenty hours.
func TestAContainerThatIsRestartingIsNotVerified(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].TargetDigest = "sha256:wanted"
	// Right tag, right digest — and never once started.
	newEngine(f, &fakeDeployer{}, &fakeRunner{
		out: "::OK::\nnginx:1.27\tnginx\trestarting\tnginx@sha256:wanted\n",
	}).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State == store.UpdateHostVerified {
		t.Fatalf("a crash-looping container was recorded as verified — the exact failure this guards")
	}
	if !strings.Contains(h.Error, "restarting") || !strings.Contains(h.Error, "did not come up") {
		t.Errorf("the error should say the container never came up, got %q", h.Error)
	}
}

// A container that is up on the target digest still verifies. Without this the
// test above could be satisfied by refusing everything.
func TestARunningContainerOnTheTargetDigestStillVerifies(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].TargetDigest = "sha256:wanted"
	newEngine(f, &fakeDeployer{}, &fakeRunner{
		out: "::OK::\nnginx:1.27\tnginx\trunning\tnginx@sha256:wanted\n",
	}).Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("state = %q, want verified (error: %q)", got, f.hosts[rid][0].Error)
	}
}

// The llama.cpp incident, reproduced.
//
// One host ran the same repository in TWO containers. `llamacpp-embed` was
// already on the target tag; `llamacpp` sat on the tag the rollout was moving
// away from. Verification stopped at the first container matching the target and
// called the host verified, leaving the container the rollout existed to move
// completely untouched.
func TestASiblingLeftOnTheOldTagFailsTheHost(t *testing.T) {
	f, rid, _ := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	newEngine(f, &fakeDeployer{}, &fakeRunner{
		out: "::OK::\n" +
			"nginx:1.27\tnginx-embed\trunning\tnginx@sha256:new\n" +
			"nginx:1.24\tnginx\trunning\tnginx@sha256:old\n",
	}).Tick(context.Background())

	h := f.hosts[rid][0]
	if h.State == store.UpdateHostVerified {
		t.Fatalf("a host with a container still on the old tag was recorded as verified")
	}
	if !strings.Contains(h.Error, "nginx") || !strings.Contains(h.Error, "still running nginx:1.24") {
		t.Errorf("the error should name the container that did not move, got %q", h.Error)
	}
}

// A rebuild republishes the SAME tag, so every container legitimately sits on
// the tag being "moved away from". The sibling check must not fire there, or
// every rebuild would fail; the digest comparison is what separates old bytes
// from new.
func TestARebuildIsNotTreatedAsAStrandedSibling(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].FromTag = "1.27"
	f.rollouts[0].ToTag = "1.27"
	f.rollouts[0].TargetDigest = "sha256:rebuilt"
	// A rebuild targets the tag the host is ALREADY on, so both the running
	// container and the stack that defines it have to name it — otherwise the
	// rollout rightly skips the host as not applicable, and the check under test
	// is never reached.
	f.containers[ids[0]] = []models.Container{{
		Name: "nginx", Image: "nginx:1.27", Repository: "nginx", Tag: "1.27"}}
	f.stacks[ids[0]] = []store.ContainerStack{{
		ID: f.stacks[ids[0]][0].ID, HostID: ids[0], Enabled: true,
		Compose: "services:\n  web:\n    image: nginx:1.27\n"}}
	newEngine(f, &fakeDeployer{}, &fakeRunner{
		out: "::OK::\nnginx:1.27\tnginx\trunning\tnginx@sha256:rebuilt\n",
	}).Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Errorf("a correct rebuild should verify, got %q (error: %q)", got, f.hosts[rid][0].Error)
	}
}

// A runtime whose `ps` does not carry a state field must not fail every host:
// "we cannot tell" is not "the rollout failed".
func TestAnUnknownStateFieldDoesNotFailTheHost(t *testing.T) {
	got := parseVerifyOutput("::OK::\nnginx:1.27\tnginx\t\tnginx@sha256:x\n")
	if len(got) != 1 {
		t.Fatalf("parsed %d containers, want 1", len(got))
	}
	if !got[0].isRunning() {
		t.Error("a blank state should not read as not-running")
	}
}

func TestParseVerifyOutputSkipsMarkersAndShortLines(t *testing.T) {
	got := parseVerifyOutput("::OK::\nsome runtime warning\nnginx:1.27\tnginx\trunning\tnginx@sha256:x\n")
	if len(got) != 1 {
		t.Fatalf("parsed %d, want 1 (markers and chatter must be skipped)", len(got))
	}
	if got[0].name != "nginx" || len(got[0].digests) != 1 || got[0].digests[0] != "nginx@sha256:x" {
		t.Errorf("parsed wrong fields: %+v", got[0])
	}
}

// The questarr symptom, reproduced.
//
// A rebuild republishes the SAME tag, so the cached registry row is keyed by a
// tag that is still running and keeps matching the container it describes. The
// rebuild was applied correctly — pulled, recreated, on the new digest — and the
// Updates screen went on saying "rebuilt" for as long as the twelve-hour
// freshness window, which reads exactly like a rollout that did nothing.
func TestASuccessfulRolloutDropsTheStaleRegistryAnswer(t *testing.T) {
	f, rid, ids := fixture(1, store.UpdateRollout{Canary: 1, BatchSize: 1})
	f.rollouts[0].FromTag = "1.27"
	f.rollouts[0].ToTag = "1.27"
	f.rollouts[0].TargetDigest = "sha256:rebuilt"
	f.images[rid] = []store.RolloutImage{{
		Repository: "nginx", FromTag: "1.27", ToTag: "1.27",
		TargetDigest: "sha256:rebuilt"}}
	f.containers[ids[0]] = []models.Container{{
		Name: "nginx", Image: "nginx:1.27", Repository: "nginx", Tag: "1.27"}}
	f.stacks[ids[0]] = []store.ContainerStack{{
		ID: f.stacks[ids[0]][0].ID, HostID: ids[0], Enabled: true,
		Compose: "services:\n  web:\n    image: nginx:1.27\n"}}

	newEngine(f, &fakeDeployer{}, &fakeRunner{
		out: "::OK::\nnginx:1.27\tnginx\trunning\tnginx@sha256:rebuilt\n",
	}).Tick(context.Background())

	if got := f.hosts[rid][0].State; got != store.UpdateHostVerified {
		t.Fatalf("state = %q, want verified (error: %q)", got, f.hosts[rid][0].Error)
	}
	var found bool
	for _, k := range f.invalidated {
		if k == "nginx:1.27" {
			found = true
		}
	}
	if !found {
		t.Errorf("the stale registry answer for nginx:1.27 was not dropped; "+
			"a completed rebuild would keep reading as pending. invalidated=%v", f.invalidated)
	}
}

// An image answers to more than one digest, and the rollout targets the second.
//
// Docker Hub republished the python:3.14 INDEX — a platform or attestation change —
// while the amd64 image underneath it stayed byte-identical. A host that had pulled
// the tag before and after ended up with one image carrying two RepoDigests:
//
//	python@sha256:a2e978…   (the older index)
//	python@sha256:be8ccd…   (the one the rollout targets)
//
// and `docker inspect rag-api` confirmed it was running exactly that image id. Reading
// RepoDigests[0] picked the older one — Docker does not order them by recency — so the
// verification failed forever on a host that had done precisely what was asked, and the
// rollout halted with the remaining hosts left pending.
func TestVerifyAcceptsAnyOfAnImagesDigests(t *testing.T) {
	const (
		older  = "sha256:a2e9788143507cacbb754fcc06ad3b7108ca9c334f97a466906103846107cdd5"
		target = "sha256:be8ccd085666c34273c9dc5607c9842f8b2e3116128aae45148ce164c07ce09d"
	)
	// Exactly what the probe emits for such an image: both digests, comma-terminated.
	out := "::OK::\npython:3.14\trag-api\trunning\tpython@" + older + ",python@" + target + ",\n"
	got := parseVerifyOutput(out)
	if len(got) != 1 {
		t.Fatalf("parsed %d containers, want 1", len(got))
	}
	if len(got[0].digests) != 2 {
		t.Fatalf("parsed %d digests, want both: %+v", len(got[0].digests), got[0])
	}
	if !got[0].matches(target) {
		t.Errorf("the container is running the target image and was not recognised — "+
			"this is the rollout that could never pass: %+v", got[0])
	}
	if !got[0].matches(older) {
		t.Errorf("the older index digest names the same image and must also match: %+v", got[0])
	}
	if got[0].matches("sha256:deadbeef") {
		t.Error("an unrelated digest matched")
	}
	if got[0].matches("") {
		t.Error("an empty target matched, which would verify anything")
	}
}

// A locally built image has no registry digest at all. That is "cannot tell", and it
// must not read as a match.
func TestVerifyDoesNotMatchAnImageWithNoDigests(t *testing.T) {
	got := parseVerifyOutput("::OK::\nmyapp:1.0\tmyapp\trunning\t\n")
	if len(got) != 1 {
		t.Fatalf("parsed %d, want 1", len(got))
	}
	if got[0].matches("sha256:whatever") {
		t.Error("an image with no digests matched a target")
	}
}
