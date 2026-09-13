package store

import "testing"

// The state six services were in, and the reason a rollout of them changed
// nothing.
//
// The container runs :latest. The compose file names v1.6.0-ls356. That is two
// rows behaving in opposite ways: rolling out :latest can only skip, because the
// host's compose has moved past it, while rolling out v1.6.0-ls356 rewrites the
// file and recreates the container.
//
// This list was built only from what the fleet RUNS, so the declared row — the
// one that could be applied — never reached the screen at all. The rebuild row
// was the only thing on offer, was rolled out, completed successfully, and did
// nothing.
func TestDeclaredRowsReachTheScreen(t *testing.T) {
	const repo = "lscr.io/linuxserver/bazarr"
	tracked := []TrackedImage{{Repository: repo, Tag: "latest", Digest: "sha256:old"}}
	checked := []ImageUpdate{
		{Repository: repo, Tag: "latest", Digest: "sha256:new"},
		{Repository: repo, Tag: "v1.6.0-ls356", Digest: "sha256:old",
			LatestTag: "v1.6.0-ls363", Declared: true},
	}
	byImage := map[string][]ImageUpdateHost{
		repo + ":latest": {{HostID: "h1", Hostname: "docker", Digest: "sha256:old"}},
	}

	rows := assembleImageRows(tracked, checked, byImage)

	var declared, running *ImageUpdateRow
	for i := range rows {
		switch rows[i].Tag {
		case "v1.6.0-ls356":
			declared = &rows[i]
		case "latest":
			running = &rows[i]
		}
	}
	if declared == nil {
		t.Fatalf("the only actionable row is missing; got %d row(s)", len(rows))
	}
	if len(declared.Hosts) != 1 || declared.Hosts[0].Hostname != "docker" {
		t.Errorf("hosts = %+v, want the host running the repository", declared.Hosts)
	}
	// A host not running this tag has no answer to "is your digest behind this
	// tag's", so calling it stale would invent one.
	if declared.Hosts[0].Stale {
		t.Error("a host that does not run this tag must not be called stale")
	}
	if running == nil {
		t.Fatal("the running row disappeared")
	}
	if !running.Hosts[0].Stale {
		t.Error("the running row's host IS behind its tag and should say so")
	}
}

func TestNoDeclaredRowOnceNothingRunsTheRepository(t *testing.T) {
	// ollama was replaced by llama.cpp. Its compose file still names it, behind a
	// profile, but nothing runs it — so there is nobody to offer it to.
	checked := []ImageUpdate{
		{Repository: "ollama/ollama", Tag: "0.31.2", LatestTag: "0.34.0", Declared: true},
	}
	rows := assembleImageRows(nil, checked, map[string][]ImageUpdateHost{})
	if len(rows) != 0 {
		t.Errorf("offered %d row(s) for a repository nothing runs: %+v", len(rows), rows)
	}
}

func TestADeclaredTagThatIsAlsoRunningIsOneRow(t *testing.T) {
	// The healthy case: pinned AND recreated. Emitting it twice would show the
	// same update as two different things to do.
	const repo = "team/app"
	tracked := []TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:a"}}
	checked := []ImageUpdate{{Repository: repo, Tag: "1.0.0", Digest: "sha256:a", Declared: true}}
	byImage := map[string][]ImageUpdateHost{
		repo + ":1.0.0": {{HostID: "h1", Hostname: "docker", Digest: "sha256:a"}},
	}
	if rows := assembleImageRows(tracked, checked, byImage); len(rows) != 1 {
		t.Errorf("got %d rows, want 1: %+v", len(rows), rows)
	}
}
