package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/store"
)

type fakeStore struct {
	tracked      []store.TrackedImage
	stale        []store.TrackedImage
	composes     []string
	lastChecked  map[string]time.Time
	clock        time.Time
	tagCache     map[string][]string
	tagCacheAny  map[string][]string
	tagCachePuts map[string]int
	saved        []store.ImageUpdate
	pruned       [][]store.TrackedImage
	maxAgeIn     time.Duration
}

func (f *fakeStore) EnabledStackComposes(context.Context) ([]string, error) {
	return f.composes, nil
}

func (f *fakeStore) LastCheckedAt(context.Context) (map[string]time.Time, error) {
	return f.lastChecked, nil
}

func (f *fakeStore) CachedTags(_ context.Context, repo string, _ time.Duration) ([]string, bool, bool) {
	t, ok := f.tagCache[repo]
	return t, true, ok
}

func (f *fakeStore) AnyCachedTags(_ context.Context, repo string) ([]string, bool, bool) {
	t, ok := f.tagCacheAny[repo]
	return t, true, ok
}

func (f *fakeStore) PutCachedTags(_ context.Context, repo string, tags []string, _ bool) error {
	if f.tagCachePuts == nil {
		f.tagCachePuts = map[string]int{}
	}
	f.tagCachePuts[repo]++
	return nil
}

func (f *fakeStore) TrackedImages(context.Context) ([]store.TrackedImage, error) {
	return f.tracked, nil
}

func (f *fakeStore) StaleImageChecks(_ context.Context, imgs []store.TrackedImage, maxAge time.Duration) ([]store.TrackedImage, error) {
	f.maxAgeIn = maxAge
	if f.stale != nil {
		return f.stale, nil
	}
	return imgs, nil
}

func (f *fakeStore) UpsertImageUpdate(_ context.Context, in store.ImageUpdate) error {
	f.saved = append(f.saved, in)
	// Like the real store, which stamps checked_at on every write. Without this
	// a second pass would re-order on stale times and re-check the same images,
	// so the fake would hide exactly the bug the ordering exists to prevent.
	if f.lastChecked == nil {
		f.lastChecked = map[string]time.Time{}
	}
	f.clock = f.clock.Add(time.Second)
	f.lastChecked[in.Repository+":"+in.Tag] = f.clock
	return nil
}

func (f *fakeStore) PruneImageUpdates(_ context.Context, keep []store.TrackedImage) error {
	f.pruned = append(f.pruned, keep)
	return nil
}

// stubRegistry serves tag lists and digests with no auth, which is what an
// internal registry looks like.
func stubRegistry(t *testing.T, tags []string, digests map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			if tags == nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"tags": tags})
		case strings.Contains(r.URL.Path, "/manifests/"):
			tag := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			d, ok := digests[tag]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newChecker(t *testing.T, st Store, srv *httptest.Server) *Checker {
	t.Helper()
	c := NewChecker(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.client.http = srv.Client()
	c.client.scheme = "http"
	return c
}

func repoAt(srv *httptest.Server, name string) string {
	return strings.TrimPrefix(srv.URL, "http://") + "/" + name
}

func TestNewerVersionIsOffered(t *testing.T) {
	srv := stubRegistry(t, []string{"1.0.0", "1.1.0", "1.2.0"},
		map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}}

	checked, failed := newChecker(t, st, srv).Check(context.Background())
	if checked != 1 || failed != 0 {
		t.Fatalf("checked=%d failed=%d, want 1/0", checked, failed)
	}
	got := st.saved[0]
	if got.LatestTag != "1.2.0" {
		t.Errorf("latest = %q, want 1.2.0", got.LatestTag)
	}
	if got.Digest != "sha256:aaa" {
		t.Errorf("digest = %q", got.Digest)
	}
}

func TestMovedTagIsReportedEvenWithNoNewerVersion(t *testing.T) {
	// The case a version comparison alone cannot see: same tag, different bytes.
	// A base-image security rebuild republishes 1.0.0 in place, and an operator
	// who is only shown version numbers is told they are up to date.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:new"})
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:old"}}

	newChecker(t, st, srv).Check(context.Background())
	got := st.saved[0]
	if got.LatestTag != "" {
		t.Errorf("no newer version tag exists, got latest=%q", got.LatestTag)
	}
	if !strings.Contains(got.Note, "rebuilt at the same version") {
		t.Errorf("a moved tag must be reported, got note %q", got.Note)
	}
}

func TestMovedLatestTagIsReported(t *testing.T) {
	// "latest" carries no version information, so the digest IS the whole answer.
	srv := stubRegistry(t, []string{"latest"}, map[string]string{"latest": "sha256:new"})
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "latest", Digest: "sha256:old"}}

	newChecker(t, st, srv).Check(context.Background())
	got := st.saved[0]
	if !strings.Contains(got.Note, "tag moved") {
		t.Errorf("a moved latest must be reported, got note %q", got.Note)
	}
}

func TestUnversionedTagSkipsTagListing(t *testing.T) {
	// Listing every tag to find something "newer than latest" is a request that
	// can only produce noise, against a rate limit that matters.
	listed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			listed = true
		}
		w.Header().Set("Docker-Content-Digest", "sha256:same")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "stable", Digest: "sha256:same"}}

	newChecker(t, st, srv).Check(context.Background())
	if listed {
		t.Error("tags were listed for an unversioned tag")
	}
}

func TestTagListingFailureKeepsTheDigestAnswer(t *testing.T) {
	// Some registries serve manifests but refuse catalog listing. Half an answer
	// is still an answer, and must not be recorded as a total failure.
	srv := stubRegistry(t, nil, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}}

	checked, failed := newChecker(t, st, srv).Check(context.Background())
	if failed != 0 || checked != 1 {
		t.Fatalf("checked=%d failed=%d: a tag-listing refusal is not a failed check", checked, failed)
	}
	got := st.saved[0]
	if got.Error != "" {
		t.Errorf("error = %q, want empty", got.Error)
	}
	if got.Digest != "sha256:aaa" {
		t.Errorf("the digest answer must be kept, got %q", got.Digest)
	}
	if !strings.Contains(got.Note, "could not list tags") {
		t.Errorf("note should say what was missed, got %q", got.Note)
	}
}

func TestUnreachableRegistryIsRecordedNotDropped(t *testing.T) {
	// An image that could not be checked must never read as an image with nothing
	// newer available. Silence here means an operator believes they are current.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	st := &fakeStore{}
	repo := repoAt(srv, "team/app")
	// A digest, because this is an image that WAS pulled from a registry — the
	// case where a registry failure is real news. An image with no digest never
	// came from one and is not asked about at all.
	st.tracked = []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}}

	checked, failed := newChecker(t, st, srv).Check(context.Background())
	if failed != 1 || checked != 0 {
		t.Fatalf("checked=%d failed=%d, want 0/1", checked, failed)
	}
	if len(st.saved) != 1 || st.saved[0].Error == "" {
		t.Fatalf("the failure must be recorded against the image, got %+v", st.saved)
	}
}

func TestOneBadRegistryDoesNotStopThePass(t *testing.T) {
	good := stubRegistry(t, []string{"1.0.0", "2.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	st := &fakeStore{tracked: []store.TrackedImage{
		{Repository: repoAt(bad, "team/broken"), Tag: "1.0.0", Digest: "sha256:bbb"},
		{Repository: repoAt(good, "team/app"), Tag: "1.0.0", Digest: "sha256:aaa"},
	}}

	checked, failed := newChecker(t, st, good).Check(context.Background())
	if checked != 1 || failed != 1 {
		t.Fatalf("checked=%d failed=%d, want 1/1", checked, failed)
	}
	var sawGood bool
	for _, s := range st.saved {
		if s.LatestTag == "2.0.0" {
			sawGood = true
		}
	}
	if !sawGood {
		t.Error("the reachable registry's answer was lost when another failed")
	}
}

func TestBatchIsBounded(t *testing.T) {
	// A fleet with hundreds of distinct images must not spend them all in one
	// pass: the registry stops answering partway and every remaining image is
	// recorded as an error that looks like an outage.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{}
	for i := 0; i < checkBatch+25; i++ {
		st.tracked = append(st.tracked, store.TrackedImage{
			Repository: repoAt(srv, "team/app"), Tag: "1.0.0", Digest: "sha256:aaa"})
	}
	checked, failed := newChecker(t, st, srv).Check(context.Background())
	if checked+failed > checkBatch {
		t.Errorf("pass checked %d images, over the batch limit of %d",
			checked+failed, checkBatch)
	}
}

func TestPruneRunsBeforeChecking(t *testing.T) {
	// Pruning after would spend the pass budget on images nothing runs.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{tracked: []store.TrackedImage{
		{Repository: repoAt(srv, "team/app"), Tag: "1.0.0", Digest: "sha256:aaa"}}}
	newChecker(t, st, srv).Check(context.Background())
	if len(st.pruned) != 1 {
		t.Fatalf("prune ran %d times, want 1", len(st.pruned))
	}
	if len(st.pruned[0]) != 1 {
		t.Errorf("prune must be given every tracked image to keep, got %d", len(st.pruned[0]))
	}
}

func TestNoTrackedImagesPrunesNothing(t *testing.T) {
	// An empty inventory is far more likely to be a collection outage than a
	// fleet that runs no containers. Pruning on that signal deletes the history.
	srv := stubRegistry(t, nil, nil)
	st := &fakeStore{}
	newChecker(t, st, srv).Check(context.Background())
	if len(st.pruned) != 0 {
		t.Error("pruned with an empty tracked list")
	}
}

func TestALocallyBuiltImageIsNotAskedAboutAtAll(t *testing.T) {
	// Docker records RepoDigests only for images it PULLED, so a locally built
	// one has none. Asking a registry about it is worse than useless: a bare name
	// resolves to Docker Hub, the repository does not exist there, and Hub answers
	// 401 — which surfaces as "needs credentials" and sends an operator to
	// configure credentials that cannot help. On the host running this product
	// that was ten rows out of thirteen.
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	st := &fakeStore{tracked: []store.TrackedImage{
		{Repository: repoAt(srv, "provenance-backend"), Tag: "1.2.3"}, // no digest
	}}
	checked, failed := newChecker(t, st, srv).Check(context.Background())

	if asked {
		t.Error("a registry was asked about an image that was never pulled from one")
	}
	if failed != 0 {
		t.Errorf("failed=%d — a locally built image is not a failed check", failed)
	}
	if checked != 1 {
		t.Errorf("checked=%d, want 1", checked)
	}
	got := st.saved[0]
	if got.Error != "" {
		t.Errorf("recorded an error for a locally built image: %q", got.Error)
	}
	if !strings.Contains(got.Note, "built locally") {
		t.Errorf("the row should say why it cannot be checked, got note %q", got.Note)
	}
}

// The button that did nothing whenever it was most wanted.
//
// "Check registries now" ran the same pass as the scheduler, freshness window and
// all — so pressing it after changing something, which is the only reason anyone
// presses it, re-asked nothing and reported success.
func TestCheckNowIgnoresTheFreshnessWindow(t *testing.T) {
	srv := stubRegistry(t, []string{"1.0.0", "2.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	repo := repoAt(srv, "team/app")

	st := &fakeStore{
		tracked: []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}},
		// Everything is fresh: the scheduled pass would select nothing.
		stale: []store.TrackedImage{},
	}
	c := newChecker(t, st, srv)

	if checked, _ := c.Check(context.Background()); checked != 0 {
		t.Fatalf("fixture wrong: the scheduled pass checked %d", checked)
	}
	checked, _, _ := c.CheckNow(context.Background())
	if checked != 1 {
		t.Errorf("a forced check re-asked %d images; the window must not apply to "+
			"somebody who has just pressed the button", checked)
	}
}

func TestAForcedCheckIsStillBounded(t *testing.T) {
	// A press finishes the job, but not at any price: the budget is bounded, and
	// a pass that hits the bound reports what is left rather than quietly doing
	// part of the work and saying nothing.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{stale: []store.TrackedImage{}, lastChecked: map[string]time.Time{}, clock: time.Now()}
	over := forcedBatches*checkBatch + 7
	for i := 0; i < over; i++ {
		st.tracked = append(st.tracked, store.TrackedImage{
			Repository: repoAt(srv, fmt.Sprintf("team/app%03d", i)),
			Tag:        "1.0.0", Digest: "sha256:aaa"})
	}
	checked, failed, remaining := newChecker(t, st, srv).CheckNow(context.Background())
	if checked+failed > forcedBatches*checkBatch {
		t.Errorf("checked %d, over the budget of %d", checked+failed, forcedBatches*checkBatch)
	}
	if remaining != 7 {
		t.Errorf("remaining = %d, want 7 — an operator should know the pass was "+
			"not the whole fleet", remaining)
	}
}

// The situation this exists for, reproduced with the real shape it had on the
// fleet: every compose file correctly pinned, and the containers still running
// the floating tag they were created from because pinning a file to the version
// a container is ALREADY on recreates nothing.
//
// Asked about under ":latest", the only answer available is "latest moved
// again" — so v1.6.0-ls356 was never compared against anything, and the newer
// version sitting in the registry was invisible. Thirteen services across two
// hosts were in exactly that state.
func TestAPinnedTagIsCheckedEvenWhileTheContainerStillRunsLatest(t *testing.T) {
	srv := stubRegistry(t,
		[]string{"v1.6.0-ls356", "v1.7.1-ls372", "latest"},
		map[string]string{"latest": "sha256:aaa", "v1.6.0-ls356": "sha256:aaa"})
	repo := repoAt(srv, "linuxserver/bazarr")

	st := &fakeStore{
		tracked:  []store.TrackedImage{{Repository: repo, Tag: "latest", Digest: "sha256:aaa"}},
		composes: []string{"services:\n  bazarr:\n    image: " + repo + ":v1.6.0-ls356\n"},
	}

	newChecker(t, st, srv).Check(context.Background())

	var pinned *store.ImageUpdate
	for i := range st.saved {
		if st.saved[i].Tag == "v1.6.0-ls356" {
			pinned = &st.saved[i]
		}
	}
	if pinned == nil {
		t.Fatalf("the pinned tag was never checked; saved %d row(s): %+v", len(st.saved), st.saved)
	}
	if pinned.LatestTag != "v1.7.1-ls372" {
		t.Errorf("latest = %q, want v1.7.1-ls372 — the upgrade the operator could not see",
			pinned.LatestTag)
	}
	if !strings.Contains(pinned.Note, "still running latest") {
		t.Errorf("the note should say the container has not caught up yet, got %q", pinned.Note)
	}
}

func TestTheRunningTagIsStillCheckedAlongsideThePin(t *testing.T) {
	// Another host may legitimately run the same repository unpinned, and a tag
	// that moved under it is a true fact worth keeping. The declared row answers
	// a different question, so it is carried as a different row rather than
	// replacing this one.
	srv := stubRegistry(t, []string{"1.0.0", "latest"},
		map[string]string{"latest": "sha256:new", "1.0.0": "sha256:aaa"})
	repo := repoAt(srv, "team/app")

	st := &fakeStore{
		tracked:  []store.TrackedImage{{Repository: repo, Tag: "latest", Digest: "sha256:old"}},
		composes: []string{"services:\n  app:\n    image: " + repo + ":1.0.0\n"},
	}
	newChecker(t, st, srv).Check(context.Background())

	var sawLatest bool
	for _, r := range st.saved {
		if r.Tag == "latest" && strings.Contains(r.Note, "older build") {
			sawLatest = true
		}
	}
	if !sawLatest {
		t.Errorf("the running tag's moved-tag answer was lost: %+v", st.saved)
	}
}

func TestADeclaredTagSaysNothingAboutRebuilds(t *testing.T) {
	// The digest borrowed for a declared row is the RUNNING container's, because
	// it is the only one the fleet has. Comparing it against the declared tag's
	// digest would answer a question nobody asked — "did the bytes behind a tag
	// this host never pulled change" — and phrase the answer as though the host
	// had pulled it.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:different"})
	repo := repoAt(srv, "team/app")

	st := &fakeStore{
		tracked:  []store.TrackedImage{{Repository: repo, Tag: "latest", Digest: "sha256:running"}},
		composes: []string{"services:\n  app:\n    image: " + repo + ":1.0.0\n"},
	}
	newChecker(t, st, srv).Check(context.Background())

	for _, r := range st.saved {
		if r.Tag == "1.0.0" && strings.Contains(r.Note, "rebuilt") {
			t.Errorf("a declared tag must not claim a rebuild: %q", r.Note)
		}
	}
}

func TestNoDeclaredRowForARepositoryNothingRuns(t *testing.T) {
	// A compose file may name a service that is scaled to zero or commented out
	// of the running project. Asking a registry about it spends a rate-limited
	// request on nobody's behalf.
	tracked := []store.TrackedImage{{Repository: "team/app", Tag: "latest", Digest: "sha256:aaa"}}
	extras := declaredExtras(tracked,
		[]string{"services:\n  other:\n    image: team/unrelated:2.0.0\n"})
	if len(extras) != 0 {
		t.Errorf("asked about %d image(s) nothing runs: %+v", len(extras), extras)
	}
}

func TestNoDeclaredRowWhenTheContainerAlreadyMatches(t *testing.T) {
	// The ordinary, healthy case: pinned AND recreated. One row, not two.
	tracked := []store.TrackedImage{{Repository: "team/app", Tag: "1.0.0", Digest: "sha256:aaa"}}
	extras := declaredExtras(tracked,
		[]string{"services:\n  app:\n    image: team/app:1.0.0\n"})
	if len(extras) != 0 {
		t.Errorf("duplicated a tag that is already being checked: %+v", extras)
	}
}

// The batch cap means some images wait. Which ones wait must not be decided by
// where they happen to sit in a list.
//
// Tracked images arrive ordered by name with compose-declared ones appended
// after them. On a live fleet that was 64 images against a cap of 40, so every
// declared row sat in positions 52-64 and was cut every time — and on a FORCED
// pass, which ignores freshness and re-offers the same first 40, it would have
// been cut forever. The operator pressing the button never sees the rows they
// pressed it for.
func TestNeverCheckedImagesGoFirst(t *testing.T) {
	now := time.Now()
	imgs := []store.TrackedImage{
		{Repository: "a/one", Tag: "1"},
		{Repository: "b/two", Tag: "1"},
		{Repository: "z/new", Tag: "1"}, // never checked: no entry below
		{Repository: "c/three", Tag: "1"},
	}
	last := map[string]time.Time{
		"a/one:1":   now.Add(-time.Hour),
		"b/two:1":   now.Add(-3 * time.Hour),
		"c/three:1": now.Add(-2 * time.Hour),
	}
	got := leastRecentlyCheckedFirst(imgs, last)
	want := []string{"z/new", "b/two", "c/three", "a/one"}
	for i, w := range want {
		if got[i].Repository != w {
			t.Errorf("position %d = %s, want %s (order: %v)", i, got[i].Repository, w,
				[]string{got[0].Repository, got[1].Repository, got[2].Repository, got[3].Repository})
		}
	}
}

func TestADeclaredRowIsNotStarvedByTheBatchCap(t *testing.T) {
	// The whole pass, with more images than one batch can hold and the declared
	// row last in line — exactly the shape that made a forced recheck useless.
	srv := stubRegistry(t, []string{"1.0.0", "1.1.0", "latest"},
		map[string]string{"latest": "sha256:aaa", "1.0.0": "sha256:aaa"})
	repo := repoAt(srv, "team/app")

	st := &fakeStore{
		composes:    []string{"services:\n  app:\n    image: " + repo + ":1.0.0\n"},
		lastChecked: map[string]time.Time{},
	}
	// Fill the batch with images already checked, so the declared row can only
	// be reached by ordering rather than by luck.
	for i := 0; i < checkBatch; i++ {
		filler := store.TrackedImage{
			Repository: repoAt(srv, "filler/app"), Tag: "1.0.0", Digest: "sha256:aaa"}
		filler.Repository += string(rune('a' + i%26))
		st.tracked = append(st.tracked, filler)
		st.lastChecked[filler.Repository+":1.0.0"] = time.Now().Add(-time.Minute)
	}
	st.tracked = append(st.tracked,
		store.TrackedImage{Repository: repo, Tag: "latest", Digest: "sha256:aaa"})
	st.lastChecked[repo+":latest"] = time.Now().Add(-time.Minute)

	newChecker(t, st, srv).CheckNow(context.Background())

	for _, r := range st.saved {
		if r.Repository == repo && r.Tag == "1.0.0" {
			return // reached, which is the whole point
		}
	}
	t.Errorf("the declared row was never reached in %d checked row(s)", len(st.saved))
}

// One press, the whole fleet.
//
// The batch cap is about a registry's rate limit and still governs each pass.
// What it must not do is turn a deliberate press into PART of the work: 64
// images against a cap of 40 left 24 unchecked, the count went to a log line,
// and the operator had no way to know a second press was needed. jackett and
// prowlarr sat in that remainder with real updates waiting behind them.
func TestAForcedCheckFinishesTheWholeFleet(t *testing.T) {
	srv := stubRegistry(t, []string{"1.0.0", "1.1.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{lastChecked: map[string]time.Time{}, clock: time.Now()}

	const total = checkBatch + 24 // the shape the fleet was actually in
	for i := 0; i < total; i++ {
		st.tracked = append(st.tracked, store.TrackedImage{
			Repository: repoAt(srv, fmt.Sprintf("team/app%03d", i)),
			Tag:        "1.0.0", Digest: "sha256:aaa",
		})
	}

	checked, failed, remaining := newChecker(t, st, srv).CheckNow(context.Background())

	if remaining != 0 {
		t.Errorf("left %d image(s) unchecked after a deliberate press", remaining)
	}
	if failed != 0 {
		t.Errorf("failed=%d", failed)
	}
	if checked != total {
		t.Errorf("checked %d of %d", checked, total)
	}
	// Every image, not the first batch twice.
	seen := map[string]bool{}
	for _, r := range st.saved {
		seen[r.Repository] = true
	}
	if len(seen) != total {
		t.Errorf("reached %d distinct image(s), want %d — the passes re-checked the same ones",
			len(seen), total)
	}
}

func TestTheScheduledSweepStillRespectsTheBatchCap(t *testing.T) {
	// Only a press finishes the job. The unattended sweep stays bounded, because
	// the cap is there to keep a fleet-wide pass from exhausting a rate limit
	// nobody is watching.
	srv := stubRegistry(t, []string{"1.0.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	st := &fakeStore{lastChecked: map[string]time.Time{}, clock: time.Now()}
	for i := 0; i < checkBatch+5; i++ {
		st.tracked = append(st.tracked, store.TrackedImage{
			Repository: repoAt(srv, fmt.Sprintf("team/app%03d", i)),
			Tag:        "1.0.0", Digest: "sha256:aaa",
		})
	}
	checked, _ := newChecker(t, st, srv).Check(context.Background())
	if checked != checkBatch {
		t.Errorf("a scheduled sweep checked %d, want the cap of %d", checked, checkBatch)
	}
}

// Twenty-two healthy images read as "cannot compare" because the client was
// inferring a verdict from the NOTE, and "nothing newer with the same shape as
// 10.11.11; the repository carries other version tags that cannot be ordered
// against it" is prose that means "up to date". Prose is not an API — that text
// changed twice in one evening.
func TestCheckedAndCurrentIsNotTheSameAsCouldNotCheck(t *testing.T) {
	// Versions of two different shapes: 1.0.0 is current, and the repository
	// also carries dated tags that cannot be ordered against it.
	srv := stubRegistry(t, []string{"1.0.0", "2026.01.01", "latest"},
		map[string]string{"1.0.0": "sha256:aaa"})
	repo := repoAt(srv, "team/app")
	st := &fakeStore{tracked: []store.TrackedImage{
		{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}}}

	newChecker(t, st, srv).Check(context.Background())

	got := st.saved[0]
	if got.Status != store.ImageStatusCurrent {
		t.Errorf("status = %q, want %q — it was checked and nothing newer of the "+
			"same shape exists; note was %q", got.Status, store.ImageStatusCurrent, got.Note)
	}
}

func TestARepositoryWithNothingComparableSaysSo(t *testing.T) {
	// Genuinely different: no tag here shares a shape with the running one.
	srv := stubRegistry(t, []string{"alpha", "2026.01.01"},
		map[string]string{"1.0.0-rc1": "sha256:aaa"})
	repo := repoAt(srv, "team/app")
	st := &fakeStore{tracked: []store.TrackedImage{
		{Repository: repo, Tag: "1.0.0-rc1", Digest: "sha256:aaa"}}}

	newChecker(t, st, srv).Check(context.Background())

	if got := st.saved[0].Status; got != store.ImageStatusUnorderable {
		t.Errorf("status = %q, want %q (note %q)", got, store.ImageStatusUnorderable, st.saved[0].Note)
	}
}

func TestATagListingIsReusedRatherThanRefetched(t *testing.T) {
	// Following pagination made a listing correct and made it cost up to 32
	// requests per repository. A forced sweep is then hundreds of requests to one
	// registry, and pressing the button twice in an hour rate-limits the
	// instance — which reports as "could not list tags" against images that are
	// fine.
	srv := stubRegistry(t, []string{"1.0.0", "1.1.0"}, map[string]string{"1.0.0": "sha256:aaa"})
	repo := repoAt(srv, "team/app")
	st := &fakeStore{
		tracked:  []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}},
		tagCache: map[string][]string{repo: {"1.0.0", "1.1.0", "1.2.0"}},
	}
	newChecker(t, st, srv).Check(context.Background())

	// The cached listing carries 1.2.0, which the live stub does not — so the
	// answer proves the cache was used rather than the registry.
	if got := st.saved[0].LatestTag; got != "1.2.0" {
		t.Errorf("latest = %q, want 1.2.0 from the cached listing", got)
	}
	if st.tagCachePuts[repo] != 0 {
		t.Errorf("re-fetched and re-cached a listing that was still fresh")
	}
}

func TestARateLimitedListingFallsBackToWhatIsKnown(t *testing.T) {
	// A stale list beats no list: "what was published as of this morning" is a
	// better answer than "could not check" against an image that is fine.
	srv := stubRegistry(t, nil, map[string]string{"1.0.0": "sha256:aaa"}) // tags 403
	repo := repoAt(srv, "team/app")
	st := &fakeStore{
		tracked:     []store.TrackedImage{{Repository: repo, Tag: "1.0.0", Digest: "sha256:aaa"}},
		tagCacheAny: map[string][]string{repo: {"1.0.0", "1.1.0"}},
	}
	newChecker(t, st, srv).Check(context.Background())

	if got := st.saved[0].LatestTag; got != "1.1.0" {
		t.Errorf("latest = %q, want 1.1.0 from the last known listing (note %q)",
			got, st.saved[0].Note)
	}
}

// The digest carried on a declared row is the RUNNING container's, because it is
// the only one the fleet has. "This host pulled something else" is a claim about
// a tag the host has never pulled — and a rate-limited registry put that
// sentence on every declared row at once.
func TestARateLimitedDeclaredRowMakesNoClaimAboutWhatWasPulled(t *testing.T) {
	srv := stubRegistry(t, nil, map[string]string{"v1.6.0-ls363": "sha256:different"})
	repo := repoAt(srv, "linuxserver/bazarr")
	st := &fakeStore{
		tracked: []store.TrackedImage{{
			Repository: repo, Tag: "v1.6.0-ls363", Digest: "sha256:running",
			Declared: true, RunningTag: "latest",
		}},
	}
	newChecker(t, st, srv).Check(context.Background())

	if got := st.saved[0].Note; strings.Contains(got, "pulled") {
		t.Errorf("a declared row claims something about what the host pulled: %q", got)
	}
}
