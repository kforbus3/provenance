package registry

import (
	"context"
	"encoding/json"
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
	tracked  []store.TrackedImage
	stale    []store.TrackedImage
	saved    []store.ImageUpdate
	pruned   [][]store.TrackedImage
	maxAgeIn time.Duration
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
		{Repository: repoAt(srv, "fleet-terminal-backend"), Tag: "1.2.3"}, // no digest
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
