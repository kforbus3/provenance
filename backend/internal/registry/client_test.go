package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSplitRepository(t *testing.T) {
	// The rule that decides these is not "split on the first slash". Getting it
	// wrong sends every Docker Hub image to a hostname that does not resolve,
	// and every private-registry image to Docker Hub.
	cases := []struct {
		repo, host, path string
		why              string
	}{
		{"nginx", dockerHubName, "library/nginx",
			"a bare name is an official Docker Hub image under library/"},
		{"grafana/grafana", dockerHubName, "grafana/grafana",
			"one slash with no dot in the first part is still Docker Hub"},
		{"ghcr.io/kforbus3/app", "ghcr.io", "kforbus3/app",
			"a dot in the first component makes it a registry host"},
		{"registry.example.com/tools/aptly", "registry.example.com", "tools/aptly",
			"an internal registry is recognised by the dot too"},
		{"localhost:5000/app", "localhost:5000", "app",
			"localhost is a registry even though it has no dot"},
		{"localhost/app", "localhost", "app",
			"bare localhost is special-cased by name"},
		{"repo:5000/team/app", "repo:5000", "team/app",
			"a port makes a dotless name a registry"},
	}
	for _, c := range cases {
		host, path := splitRepository(c.repo)
		if host != c.host || path != c.path {
			t.Errorf("%s: splitRepository(%q) = %q, %q; want %q, %q",
				c.why, c.repo, host, path, c.host, c.path)
		}
	}
}

func TestAPIHostRewritesDockerHub(t *testing.T) {
	// docker.io is not a registry API endpoint. Requests to it do not work.
	if got := apiHost(dockerHubName); got != dockerHubAPI {
		t.Errorf("docker.io must be asked at %s, got %s", dockerHubAPI, got)
	}
	if got := apiHost("ghcr.io"); got != "ghcr.io" {
		t.Errorf("every other registry is asked at its own name, got %s", got)
	}
}

// newTestRegistry stands up a registry that challenges for a token exactly the
// way a real one does, so the challenge->token->retry path is exercised rather
// than assumed.
func newTestRegistry(t *testing.T, tags []string, digest string) (*httptest.Server, *int) {
	t.Helper()
	tokenRequests := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		if got := r.URL.Query().Get("scope"); got != "repository:team/app:pull" {
			t.Errorf("token must be scoped to the repository, got %q", got)
		}
		if got := r.URL.Query().Get("service"); got != "test-registry" {
			t.Errorf("service from the challenge must be echoed, got %q", got)
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok-123"})
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+srv.URL+`/token",service="test-registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			json.NewEncoder(w).Encode(map[string]any{"tags": tags})
		case strings.Contains(r.URL.Path, "/manifests/"):
			if r.Method != http.MethodHead {
				t.Errorf("manifests must be fetched with HEAD, got %s", r.Method)
			}
			if !strings.Contains(r.Header.Get("Accept"), "manifest.v1+json") {
				t.Errorf("Accept must offer OCI manifests, got %q", r.Header.Get("Accept"))
			}
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return srv, &tokenRequests
}

// testClient points the client at a local test server. splitRepository would
// otherwise send "127.0.0.1:PORT/team/app" over TLS.
func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := New()
	c.http = srv.Client()
	c.scheme = "http"
	return c
}

func TestTokenChallengeFlow(t *testing.T) {
	const dg = "sha256:3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed"
	srv, tokenRequests := newTestRegistry(t, []string{"1.0", "1.1"}, dg)
	c := testClient(t, srv)
	repo := strings.TrimPrefix(srv.URL, "http://") + "/team/app"

	got, err := c.Digest(context.Background(), repo, "1.1")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != dg {
		t.Errorf("digest = %q, want %q", got, dg)
	}
	if *tokenRequests != 1 {
		t.Fatalf("expected one token request, got %d", *tokenRequests)
	}

	// A second call to the same repository must reuse the token. Registries rate
	// limit, and a sweep over a fleet multiplies every avoidable request.
	if _, err := c.Tags(context.Background(), repo); err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if *tokenRequests != 1 {
		t.Errorf("token was re-fetched (%d requests); it must be cached per repository",
			*tokenRequests)
	}
}

func TestTagsListed(t *testing.T) {
	srv, _ := newTestRegistry(t, []string{"1.0", "1.1", "latest"}, "sha256:x")
	c := testClient(t, srv)
	tags, err := c.Tags(context.Background(),
		strings.TrimPrefix(srv.URL, "http://")+"/team/app")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 3 {
		t.Errorf("tags = %v, want 3", tags)
	}
}

func TestErrorsAreActionable(t *testing.T) {
	// An operator seeing "registry answered 401" cannot tell whether the image is
	// gone, private, or the instance is rate limited. Those have different
	// answers, so each must say which one it is.
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusNotFound, "no such tag"},
		{http.StatusTooManyRequests, "rate limiting"},
		{http.StatusForbidden, "needs credentials"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status) }))
		c := testClient(t, srv)
		_, err := c.Digest(context.Background(),
			strings.TrimPrefix(srv.URL, "http://")+"/team/app", "1.0")
		if err == nil {
			t.Errorf("status %d: expected an error", tc.status)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d: error %q does not say %q", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

func TestBasicChallengeIsReportedNotRetried(t *testing.T) {
	// A registry asking for Basic auth is asking for credentials this client does
	// not have. Reporting that is useful; retrying it forever is not.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Basic realm="private"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := testClient(t, srv)
	_, err := c.Digest(context.Background(),
		strings.TrimPrefix(srv.URL, "http://")+"/team/app", "1.0")
	if err == nil || !strings.Contains(err.Error(), "requires credentials") {
		t.Errorf("Basic challenge should report needing credentials, got %v", err)
	}
}

func TestMissingDigestHeaderIsAnError(t *testing.T) {
	// A 200 with no digest header means the answer is unusable. Returning "" as
	// though it were a digest would store an empty digest as the current state
	// and make every later comparison report a change.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := testClient(t, srv)
	got, err := c.Digest(context.Background(),
		strings.TrimPrefix(srv.URL, "http://")+"/team/app", "1.0")
	if err == nil {
		t.Errorf("expected an error, got digest %q", got)
	}
}
