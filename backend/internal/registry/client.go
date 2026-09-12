package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerHubHost is the registry a bare repository name refers to, and the reason
// this needs a special case at all: "nginx" means "docker.io/library/nginx", and
// the API for it lives on a different hostname than the name suggests.
const (
	dockerHubName = "docker.io"
	dockerHubAPI  = "registry-1.docker.io"
)

// Client talks to OCI registries.
//
// No Docker daemon and no credential helper: this asks the registry's HTTP API
// directly. Anonymous by default, which covers public images; a registry that
// requires credentials answers 401 and that is reported rather than retried,
// because "needs auth" and "does not exist" have different answers and guessing
// between them wastes an operator's time.
type Client struct {
	http *http.Client
	// tokens caches per-repository bearer tokens for the life of one sweep. A
	// registry issues one per scope and they are short-lived; re-fetching per
	// request would double the request count against a rate limit that is the
	// binding constraint here.
	tokens map[string]string
	// scheme is "https" everywhere except in tests, which serve a registry over
	// plain HTTP on loopback. It is not configurable from outside this package:
	// a registry reached over http would leak any token issued for it.
	scheme string
}

func New() *Client {
	return &Client{
		http:   &http.Client{Timeout: 30 * time.Second},
		tokens: map[string]string{},
		scheme: "https",
	}
}

// splitRepository turns a repository reference into the registry host to ask and
// the path to ask about.
//
// The rule is the one the Docker CLI uses and it is not obvious: the first
// component is a registry only if it contains a dot or a colon, or is
// "localhost". So "myteam/app" is Docker Hub, while "ghcr.io/myteam/app" is not
// -- and a rule that split on the first slash would send every Docker Hub image
// to a host that does not exist.
func splitRepository(repo string) (host, path string) {
	first, rest, ok := strings.Cut(repo, "/")
	if !ok || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		// Docker Hub. A single-component name is an official image, which lives
		// under library/.
		if !strings.Contains(repo, "/") {
			return dockerHubName, "library/" + repo
		}
		return dockerHubName, repo
	}
	return first, rest
}

func apiHost(host string) string {
	if host == dockerHubName {
		return dockerHubAPI
	}
	return host
}

// do performs a registry request, obtaining a bearer token if challenged.
func (c *Client) do(ctx context.Context, method, host, path, repo string, accept []string) (*http.Response, error) {
	build := func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, c.scheme+"://"+apiHost(host)+path, nil)
		if err != nil {
			return nil, err
		}
		// One comma-joined header, not repeated headers: a registry is only
		// required to read a single Accept, and one that does would see just the
		// first type offered and answer with a manifest this client did not ask
		// for -- or a 404 for a tag that exists.
		if len(accept) > 0 {
			req.Header.Set("Accept", strings.Join(accept, ", "))
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return req, nil
	}

	req, err := build(c.tokens[host+"/"+repo])
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Challenged. Read the realm and service out of the header and ask for a
	// token scoped to this repository.
	challenge := resp.Header.Get("Www-Authenticate")
	resp.Body.Close()
	token, terr := c.token(ctx, challenge, repo)
	if terr != nil {
		return nil, terr
	}
	c.tokens[host+"/"+repo] = token
	req, err = build(token)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// token exchanges a WWW-Authenticate challenge for a bearer token.
func (c *Client) token(ctx context.Context, challenge, repo string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return "", fmt.Errorf("this registry requires credentials (%s)", firstWord(challenge))
	}
	params := map[string]string{}
	for _, part := range strings.Split(challenge[len("bearer "):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[strings.ToLower(k)] = strings.Trim(v, `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("registry issued an authentication challenge with no realm")
	}
	q := url.Values{}
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+repo+":pull")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not obtain a registry token (%d) — this image may need credentials", resp.StatusCode)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Token != "" {
		return out.Token, nil
	}
	return out.AccessToken, nil
}

var manifestAccept = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// Digest resolves what a tag points at right now.
//
// A HEAD, so the manifest body is never transferred: the answer is in a header,
// and this runs across every image the fleet runs.
func (c *Client) Digest(ctx context.Context, repo, tag string) (string, error) {
	host, path := splitRepository(repo)
	resp, err := c.do(ctx, http.MethodHead, host, "/v2/"+path+"/manifests/"+tag, path, manifestAccept)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("no such tag %s in %s", tag, repo)
	case http.StatusTooManyRequests:
		return "", fmt.Errorf("the registry is rate limiting this instance; try again later or configure credentials")
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("this registry needs credentials for %s", repo)
	default:
		return "", fmt.Errorf("registry answered %d for %s:%s", resp.StatusCode, repo, tag)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", fmt.Errorf("registry returned no digest for %s:%s", repo, tag)
	}
	return d, nil
}

// Tags lists a repository's tags.
func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	host, path := splitRepository(repo)
	// n=1000: enough for any repository worth tracking, and a bound rather than
	// following pagination forever against a rate limit.
	resp, err := c.do(ctx, http.MethodGet, host, "/v2/"+path+"/tags/list?n=1000", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("the registry is rate limiting this instance; try again later or configure credentials")
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("this registry needs credentials for %s", repo)
	default:
		return nil, fmt.Errorf("registry answered %d listing tags for %s", resp.StatusCode, repo)
	}
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
