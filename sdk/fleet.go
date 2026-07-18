// Package fleet is the official Go client for the Fleet Terminal API.
//
// It wraps the REST API under /api/v1 and authenticates with a service-account
// API token (the "flt_" bearer token issued from Settings → Service Accounts, or
// via CreateToken here). Everything the CLI (cmd/fleet) does is built on this
// package, and it is safe for use in CI jobs, schedulers, and custom tooling.
//
// The package depends only on the standard library.
//
// Basic use:
//
//	c, err := fleet.New("https://fleet.example.com", fleet.WithToken(os.Getenv("FLEET_API_TOKEN")))
//	if err != nil { log.Fatal(err) }
//	hosts, err := c.ListHosts(ctx, fleet.ListOptions{})
//
// The zero value of Client is not usable; construct one with New.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent identifies this client to the server. Callers may override it
// with WithUserAgent (e.g. the CLI appends its version).
const DefaultUserAgent = "fleet-go-sdk"

// Client talks to a Fleet Terminal deployment. It is safe for concurrent use.
type Client struct {
	baseURL   string // normalized, no trailing slash, includes scheme+host
	apiPrefix string // "/api/v1"
	token     string
	userAgent string
	http      *http.Client
}

// Option configures a Client in New.
type Option func(*Client)

// WithToken sets the service-account API token sent as "Authorization: Bearer".
func WithToken(token string) Option {
	return func(c *Client) { c.token = strings.TrimSpace(token) }
}

// WithHTTPClient supplies a custom *http.Client (timeouts, proxies, custom TLS).
// If unset, a client with a 60s timeout is used.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// New creates a Client for the deployment at baseURL (e.g. "https://fleet.example.com").
// The "/api/v1" prefix is added automatically; a baseURL that already ends in it
// is accepted too.
func New(baseURL string, opts ...Option) (*Client, error) {
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return nil, errors.New("fleet: baseURL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("fleet: invalid baseURL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("fleet: invalid baseURL %q: missing host", baseURL)
	}
	// Fold a caller-supplied /api/v1 suffix into the prefix so both forms work.
	path := strings.TrimRight(u.Path, "/")
	path = strings.TrimSuffix(path, "/api/v1")
	base := u.Scheme + "://" + u.Host + path

	c := &Client{
		baseURL:   strings.TrimRight(base, "/"),
		apiPrefix: "/api/v1",
		userAgent: DefaultUserAgent,
		http:      &http.Client{Timeout: 60 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// APIError is returned when the server responds with a non-2xx status. It carries
// the HTTP status and the server's error message (from the {"error": "..."} body).
type APIError struct {
	StatusCode int
	Message    string
	// Method and Path identify the request that failed, for diagnostics.
	Method string
	Path   string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("fleet: %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("fleet: %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

// IsNotFound reports whether err is an APIError with a 404 status.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

// IsUnauthorized reports whether err is an APIError with a 401/403 status —
// typically a missing, expired, or under-scoped API token.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.StatusCode == http.StatusUnauthorized || ae.StatusCode == http.StatusForbidden)
}

// ListOptions carries pagination for list endpoints. Zero values mean "server
// default" (Limit) and "from the start" (Offset).
type ListOptions struct {
	Limit  int
	Offset int
}

func (o ListOptions) query() url.Values {
	v := url.Values{}
	if o.Limit > 0 {
		v.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Offset > 0 {
		v.Set("offset", strconv.Itoa(o.Offset))
	}
	return v
}

// do executes a request against apiPrefix+path. If body is non-nil it is JSON
// encoded. If out is non-nil the JSON response is decoded into it. query may be
// nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	full := c.baseURL + c.apiPrefix + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fleet: encode request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, full, reader)
	if err != nil {
		return fmt.Errorf("fleet: build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleet: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.parseError(resp, method, path)
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("fleet: decode response for %s %s: %w", method, path, err)
	}
	return nil
}

// doRaw is like do but returns the raw response body (used for CSV report
// downloads). The caller owns closing via the returned bytes (already read).
func (c *Client) doRaw(ctx context.Context, method, path string, query url.Values, accept string) ([]byte, error) {
	full := c.baseURL + c.apiPrefix + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, full, nil)
	if err != nil {
		return nil, fmt.Errorf("fleet: build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fleet: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.parseError(resp, method, path)
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) parseError(resp *http.Response, method, path string) error {
	ae := &APIError{StatusCode: resp.StatusCode, Method: method, Path: path}
	// The API reports errors as {"error": "..."}; fall back to raw text.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &body) == nil && body.Error != "" {
		ae.Message = body.Error
	} else {
		ae.Message = strings.TrimSpace(string(data))
	}
	return ae
}
