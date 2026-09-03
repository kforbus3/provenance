// Package imaging drives a Flipside deployment — the A/B image builder, PXE
// imaging server and staged-rollout control plane — from inside Moorgate, and
// gives Flipside the one thing it structurally cannot have: a way to reach the
// machines it provisioned.
//
// Flipside's control plane is a pull. A machine is imaged on a private
// provisioning switch and then moved to wherever it lives, so the imaging server
// does not learn its address and usually cannot route to it; each machine's
// agent checks in every few minutes instead. Moorgate already reaches every
// enrolled host through the jump host, so it can make those machines ask *now*,
// and can install directly on the ones that cannot reach Flipside at all.
//
// What it deliberately does not do is decide anything a rollout decides. Canary,
// soak, batch size, failure budget, maintenance window and what counts as a
// machine having actually taken an update all stay in Flipside, where they are
// implemented and tested. Two copies of that logic would have to be kept in step
// and would not be. See docs/imaging.md.
package imaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a typed client for Flipside's HTTP API.
//
// Hand-written rather than generated: the surface used here is a dozen
// endpoints, and a generator plus its schema is more moving parts than the
// thing it would produce.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// ErrNotConfigured is returned by every call when no Flipside URL is set. It is
// a distinct error rather than a generic failure because "you have not set this
// up" and "this is broken" want completely different messages in the UI.
var ErrNotConfigured = errors.New("no Flipside server is configured")

// APIError carries Flipside's own status and message so a failure can be
// reported as what Flipside said rather than as "request failed".
type APIError struct {
	Status int
	Detail string
	Path   string
}

func (e *APIError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("flipside %s: HTTP %d", e.Path, e.Status)
	}
	return fmt.Sprintf("flipside %s: %s", e.Path, e.Detail)
}

// Unauthorized reports whether the token was rejected, which is worth telling
// apart: it is a configuration problem with a specific fix, not an outage.
func (e *APIError) Unauthorized() bool { return e.Status == 401 || e.Status == 403 }

func NewClient(base, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		// No redirect following. Flipside is named by configuration and answers
		// on its own address; a redirect would be either a misconfiguration or
		// something answering in its place, and following one would send the
		// operator token wherever it pointed.
		http: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) Configured() bool { return c != nil && c.base != "" }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("reaching Flipside at %s: %w", c.base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		// Bounded: an error body is a sentence, and a proxy answering with a
		// page of HTML must not become a page of HTML in a log line.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		detail := ""
		var wrapped struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &wrapped) == nil {
			detail = wrapped.Detail
		}
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
		}
		if len(detail) > 300 {
			detail = detail[:300] + "…"
		}
		return &APIError{Status: resp.StatusCode, Detail: detail, Path: path}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// --- what Flipside returns ---------------------------------------------------
//
// Only the fields this subsystem uses. Flipside's payloads carry more, and
// mirroring all of it would be a second schema to keep in step for no gain --
// anything not named here is simply not read.

type Image struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created string    `json:"created"`
	SHA256  string    `json:"sha256"`
	Meta    ImageMeta `json:"meta"`
}

type ImageMeta struct {
	Distro     string `json:"distro"`
	Suite      string `json:"suite"`
	Arch       string `json:"arch"`
	Profile    string `json:"profile"`
	Version    string `json:"version"`
	Encrypted  bool   `json:"encrypted"`
	SecureBoot bool   `json:"secure_boot"`
	Packages   int    `json:"packages"`
	Created    string `json:"created"`
}

type Bundle struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Compatible  string `json:"compatible"`
	Source      string `json:"source"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	Created     string `json:"created"`
	IsLatest    bool   `json:"is_latest"`
}

type BundleList struct {
	Bundles         []Bundle       `json:"bundles"`
	RunningVersions map[string]int `json:"running_versions"`
}

// Machine is Flipside's view of one machine: what its agent last reported, and
// what it was imaged with.
type Machine struct {
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	Address     string   `json:"address"`
	Slot        string   `json:"slot"`
	Version     string   `json:"version"`
	Image       string   `json:"image"`
	Groups      []string `json:"groups"`
	Label       string   `json:"label"`
	Paused      bool     `json:"paused"`
	Presence    string   `json:"presence"` // online | stale | offline | unknown
	Health      string   `json:"health"`
	UpdateState string   `json:"update_state"`
	UpdateError string   `json:"update_error"`
	LastSeen    float64  `json:"last_seen"`
	ImagedAt    float64  `json:"imaged_at"`
	BootedAt    float64  `json:"booted_at"`
}

type FleetView struct {
	Machines   []Machine      `json:"machines"`
	Counts     map[string]int `json:"counts"`
	Versions   map[string]int `json:"versions"`
	Interval   int            `json:"interval"`
	ControlURL string         `json:"control_url"`
}

type RolloutMachine struct {
	State string  `json:"state"`
	Error string  `json:"error"`
	At    float64 `json:"at"`
}

type Rollout struct {
	ID          string                    `json:"id"`
	Bundle      string                    `json:"bundle"`
	Version     string                    `json:"version"`
	BundleURL   string                    `json:"bundle_url"`
	Description string                    `json:"description"`
	State       string                    `json:"state"`
	HaltReason  string                    `json:"halt_reason"`
	Created     float64                   `json:"created"`
	CreatedBy   string                    `json:"created_by"`
	Total       int                       `json:"total"`
	Done        int                       `json:"done"`
	Counts      map[string]int            `json:"counts"`
	Machines    map[string]RolloutMachine `json:"machines"`
	Target      RolloutTarget             `json:"target"`
	Strategy    RolloutStrategy           `json:"strategy"`
}

type RolloutTarget struct {
	Groups []string `json:"groups"`
	Hosts  []string `json:"hosts"`
	All    bool     `json:"all"`
}

type RolloutStrategy struct {
	Canary      int `json:"canary"`
	BatchSize   int `json:"batch_size"`
	SoakSeconds int `json:"soak_seconds"`
	MaxFailures int `json:"max_failures"`
}

type Group struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Hosts       int    `json:"hosts"`
}

// --- calls -------------------------------------------------------------------

func (c *Client) Health(ctx context.Context) (string, error) {
	var out struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/health", nil, &out); err != nil {
		return "", err
	}
	return out.Version, nil
}

func (c *Client) Images(ctx context.Context) ([]Image, error) {
	var out struct {
		Images []Image `json:"images"`
	}
	err := c.do(ctx, http.MethodGet, "/api/images", nil, &out)
	return out.Images, err
}

func (c *Client) Bundles(ctx context.Context) (*BundleList, error) {
	var out BundleList
	err := c.do(ctx, http.MethodGet, "/api/bundles", nil, &out)
	return &out, err
}

func (c *Client) Fleet(ctx context.Context) (*FleetView, error) {
	var out FleetView
	err := c.do(ctx, http.MethodGet, "/api/fleet", nil, &out)
	return &out, err
}

func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	err := c.do(ctx, http.MethodGet, "/api/fleet/groups", nil, &out)
	return out.Groups, err
}

func (c *Client) Rollouts(ctx context.Context) ([]Rollout, error) {
	var out struct {
		Rollouts []Rollout `json:"rollouts"`
	}
	err := c.do(ctx, http.MethodGet, "/api/rollouts", nil, &out)
	return out.Rollouts, err
}

func (c *Client) Rollout(ctx context.Context, id string) (*Rollout, error) {
	var out Rollout
	err := c.do(ctx, http.MethodGet, "/api/rollouts/"+url.PathEscape(id), nil, &out)
	return &out, err
}

// CreateRollout starts one. The body is passed through as given rather than
// modelled field by field: the strategy and window are Flipside's vocabulary,
// it validates them and says exactly what is wrong, and a second validator here
// would only ever disagree with the first.
func (c *Client) CreateRollout(ctx context.Context, body map[string]any) (*Rollout, error) {
	var out Rollout
	err := c.do(ctx, http.MethodPost, "/api/rollouts", body, &out)
	return &out, err
}

func (c *Client) SteerRollout(ctx context.Context, id, verb string) error {
	return c.do(ctx, http.MethodPost,
		"/api/rollouts/"+url.PathEscape(id)+"/"+url.PathEscape(verb), nil, nil)
}

func (c *Client) SetHostGroups(ctx context.Context, machineID string, groups []string) error {
	return c.do(ctx, http.MethodPut, "/api/fleet/hosts/"+url.PathEscape(machineID),
		map[string]any{"groups": groups}, nil)
}

func (c *Client) SetHostPaused(ctx context.Context, machineID string, paused bool) error {
	return c.do(ctx, http.MethodPut, "/api/fleet/hosts/"+url.PathEscape(machineID),
		map[string]any{"paused": paused}, nil)
}

// Report tells Flipside what Moorgate observed on a machine it reached directly.
//
// Not the machine's heartbeat: this is Moorgate saying "I looked at that host
// and this is what is on it", which is stronger evidence than a machine's own
// word and belongs to a different identity. Flipside records who said it.
func (c *Client) Report(ctx context.Context, machineID string, obs Observation) error {
	return c.do(ctx, http.MethodPost, "/api/fleet/report", map[string]any{
		"id":           machineID,
		"version":      obs.Version,
		"health":       obs.Health,
		"slot":         obs.Slot,
		"update_state": obs.UpdateState,
		"update_error": obs.UpdateError,
		"observed_by":  obs.ObservedBy,
	}, nil)
}

// Observation is what Moorgate saw on a host, over SSH, with its own eyes.
type Observation struct {
	Version     string
	Health      string
	Slot        string
	UpdateState string
	UpdateError string
	ObservedBy  string
}

// BundleURL resolves the URL a machine should fetch a bundle from. Flipside
// records one per rollout, derived from its CONTROL_URL — the address that
// works from where the fleet lives, which is routinely not the address Moorgate
// uses to talk to Flipside's API.
func (r *Rollout) BundleFetchURL() string { return r.BundleURL }
