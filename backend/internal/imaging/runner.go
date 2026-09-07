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

// Client for the builder-runner sidecar: the only thing in a deployment that
// touches the Docker socket.
//
// Building an image means running a privileged container that attaches a disk
// image to a loop device and debootstraps into it. A process able to ask the
// Docker daemon for that can ask it for anything -- a socket that can start a
// privileged container with `/` bind-mounted is root on the host with extra
// steps. So the backend does not have the socket. It has an HTTP client, a
// token, and a service that does nothing but builds.
//
// The runner has no users, no sessions and no opinion about who may do
// anything. Every request reaching it has already passed this product's
// authentication, permission check and audit. Putting a second, weaker copy of
// that in the sidecar would only mean there were two, and the weaker one would
// be the one that mattered.

// ErrNoRunner is returned when no builder runner is configured. Building is
// opt-in: a fleet that consumes images somebody else builds should not have to
// run a privileged sidecar, and saying so plainly beats a connection refused.
var ErrNoRunner = errors.New("no image builder is configured; set FLEET_BUILDER_RUNNER_URL " +
	"to the builder-runner sidecar")

// runnerTimeout bounds one call to the sidecar. Deliberately short: nothing here
// waits for a build. Starting one returns a job immediately and the log is
// polled, because an HTTP request held open for the forty minutes a build takes
// is a request that fails on any proxy between here and there.
const runnerTimeout = 30 * time.Second

func (s *Service) runnerClient() *http.Client {
	return &http.Client{Timeout: runnerTimeout}
}

// runner performs one call against the sidecar and decodes the result.
func (s *Service) runner(ctx context.Context, method, path string, body, into any) error {
	base := s.cfg.BuilderRunnerURL
	if base == "" {
		return ErrNoRunner
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, runnerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := s.cfg.BuilderRunnerToken; tok != "" {
		req.Header.Set("X-Runner-Token", tok)
	}
	resp, err := s.runnerClient().Do(req)
	if err != nil {
		return fmt.Errorf("reaching the image builder: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return runnerError(resp)
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// runnerError turns the sidecar's failure into one worth showing.
//
// FastAPI puts the reason in `detail`, and it is usually the useful sentence --
// "no such image", "a build is already running", "secure_boot must be one of".
// Passing it through beats replacing it with the status code, which tells an
// operator nothing they can act on.
func runnerError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Detail != nil {
		if msg, ok := body.Detail.(string); ok && msg != "" {
			return errors.New(msg)
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// Named specifically because the fix is a deployment change, not a
		// retry, and "401" on its own sends people looking at their own login.
		return errors.New("the image builder rejected our token; check that " +
			"FLEET_BUILDER_RUNNER_TOKEN matches on both sides")
	}
	text := strings.TrimSpace(string(raw))
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	if text == "" {
		text = resp.Status
	}
	return fmt.Errorf("the image builder failed: %s", text)
}

// Job is a build in progress or finished.
type Job struct {
	ID         string `json:"id"`
	Type       string `json:"type"` // image | bundle | imager
	Label      string `json:"label"`
	Status     string `json:"status"` // running | success | failed | canceled
	ReturnCode *int   `json:"returncode,omitempty"`
	Started    string `json:"started"`
	Finished   string `json:"finished,omitempty"`
	Lines      int    `json:"lines"`
	Progress   *struct {
		Step  int    `json:"step"`
		Total int    `json:"total"`
		Label string `json:"label"`
	} `json:"progress,omitempty"`

	// Only on a single-job read.
	Log    []string `json:"log,omitempty"`
	Offset int      `json:"offset,omitempty"`
	Total  int      `json:"total,omitempty"`
}

func (s *Service) StartBuild(ctx context.Context, kind string, req any) (*Job, error) {
	switch kind {
	case "image", "bundle", "imager":
	default:
		return nil, fmt.Errorf("unknown build kind %q", kind)
	}
	var job Job
	if err := s.runner(ctx, http.MethodPost, "/build/"+kind, req, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *Service) Jobs(ctx context.Context) ([]Job, error) {
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	if err := s.runner(ctx, http.MethodGet, "/jobs", nil, &out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// JobLog is one job with its log from `offset` lines in.
//
// Polled with an offset rather than streamed between here and the sidecar. A
// poll that says where it got to survives a restart of either side; a held-open
// stream does not, and a build long enough to be worth watching is long enough
// for something in the middle to drop it.
func (s *Service) JobLog(ctx context.Context, id string, offset int) (*Job, error) {
	var job Job
	path := fmt.Sprintf("/jobs/%s?offset=%d", url.PathEscape(id), offset)
	if err := s.runner(ctx, http.MethodGet, path, nil, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *Service) CancelJob(ctx context.Context, id string) (*Job, error) {
	var job Job
	if err := s.runner(ctx, http.MethodPost, "/jobs/"+url.PathEscape(id)+"/cancel", nil, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// DeleteArtifact removes a built image or bundle.
//
// Deliberately routed through the runner rather than done here with os.Remove,
// even though this process can see the same directory. The runner owns what is
// in that directory -- it knows an image has a .sha256 and a .json beside it and
// that a bundle may be the one `latest` points at -- and two things deleting
// from one directory by different rules is how a half-deleted artefact happens.
func (s *Service) DeleteArtifact(ctx context.Context, kind, name string) error {
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return errors.New("that is not a name in the artefact library")
	}
	switch kind {
	case "images", "bundles":
	default:
		return fmt.Errorf("unknown artefact kind %q", kind)
	}
	return s.runner(ctx, http.MethodDelete, "/"+kind+"/"+url.PathEscape(name), nil, nil)
}

// DiskUsage is what the artefact library occupies and what is left.
//
// Worth surfacing because the way an image build fails when the volume is full
// is not a clean error: debootstrap gets part way, the loop device stays
// attached, and the log says something about a write error two hundred lines
// before the end.
type DiskUsage struct {
	Artifacts int64 `json:"artifacts"`
	Free      int64 `json:"free"`
	Total     int64 `json:"total"`
}

func (s *Service) DiskUsage(ctx context.Context) (*DiskUsage, error) {
	var out DiskUsage
	if err := s.runner(ctx, http.MethodGet, "/disk", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- the provisioning stack --------------------------------------------------

// ProvisioningEnv is the PXE stack's configuration: which interface it serves,
// what DHCP range it hands out, and what it tells machines the control plane is.
type ProvisioningEnv struct {
	Env        map[string]string `json:"env"`
	ControlURL string            `json:"controlUrl"`
}

func (s *Service) ProvisioningEnv(ctx context.Context) (*ProvisioningEnv, error) {
	var out ProvisioningEnv
	if err := s.runner(ctx, http.MethodGet, "/server/env", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) SetProvisioningEnv(ctx context.Context, env map[string]string) (*ProvisioningEnv, error) {
	var out ProvisioningEnv
	if err := s.runner(ctx, http.MethodPut, "/server/env",
		map[string]any{"env": env}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) ProvisioningStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/server/status", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ProvisioningPreflight is what is wrong before anything is started.
//
// Run before starting the stack rather than after, because the failures here are
// the quiet kind: a DHCP server on an interface that already has one, a
// provisioning range overlapping the office network. By the time those show up
// as symptoms they are somebody else's outage.
func (s *Service) ProvisioningPreflight(ctx context.Context) ([]string, error) {
	var out struct {
		Problems []string `json:"problems"`
	}
	if err := s.runner(ctx, http.MethodGet, "/server/preflight", nil, &out); err != nil {
		return nil, err
	}
	return out.Problems, nil
}

func (s *Service) ProvisioningInterfaces(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/server/interfaces", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) StartProvisioning(ctx context.Context) (string, error) {
	var out struct {
		Output string `json:"output"`
	}
	err := s.runner(ctx, http.MethodPost, "/server/up", nil, &out)
	return out.Output, err
}

func (s *Service) StopProvisioning(ctx context.Context) (string, error) {
	var out struct {
		Output string `json:"output"`
	}
	err := s.runner(ctx, http.MethodPost, "/server/down", nil, &out)
	return out.Output, err
}

// Assignments map a MAC to the hostname and profile a machine gets when it is
// imaged. This is how a rack of identical hardware comes out with the right
// names on it rather than fourteen machines called debian-ab.
func (s *Service) Assignments(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Assignments []map[string]any `json:"assignments"`
	}
	if err := s.runner(ctx, http.MethodGet, "/assignments", nil, &out); err != nil {
		return nil, err
	}
	return out.Assignments, nil
}

func (s *Service) SetAssignments(ctx context.Context, items []map[string]any) ([]map[string]any, error) {
	var out struct {
		Assignments []map[string]any `json:"assignments"`
	}
	if err := s.runner(ctx, http.MethodPut, "/assignments",
		map[string]any{"items": items}, &out); err != nil {
		return nil, err
	}
	return out.Assignments, nil
}

// --- the build overlay -------------------------------------------------------

// Overlay files are layered into an image at build time: unit files, configs,
// scripts. Edited here rather than only on disk because the person who decides
// what goes into an image is not always the person with a shell on the machine
// that builds it.
func (s *Service) OverlayFiles(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/overlay", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) OverlayRead(ctx context.Context, path string) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/overlay/file?path="+url.QueryEscape(path), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) OverlayWrite(ctx context.Context, path, content, contentBase64 string, mode *int) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"path": path}
	// One or the other, never both: sending both would leave which one wins to
	// the far end, and the answer would be invisible until a file came back wrong.
	if contentBase64 != "" {
		body["contentBase64"] = contentBase64
	} else {
		body["content"] = content
	}
	if mode != nil {
		body["mode"] = *mode
	}
	if err := s.runner(ctx, http.MethodPut, "/overlay/file", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// OverlayDownload returns a file's bytes, base64-encoded — the same encoding the
// write side takes, so a binary round-trips byte-identical rather than through a
// decode that would have to guess at an encoding.
func (s *Service) OverlayDownload(ctx context.Context, path string) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/overlay/download?path="+url.QueryEscape(path), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) OverlayMove(ctx context.Context, from, to string) (map[string]any, error) {
	var out map[string]any
	// src/dst, which is what the sidecar's model declares. Sending from/to would
	// be dropped by its extra="ignore" and fail as a missing required field —
	// with a message about src, naming something the caller never sent.
	body := map[string]any{"src": from, "dst": to}
	if err := s.runner(ctx, http.MethodPost, "/overlay/move", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) OverlayChmod(ctx context.Context, path string, mode int) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"path": path, "mode": mode}
	if err := s.runner(ctx, http.MethodPost, "/overlay/chmod", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) OverlayDelete(ctx context.Context, path string) error {
	return s.runner(ctx, http.MethodDelete, "/overlay/file?path="+url.QueryEscape(path), nil, nil)
}

// --- imaging key backup -------------------------------------------------
//
// What the database backup cannot hold: the RAUC signing key, the MAC→hostname
// assignments, and the provisioning stack's configuration.
//
// Metadata only, in both directions. The key never crosses this boundary and
// there is no download route on purpose — a signing key fetchable over HTTP is
// one whose custody is whoever holds a session cookie, and losing this one means
// no deployed machine can ever be updated again.

func (s *Service) KeyBackupStatus(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/keys/status", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) KeyBackupCreate(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodPost, "/keys/backup", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) KeyBackupInspect(ctx context.Context, name string) (map[string]any, error) {
	var out map[string]any
	if err := s.runner(ctx, http.MethodGet, "/keys/inspect?name="+url.QueryEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
