package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// execDocker implements Docker by shelling out to the docker CLI (the sidecar image is
// docker:cli with the compose plugin, and mounts /var/run/docker.sock).
type execDocker struct {
	project      string
	composeFiles []string
	envFile      string
	log          *slog.Logger

	projectDirOnce sync.Once
	projectDir     string // cached host path of the compose dir (for --project-directory)
}

// hostProjectDir returns the HOST path of the compose directory (the /compose mount's
// source), used as compose's --project-directory. This is essential: the compose files
// contain RELATIVE bind sources like `../../.env`, and Docker Compose resolves them
// against the project directory. Running inside the updater the compose files sit at
// `/compose`, so without this compose would resolve `../../.env` to `/.env` and the
// daemon would create a stray directory there and bind it — the exact bug that broke the
// fleet-updater's own .env mount during a self-update. Pointing --project-directory at
// the real host compose dir makes those relative paths resolve to the real host files.
// Best-effort: on discovery failure it returns "" and callers omit the flag.
func (d *execDocker) hostProjectDir(ctx context.Context) string {
	d.projectDirOnce.Do(func() {
		self := fmt.Sprintf("%s-fleet-updater-1", d.project)
		src, err := d.InspectMount(ctx, self, "/compose")
		if err != nil || src == "" {
			if d.log != nil {
				d.log.Warn("could not resolve host compose dir; compose relative paths may misresolve", "err", err)
			}
			return
		}
		d.projectDir = src
	})
	return d.projectDir
}

func (d *execDocker) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (d *execDocker) Load(ctx context.Context, tarPath string) error {
	_, err := d.run(ctx, "load", "-i", tarPath)
	return err
}

func (d *execDocker) RunningImageID(ctx context.Context, container string) (string, error) {
	out, err := d.run(ctx, "inspect", "-f", "{{.Image}}", container)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(out)
	if id == "" {
		return "", fmt.Errorf("no image id for container %s", container)
	}
	return id, nil
}

func (d *execDocker) Tag(ctx context.Context, src, dst string) error {
	_, err := d.run(ctx, "tag", src, dst)
	return err
}

// ComposeUp recreates the named services from already-loaded images (no build, no
// pull), layering the upgrade/rollback override last so its image pins win.
func (d *execDocker) ComposeUp(ctx context.Context, services []string, overrideFile string) error {
	args := []string{"compose"}
	if pd := d.hostProjectDir(ctx); pd != "" {
		args = append(args, "--project-directory", pd)
	}
	if d.envFile != "" {
		args = append(args, "--env-file", d.envFile)
	}
	for _, f := range d.composeFiles {
		args = append(args, "-f", f)
	}
	args = append(args, "-f", overrideFile, "up", "-d", "--no-build", "--no-deps")
	args = append(args, services...)
	_, err := d.run(ctx, args...)
	return err
}

// InspectMount returns the host source path of the mount whose destination matches dest
// inside the given container, or "" if there is no such mount.
func (d *execDocker) InspectMount(ctx context.Context, container, dest string) (string, error) {
	format := fmt.Sprintf(`{{range .Mounts}}{{if eq .Destination %q}}{{.Source}}{{end}}{{end}}`, dest)
	out, err := d.run(ctx, "inspect", "-f", format, container)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// RunDetached launches a detached, auto-removing container from image with the given
// host binds, running shellCmd via /bin/sh -c (entrypoint overridden). Used for the
// updater's own out-of-band replacement, which must outlive this updater process.
func (d *execDocker) RunDetached(ctx context.Context, image string, binds []string, shellCmd string) error {
	args := []string{"run", "-d", "--rm", "--entrypoint", "/bin/sh"}
	for _, b := range binds {
		args = append(args, "-v", b)
	}
	args = append(args, image, "-c", shellCmd)
	_, err := d.run(ctx, args...)
	return err
}

// httpHealth polls a backend instance's /ready and /version until it's ready on the
// wanted version (empty wantVersion = any version, used during rollback). The base URL
// is passed per call so a rolling upgrade can gate each replica.
type httpHealth struct{}

func (h *httpHealth) WaitHealthy(ctx context.Context, baseURL, wantVersion string, timeout time.Duration) error {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	// Small settle delay so we don't observe the OLD container as "ready" before the
	// recreate has begun.
	time.Sleep(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := h.check(client, baseURL, wantVersion); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(3 * time.Second)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out after %s", timeout)
	}
	return lastErr
}

func (h *httpHealth) check(client *http.Client, baseURL, wantVersion string) error {
	// Readiness first.
	rr, err := client.Get(baseURL + "/ready")
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rr.Body, 4096))
	rr.Body.Close()
	if rr.StatusCode != http.StatusOK {
		return fmt.Errorf("/ready returned %d", rr.StatusCode)
	}
	if wantVersion == "" {
		return nil
	}
	vr, err := client.Get(baseURL + "/version")
	if err != nil {
		return err
	}
	defer vr.Body.Close()
	var v struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(vr.Body, 4096)).Decode(&v); err != nil {
		return err
	}
	if v.Version != wantVersion {
		return fmt.Errorf("running version %q, waiting for %q", v.Version, wantVersion)
	}
	return nil
}
