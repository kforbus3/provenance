package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/sshgw"
)

// osTokenRe guards the OS id/version tokens we interpolate into a filename and a
// remote shell command.
var osTokenRe = regexp.MustCompile(`^[a-z0-9]+$`)

// contentProbeScript reports the host's OS id + version and whether a matching
// SSG datastream is already present locally.
const contentProbeScript = `ID=$(. /etc/os-release 2>/dev/null; echo "$ID"); VER=$(. /etc/os-release 2>/dev/null; echo "$VERSION_ID" | tr -d .)
echo "OSID=$ID"
echo "OSVER=$VER"
[ -f "/usr/share/xml/scap/ssg/content/ssg-${ID}${VER}-ds.xml" ] && echo "HAVE=1" || echo "HAVE=0"`

// ensureContent makes sure the host has SCAP content matching its OS version.
// If not, it provisions the matching datastream from the backend's cache
// (downloading the ComplianceAsCode release once, on the backend), pushing the
// ~8MB file to the host over the existing connection. Best-effort: failures are
// logged, not fatal — the scan proceeds with whatever content the host has.
func (s *Service) ensureContent(ctx context.Context, conn *sshgw.Conn, host *models.Host) {
	if s.cfg.ScapContentDir == "" {
		return // auto-provisioning disabled
	}
	out, err := runScript(ctx, conn, contentProbeScript)
	if err != nil {
		s.log.Warn("scan content probe", "host", host.Hostname, "err", err)
		return
	}
	m := parseKV(out)
	if m["HAVE"] == "1" {
		return // host already has matching content
	}
	osid, osver := m["OSID"], m["OSVER"]
	if osver == "" || !osTokenRe.MatchString(osid) || !osTokenRe.MatchString(osver) {
		return
	}
	name := fmt.Sprintf("ssg-%s%s-ds.xml", osid, osver)

	local, err := s.cachedContent(ctx, name)
	if err != nil {
		s.log.Warn("scan content cache", "host", host.Hostname, "content", name, "err", err)
		return
	}
	if local == "" {
		s.log.Info("no SCAP content for host OS version", "host", host.Hostname, "content", name)
		return
	}
	data, err := os.ReadFile(local)
	if err != nil {
		s.log.Warn("scan content read", "content", name, "err", err)
		return
	}
	if err := pushContentFile(ctx, conn, data, name); err != nil {
		s.log.Warn("scan content push", "host", host.Hostname, "err", err)
		return
	}
	s.log.Info("provisioned SCAP content", "host", host.Hostname, "content", name)
}

// cachedContent returns the path to a cached datastream, downloading + extracting
// the release into the cache on first need (serialized). Returns "" if the
// release contains no datastream by that name (unknown/too-new OS).
func (s *Service) cachedContent(ctx context.Context, name string) (string, error) {
	path := filepath.Join(s.cfg.ScapContentDir, name)
	if fileExists(path) {
		return path, nil
	}
	s.contentMu.Lock()
	defer s.contentMu.Unlock()
	if fileExists(path) { // another goroutine may have just fetched it
		return path, nil
	}
	if err := s.downloadContent(ctx); err != nil {
		return "", err
	}
	if fileExists(path) {
		return path, nil
	}
	return "", nil
}

// downloadContent fetches the ComplianceAsCode release zip and extracts every
// ssg-*-ds.xml into the content cache, so one download covers all OS versions.
func (s *Service) downloadContent(ctx context.Context) error {
	url, err := s.resolveReleaseZipURL(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.ScapContentDir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.cfg.ScapContentDir, "ssg-release-*.zip")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer tmp.Close()

	s.log.Info("downloading SCAP content release", "url", url)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download content: HTTP %d", resp.StatusCode)
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}

	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return err
	}
	defer zr.Close()
	n := 0
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if !strings.HasPrefix(base, "ssg-") || !strings.HasSuffix(base, "-ds.xml") {
			continue
		}
		if err := extractZipEntry(f, filepath.Join(s.cfg.ScapContentDir, base)); err != nil {
			return err
		}
		n++
	}
	s.log.Info("cached SCAP datastreams", "count", n)
	return nil
}

// resolveReleaseZipURL returns the release zip URL for the configured version, or
// the latest release if unset.
func (s *Service) resolveReleaseZipURL(ctx context.Context) (string, error) {
	ver := strings.TrimPrefix(s.cfg.ScapContentVersion, "v")
	if ver == "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://api.github.com/repos/ComplianceAsCode/content/releases/latest", nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("resolve latest release: HTTP %d", resp.StatusCode)
		}
		var rel struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
			return "", err
		}
		ver = strings.TrimPrefix(rel.TagName, "v")
		if ver == "" {
			return "", fmt.Errorf("empty release tag")
		}
	}
	return fmt.Sprintf("https://github.com/ComplianceAsCode/content/releases/download/v%s/scap-security-guide-%s.zip", ver, ver), nil
}

// pushContentFile writes the datastream to the host's SCAP content dir as root
// over the connection (name is validated, so it is safe to interpolate).
func pushContentFile(ctx context.Context, conn *sshgw.Conn, data []byte, name string) error {
	sess, err := conn.Client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	remote := "/usr/share/xml/scap/ssg/content/" + name
	cmd := "sudo mkdir -p /usr/share/xml/scap/ssg/content && sudo tee " + remote + " >/dev/null && sudo chmod 0644 " + remote
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func extractZipEntry(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	// Bound decompression to guard against a zip bomb even from trusted
	// ComplianceAsCode content: honor the entry's declared uncompressed size,
	// capped by a hard ceiling, and reject an entry that overruns it.
	const maxEntryBytes = 1 << 30 // 1 GiB
	limit := int64(maxEntryBytes)
	if f.UncompressedSize64 < uint64(maxEntryBytes) {
		limit = int64(f.UncompressedSize64) + 1 // +1 lets us detect an overrun past the declared size
	}
	n, err := io.Copy(out, io.LimitReader(rc, limit))
	if err != nil {
		return err
	}
	if n > int64(f.UncompressedSize64) {
		return fmt.Errorf("zip entry %s exceeds its declared uncompressed size", f.Name)
	}
	return nil
}
