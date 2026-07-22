// Package sftp provides audited file transfer (list/download/upload) to managed
// hosts, brokered through the SSH gateway. The browser never speaks SFTP — the
// backend opens the SFTP subsystem over the session's gateway connection.
package sftp

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	pkgsftp "github.com/pkg/sftp"

	"github.com/fleet-terminal/backend/internal/accesspolicy"
	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/credinject"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/sshgw"
	"github.com/fleet-terminal/backend/internal/store"
)

// Mount attaches SFTP routes (require auth + File.Transfer + host access).
func Mount(r chi.Router, d *app.Deps, gw *sshgw.Gateway) {
	h := &handler{d: d, gw: gw}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Get("/hosts/{id}/sftp/list", h.list)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Get("/hosts/{id}/sftp/download", h.download)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Get("/hosts/{id}/sftp/download-dir", h.downloadDir)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Post("/hosts/{id}/sftp/upload", h.upload)
		// In-browser config-file editor: read a text file, and write it back with an
		// automatic on-host backup. Same File.Transfer gate as upload (SFTP already
		// permits overwriting arbitrary files — this is a nicer, audited UX over it).
		pr.With(d.Auth.RequirePermission("File.Transfer")).Get("/hosts/{id}/sftp/read", h.readText)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Post("/hosts/{id}/sftp/write", h.writeText)
		pr.With(d.Auth.RequirePermission("File.Transfer")).Get("/hosts/{id}/sftp/transfers", h.transfers)
	})
}

type handler struct {
	d  *app.Deps
	gw *sshgw.Gateway
}

// connect opens an SFTP client to the host through the gateway, after access
// checks. The connection is registered in the live-session registry so an
// in-flight transfer is aborted if the session is revoked (disable/terminate/
// logout). The returned cleanup deregisters and closes everything.
func (h *handler) connect(w http.ResponseWriter, r *http.Request) (client *pkgsftp.Client, p *auth.Principal, host *models.Host, cleanup func(), ok bool) {
	noop := func() {}
	p = auth.MustPrincipal(r)
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return nil, nil, nil, noop, false
	}
	if !p.IsSuperAdmin {
		allowed, aerr := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, hostID)
		if aerr != nil || !allowed {
			httpx.WriteError(w, http.StatusForbidden, "not authorized for host")
			return nil, nil, nil, noop, false
		}
	}
	host, err = h.d.Store.GetHost(r.Context(), hostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, nil, nil, noop, false
	}
	// ABAC: contextual policies may deny this connection on top of RBAC.
	if dec := h.d.AccessPolicy.Authorize(r.Context(), accesspolicy.ConnCtx{
		UserID: p.UserID, Username: p.Username, IsSuper: p.IsSuperAdmin,
		HostID: host.ID, HostName: host.Hostname, Environment: host.Environment,
		Tags: host.Tags, Protocol: host.Protocol, Surface: "sftp", IP: accesspolicy.RequestIP(r),
	}); dec.Denied {
		httpx.WriteError(w, http.StatusForbidden, dec.Reason)
		return nil, nil, nil, noop, false
	}
	conn, derr := h.dial(r, p, host)
	if derr != nil {
		httpx.WriteError(w, http.StatusBadGateway, "connection failed: "+derr.Error())
		return nil, nil, nil, noop, false
	}
	client, serr := pkgsftp.NewClient(conn.Client)
	if serr != nil {
		conn.Close()
		httpx.WriteError(w, http.StatusBadGateway, "sftp subsystem failed: "+serr.Error())
		return nil, nil, nil, noop, false
	}
	var dereg func()
	if h.d.Live != nil {
		dereg = h.d.Live.Register(p.SessionID, host.ID, func() { conn.Close() })
	}
	cleanup = func() {
		if dereg != nil {
			dereg()
		}
		_ = client.Close()
		conn.Close()
	}
	return client, p, host, cleanup, true
}

func (h *handler) dial(r *http.Request, p *auth.Principal, host *models.Host) (*sshgw.Conn, error) {
	// Same privilege tier as terminals: Host.Sudo (or super admin) lands in the
	// sudo account, everyone else in the host's login-only account.
	loginUser, principals := sshgw.LoginTier(p.IsSuperAdmin || p.Has("Host.Sudo"), host.SSHUser, p.Username)
	// Strict overlay mode: when enabled and this host is on the WireGuard overlay,
	// dial ONLY the overlay address so a transfer never silently bypasses the
	// tunnel via the host's direct address.
	candidates := dedupe([]string{host.WGAddress, host.Address, host.Hostname})
	if host.WGAddress != "" && h.d.Store.RequireWireGuard(r.Context()) {
		candidates = []string{host.WGAddress}
	}
	// Vaulted credential injection (mirrors the terminal path): resolve the host's
	// vault credential to an SSH auth method; the plaintext never leaves the dial.
	var injection *credinject.Injection
	if host.AuthMethod != "" && host.AuthMethod != "fleet_cert" {
		key, err := h.d.Cfg.VaultKey()
		if err != nil {
			return nil, err
		}
		if injection, err = credinject.For(r.Context(), h.d.Store, key, h.d.Cfg.ExtSecret(), host, p.UserID); err != nil {
			return nil, err
		}
	}

	var lastErr error
	for _, addr := range candidates {
		var conn *sshgw.Conn
		var err error
		if injection != nil {
			conn, err = h.gw.DialAuthViaJump(r.Context(), p.SessionID.String(), addr, host.SSHPort, injection.LoginUser, injection.Auth)
		} else {
			// Use a certificate unique to this (user, host) pair.
			conn, err = h.gw.DialForHost(r.Context(), p.SessionID, p.UserID, host.ID, p.Username, host.Hostname, addr, host.SSHPort, loginUser, principals)
		}
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return nil, lastErr
}

// sessionToucher returns a throttled function that bumps the session's
// last_seen_at (idle-clock), at most once per minute. A single transfer is ONE
// HTTP request, so RequireAuth touches last_seen_at only at the start; a
// multi-GB up/download that outlasts SessionIdleTTL would otherwise be reaped
// mid-flight and its connection force-closed. Keep the session warm while data
// is actually moving. Baseline at now(): RequireAuth just touched at the start.
func (h *handler) sessionToucher(r *http.Request, sessionID uuid.UUID) func() {
	const touchInterval = time.Minute
	last := time.Now()
	return func() {
		if h.d.Store == nil {
			return
		}
		now := time.Now()
		if now.Sub(last) < touchInterval {
			return
		}
		last = now
		_ = h.d.Store.TouchSession(r.Context(), sessionID)
	}
}

// touchReader bumps the session idle-clock as bytes flow through it. io.Copy
// drives Read sequentially from the request goroutine, so the captured throttle
// state needs no locking.
type touchReader struct {
	r     io.Reader
	touch func()
}

func (t *touchReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.touch()
	}
	return n, err
}

type entry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	IsDir   bool      `json:"isDir"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	client, _, _, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "."
	}
	infos, err := client.ReadDir(dir)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "read dir: "+err.Error())
		return
	}
	entries := make([]entry, 0, len(infos))
	for _, fi := range infos {
		entries = append(entries, entry{
			Name: fi.Name(), Size: fi.Size(), IsDir: fi.IsDir(),
			Mode: fi.Mode().String(), ModTime: fi.ModTime(),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})
	abs, _ := client.RealPath(dir)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": abs, "entries": entries})
}

func (h *handler) download(w http.ResponseWriter, r *http.Request) {
	client, p, host, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	remote := r.URL.Query().Get("path")
	if remote == "" {
		httpx.WriteError(w, http.StatusBadRequest, "path required")
		return
	}
	f, err := client.Open(remote)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "open: "+err.Error())
		return
	}
	defer f.Close()
	rec, _ := h.d.Store.RecordSFTPTransfer(r.Context(), store.SFTPTransferInput{
		UserID: &p.UserID, HostID: &host.ID, Direction: "download", RemotePath: remote, Status: "started",
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(remote)))
	// Advertise the size so the client can show download progress. Exposed to JS
	// via Access-Control-Expose-Headers (CORS) when served cross-origin in dev.
	if fi, serr := f.Stat(); serr == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
	}
	n, _ := io.Copy(w, &touchReader{r: f, touch: h.sessionToucher(r, p.SessionID)})
	h.finishTransfer(r, rec, n)
	h.audit(r, p, "sftp.download", host.ID, remote, n)
}

// downloadDir streams a remote directory as a tar archive (recursive). Files are
// streamed one at a time so arbitrarily large trees never buffer in memory.
func (h *handler) downloadDir(w http.ResponseWriter, r *http.Request) {
	client, p, host, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	root := r.URL.Query().Get("path")
	if root == "" {
		httpx.WriteError(w, http.StatusBadRequest, "path required")
		return
	}
	base := path.Base(root)
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".tar"))

	tw := tar.NewWriter(w)
	defer tw.Close()
	touch := h.sessionToucher(r, p.SessionID)
	var total int64
	walker := client.Walk(root)
	for walker.Step() {
		if walker.Err() != nil {
			continue
		}
		info := walker.Stat()
		rel := strings.TrimPrefix(strings.TrimPrefix(walker.Path(), root), "/")
		name := path.Join(base, rel)
		if info.IsDir() {
			_ = tw.WriteHeader(&tar.Header{Name: name + "/", Mode: int64(info.Mode().Perm()), Typeflag: tar.TypeDir, ModTime: info.ModTime()})
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime()}); err != nil {
			return
		}
		f, err := client.Open(walker.Path())
		if err != nil {
			continue
		}
		n, _ := io.Copy(tw, &touchReader{r: f, touch: touch})
		_ = f.Close()
		total += n
	}
	h.audit(r, p, "sftp.download_dir", host.ID, root, total)
}

func (h *handler) upload(w http.ResponseWriter, r *http.Request) {
	client, p, host, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	dir := r.URL.Query().Get("path")
	name := r.URL.Query().Get("name")
	if dir == "" || name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "path and name required")
		return
	}
	// name may include a relative subpath (folder uploads). Sanitize it to stay
	// inside dir — reject absolute paths and any ".." traversal.
	rel := strings.TrimPrefix(path.Clean("/"+name), "/")
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid file name")
		return
	}
	remote := path.Join(dir, rel)
	if parent := path.Dir(remote); parent != "" && parent != "." {
		_ = client.MkdirAll(parent) // create intermediate directories for folder uploads
	}
	dst, err := client.Create(remote)
	if err != nil {
		h.d.Log.Warn("sftp create remote file", "err", err)
		httpx.WriteError(w, http.StatusBadGateway, "could not create the remote file")
		return
	}
	rec, _ := h.d.Store.RecordSFTPTransfer(r.Context(), store.SFTPTransferInput{
		UserID: &p.UserID, HostID: &host.ID, Direction: "upload", RemotePath: remote, Status: "started",
	})
	uploadFailed := func(status int, msg string) {
		_ = dst.Close()
		_ = client.Remove(remote)
		if rec != nil {
			_ = h.d.Store.CompleteSFTPTransfer(r.Context(), rec.ID, 0, "failed")
		}
		httpx.WriteError(w, status, msg)
	}
	// Enforce the configured cap (0 = unlimited) and REJECT oversized uploads
	// rather than silently truncating. The partial remote file is removed.
	body := r.Body
	if limit := h.d.Cfg.MaxUploadBytes; limit > 0 {
		body = http.MaxBytesReader(w, r.Body, limit)
	}
	n, cerr := io.Copy(dst, &touchReader{r: body, touch: h.sessionToucher(r, p.SessionID)})
	if cerr != nil {
		var mbe *http.MaxBytesError
		if errors.As(cerr, &mbe) {
			uploadFailed(http.StatusRequestEntityTooLarge,
				fmt.Sprintf("file exceeds the %d-byte upload limit", h.d.Cfg.MaxUploadBytes))
			return
		}
		uploadFailed(http.StatusBadGateway, "write: "+cerr.Error())
		return
	}
	// Close (flush + commit) the remote file BEFORE responding, so it is fully
	// written and visible to a subsequent directory listing. Closing after the
	// response (a deferred Close) raced the client's post-upload refetch, which
	// is why an uploaded file only appeared after a manual page refresh.
	//
	// The data is already written by io.Copy, so bound the Close: a slow or
	// unresponsive SFTP server must not hang the upload request forever. If it
	// doesn't finish in time we respond anyway (the bytes are on disk) and the
	// deferred cleanup releases the handle when the connection closes.
	closeErr := make(chan error, 1)
	go func() { closeErr <- dst.Close() }()
	select {
	case err := <-closeErr:
		if err != nil {
			uploadFailed(http.StatusBadGateway, "finalize upload: "+err.Error())
			return
		}
	case <-time.After(15 * time.Second):
		h.d.Log.Warn("sftp upload: remote file close slow; responding anyway",
			"host", host.Hostname, "remote", remote, "bytes", n)
	}
	h.finishTransfer(r, rec, n)
	h.audit(r, p, "sftp.upload", host.ID, remote, n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": remote, "size": n})
}

// maxEditBytes caps the size of a file the config editor will read or write. The
// editor is for config files, not data; a larger file is rejected rather than
// loaded into a browser textarea.
const maxEditBytes = 2 << 20 // 2 MiB

// readText returns a remote text file's contents for the in-browser editor. It
// refuses files larger than maxEditBytes and files that don't look like text
// (contain a NUL byte), so the editor never mangles a binary.
func (h *handler) readText(w http.ResponseWriter, r *http.Request) {
	client, p, host, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	remote := r.URL.Query().Get("path")
	if remote == "" {
		httpx.WriteError(w, http.StatusBadRequest, "path required")
		return
	}
	f, err := client.Open(remote)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "open: "+err.Error())
		return
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil {
		if fi.IsDir() {
			httpx.WriteError(w, http.StatusBadRequest, "path is a directory")
			return
		}
		if fi.Size() > maxEditBytes {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("file is %d bytes; the editor handles up to %d", fi.Size(), maxEditBytes))
			return
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxEditBytes+1))
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "read: "+err.Error())
		return
	}
	if len(data) > maxEditBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "file too large to edit")
		return
	}
	if bytesContainNUL(data) {
		httpx.WriteError(w, http.StatusUnsupportedMediaType, "file appears to be binary, not text")
		return
	}
	h.audit(r, p, "sftp.read", host.ID, remote, int64(len(data)))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": remote, "content": string(data), "size": len(data)})
}

// writeText overwrites a remote text file for the editor, taking an on-host backup
// of the previous contents first (best-effort) and preserving the file's mode. The
// backup is written alongside the file as <name>.fleetbak-<timestamp>.
func (h *handler) writeText(w http.ResponseWriter, r *http.Request) {
	client, p, host, cleanup, ok := h.connect(w, r)
	if !ok {
		return
	}
	defer cleanup()

	var rq struct {
		Path    string `json:"path"`
		Content string `json:"content"`
		Backup  *bool  `json:"backup"` // default true
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEditBytes+1024)).Decode(&rq); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rq.Path == "" {
		httpx.WriteError(w, http.StatusBadRequest, "path required")
		return
	}
	if len(rq.Content) > maxEditBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "content too large")
		return
	}

	// Preserve the existing file's mode; back up its current contents first.
	var mode os.FileMode = 0o644
	backupPath := ""
	if fi, serr := client.Stat(rq.Path); serr == nil {
		if fi.IsDir() {
			httpx.WriteError(w, http.StatusBadRequest, "path is a directory")
			return
		}
		mode = fi.Mode().Perm()
		if rq.Backup == nil || *rq.Backup {
			if bp, berr := h.backupRemote(client, rq.Path); berr != nil {
				httpx.WriteError(w, http.StatusBadGateway, "could not back up the file before writing: "+berr.Error())
				return
			} else {
				backupPath = bp
			}
		}
	}

	dst, err := client.Create(rq.Path) // truncates existing
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not open the file for writing: "+err.Error())
		return
	}
	if _, werr := io.Copy(dst, strings.NewReader(rq.Content)); werr != nil {
		_ = dst.Close()
		httpx.WriteError(w, http.StatusBadGateway, "write: "+werr.Error())
		return
	}
	if cerr := dst.Close(); cerr != nil {
		httpx.WriteError(w, http.StatusBadGateway, "finalize write: "+cerr.Error())
		return
	}
	_ = client.Chmod(rq.Path, mode) // best-effort: keep original permissions

	h.finishTransfer(r, mustRecord(h, r, p, host, rq.Path), int64(len(rq.Content)))
	h.audit(r, p, "sftp.edit", host.ID, rq.Path, int64(len(rq.Content)))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"path": rq.Path, "size": len(rq.Content), "backup": backupPath})
}

// backupRemote copies a remote file to a timestamped sibling and returns the
// backup path. Used before an edit overwrites the original.
func (h *handler) backupRemote(client *pkgsftp.Client, remote string) (string, error) {
	src, err := client.Open(remote)
	if err != nil {
		return "", err
	}
	defer src.Close()
	backup := remote + ".fleetbak-" + time.Now().Format("20060102-150405")
	dst, err := client.Create(backup)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, io.LimitReader(src, maxEditBytes)); err != nil {
		_ = dst.Close()
		return "", err
	}
	if err := dst.Close(); err != nil {
		return "", err
	}
	return backup, nil
}

// mustRecord opens a transfer record for an edit (best-effort; nil is tolerated by
// finishTransfer).
func mustRecord(h *handler, r *http.Request, p *auth.Principal, host *models.Host, remote string) *store.SFTPTransfer {
	rec, _ := h.d.Store.RecordSFTPTransfer(r.Context(), store.SFTPTransferInput{
		UserID: &p.UserID, HostID: &host.ID, Direction: "upload", RemotePath: remote, Status: "started",
	})
	return rec
}

func bytesContainNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func (h *handler) transfers(w http.ResponseWriter, r *http.Request) {
	hostID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	// Same host-access gate as the transfer routes: don't leak another host's
	// transfer history (paths, sizes, who uploaded) to users without access.
	p := auth.MustPrincipal(r)
	if !p.IsSuperAdmin {
		allowed, aerr := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, hostID)
		if aerr != nil || !allowed {
			httpx.WriteError(w, http.StatusForbidden, "no access to this host")
			return
		}
	}
	list, err := h.d.Store.ListSFTPTransfers(r.Context(), store.SFTPTransferFilter{HostID: &hostID, Limit: 100})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "list failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"transfers": list})
}

func (h *handler) finishTransfer(r *http.Request, rec *store.SFTPTransfer, n int64) {
	if rec == nil {
		return
	}
	_ = h.d.Store.CompleteSFTPTransfer(r.Context(), rec.ID, n, "completed")
}

func (h *handler) audit(r *http.Request, p *auth.Principal, action string, hostID uuid.UUID, remote string, n int64) {
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		ActorID: &p.UserID, ActorName: p.Username, Action: action,
		TargetKind: "host", TargetID: hostID.String(),
		Detail: map[string]any{"path": remote, "bytes": n},
	})
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
