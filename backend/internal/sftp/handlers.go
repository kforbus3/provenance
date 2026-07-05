// Package sftp provides audited file transfer (list/download/upload) to managed
// hosts, brokered through the SSH gateway. The browser never speaks SFTP — the
// backend opens the SFTP subsystem over the session's gateway connection.
package sftp

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	pkgsftp "github.com/pkg/sftp"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/auth"
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
	var lastErr error
	for _, addr := range candidates {
		// Use a certificate unique to this (user, host) pair.
		conn, err := h.gw.DialForHost(r.Context(), p.SessionID, p.UserID, host.ID, p.Username, host.Hostname, addr, host.SSHPort, loginUser, principals)
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
	n, _ := io.Copy(w, f)
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
		n, _ := io.Copy(tw, f)
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
	n, cerr := io.Copy(dst, body)
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
