package imaging

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// The build and provisioning half of the API.
//
// Every route here is a thin pass-through to the builder-runner sidecar with
// three things added, which is the entire reason it is not simply exposed
// directly: a permission check, an audit entry, and a secret that never reaches
// the browser. The sidecar can start privileged containers, so the list of
// people who may ask it to is not a thing to leave to network placement.

func mountBuilds(r chi.Router, h *handler) {
	// Building. Separate from Imaging.Manage because building an artefact and
	// putting it on the fleet are different acts -- see migration 0081.
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Post("/imaging/builds/{kind}", h.startBuild)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/builds", h.listJobs)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/builds/{id}", h.jobLog)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Post("/imaging/builds/{id}/cancel", h.cancelJob)
	// Clearing build history. Imaging.Build, not View: it removes a record, and
	// the log it removes is the only account of what a build did.
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/builds/{id}", h.forgetJob)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/builds", h.forgetFinishedJobs)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/images/{name}", h.deleteImage)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/bundles/{name}", h.deleteBundle)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/disk", h.disk)
	// Downloads. Imaging.View, not Build: reading an artefact is not producing
	// one, and the person who has to hand an SBOM to an auditor is not
	// necessarily the person allowed to start a build.
	//
	// The image download is NOT here. It cannot be: every route in this function is
	// registered on a router that already requires a bearer header, and a browser
	// navigating to a download cannot send one. It is registered in Mount, outside
	// that group, and authenticates itself from the token query parameter.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/images/{name}/sbom", h.downloadSBOM)

	// The build overlay: files layered into an image.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/overlay", h.overlayList)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/overlay/file", h.overlayRead)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Put("/imaging/overlay/file", h.overlayWrite)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/overlay/file", h.overlayDelete)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/overlay/download", h.overlayDownload)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Post("/imaging/overlay/move", h.overlayMove)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Post("/imaging/overlay/chmod", h.overlayChmod)

	// The provisioning stack. Its own permission: this is the part that
	// reconfigures a network segment, and the blast radius of a wrong DHCP range
	// is every machine on that switch, imaged or not.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/provisioning", h.provisioning)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Put("/imaging/provisioning/env", h.setProvisioningEnv)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Post("/imaging/provisioning/{verb}", h.steerProvisioning)
	// Who is on the provisioning network now. View, not Provision: seeing which
	// machines are waiting is what tells you whether the network is even wired
	// correctly, and refusing that to someone who can already see the stack's
	// configuration protects nothing.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/provisioning/clients", h.provisioningClients)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/assignments", h.assignments)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Put("/imaging/assignments", h.setAssignments)

	// The key backup. Imaging.Build to read what state exists, Imaging.Provision
	// to create an archive of it — the same permission that already governs the
	// provisioning stack's own configuration, which is half of what is in it.
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Get("/imaging/keys", h.keyStatus)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Post("/imaging/keys/backup", h.keyBackup)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Get("/imaging/keys/inspect", h.keyInspect)
}

// fail turns a runner error into a response.
//
// A missing runner is 501, not 500: nothing is broken, the deployment simply
// does not include the privileged sidecar, and telling an operator their server
// has failed when it is working as configured sends them debugging the wrong
// thing.
func fail(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNoRunner) {
		httpx.WriteError(w, http.StatusNotImplemented, err.Error())
		return
	}
	httpx.WriteError(w, http.StatusBadGateway, err.Error())
}

// --- builds ------------------------------------------------------------------

func (h *handler) startBuild(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	switch kind {
	case "image", "bundle", "imager":
	default:
		httpx.WriteError(w, http.StatusBadRequest, "kind must be image, bundle or imager")
		return
	}
	// Passed through as sent rather than modelled field by field. The builder
	// has thirty-odd options and validates all of them -- it refuses a build
	// rather than shipping an image whose state manifest is wrong, which is a
	// thing you would otherwise discover at a boot prompt. A struct here would
	// be a second, staler copy of those rules, and the failure mode of a stale
	// copy is silently dropping the option somebody just added.
	var body map[string]any
	if r.Body != nil {
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
		// An empty body is not a malformed one. `POST /imaging/builds/imager`
		// takes no options at all, and a sender that omits the body entirely is
		// asking for the defaults rather than making a mistake.
		if err != nil && !errors.Is(err, io.EOF) {
			httpx.WriteError(w, http.StatusBadRequest, "unreadable request")
			return
		}
	}
	// The overlay client belongs IN the image, not installed onto the machine
	// afterwards.
	//
	// Enrollment installs openvpn (or wireguard-tools) onto a running host with
	// the package manager, which puts it in /usr -- and /usr is exactly what an
	// A/B update replaces. The overlay's config, certificates and keys live in
	// /etc and survive, because the overlay carries /etc across; the binary and
	// its systemd unit do not. So a machine enrolled on the VPN, updated once,
	// comes up on the new slot with a complete configuration and nothing to run
	// it, and drops off the overlay silently. That is not a rare case -- it is
	// every A/B machine, on its first update.
	//
	// Added to `packages` rather than as a new flag, because that list already
	// flows through the sidecar to build-image.sh AND is installed in the
	// transaction that runs after EPEL is enabled -- which openvpn needs on the
	// rpm family, where it is not in any base repository.
	//
	// Every transport the FLEET uses, not just the configured default. The
	// transport is a per-host column (hosts.overlay) and the config value is only
	// the fallback for a host that has not chosen. Keying on the config alone
	// built an image carrying wireguard-tools for a deployment whose default
	// resolved to WireGuard, while the machine it was being rebuilt for was
	// enrolled with openvpn -- so the rebuilt image would have reproduced the
	// exact failure it was meant to fix, and the machine would have come up with
	// a complete OpenVPN configuration and no openvpn to run it.
	//
	// An image is not built for one host, so it cannot pick; it carries the
	// clients the fleet actually needs. Two small packages is the right price for
	// not having to know in advance which machine an image will be written to.
	if kind == "image" {
		// Best-effort: a database that cannot answer must not stop a build. The
		// configured default is covered either way.
		inUse, _ := h.svc.store.OverlayModesInUse(r.Context())
		existing := asString(body["packages"])
		for _, pkg := range overlayClientsFor(h.svc.cfg.Overlay, inUse) {
			if !strings.Contains(existing, pkg) {
				existing = strings.TrimSpace(existing + " " + pkg)
			}
		}
		if existing != "" {
			body["packages"] = existing
		}
	}

	// A generated recovery passphrase is filed BEFORE the build is started, and
	// the build is abandoned if it cannot be. See passphrase.go: an encrypted
	// image whose key was never persisted looks exactly like a success.
	var generated *GeneratedPassphrase
	// Recorded so the audit entry says the server unsealed a stored credential
	// to do this. Reading a filed passphrase on the operator's behalf is
	// reasonable -- it exists for this -- but it is not something to do silently.
	usedFiledPassphrase := false
	if shouldFilePassphrase(kind, body) {
		p := auth.MustPrincipal(r)
		name := h.svc.FreeImageName(imageBaseName(body))
		meta := map[string]string{
			"distro": asString(body["distro"]), "suite": asString(body["suite"]),
			"arch": asString(body["arch"]), "hostname": asString(body["hostname"]),
			"unlock": asString(body["unlock"]), "requestedBy": p.Username,
		}
		var perr error
		generated, perr = h.svc.StoreImagePassphrase(r.Context(), name, meta, p.UserID)
		if perr != nil {
			httpx.WriteError(w, http.StatusBadGateway, perr.Error())
			return
		}
		// The builder takes it in the environment like any typed one, so it needs
		// no access to the store this was just filed in. The name goes with it, so
		// the image that gets built is the one the secret is filed under.
		body["luksPassphrase"] = generated.Passphrase
		body["name"] = name
		delete(body, "generatePassphrase")
	}

	// A bundle is built by reading the image's root slot, so an encrypted image
	// needs its passphrase. This server generated that passphrase, filed it, and
	// knows which image it belongs to -- and used to make the operator go and
	// find it and paste it back, or watch the build stop at
	//
	//   [bundle] ERROR: this image is encrypted; pass --luks-passphrase
	//
	// Supplied only when the caller sent none, so anyone passing one explicitly
	// still wins -- including for an image built with "generate and store" off,
	// where nothing is filed and theirs is the only copy.
	//
	// It never leaves the server in a response, and goes to the builder in the
	// environment exactly as it does for an image build.
	if kind == "bundle" && strings.TrimSpace(asString(body["luksPassphrase"])) == "" {
		if img := asString(body["image"]); img != "" {
			pass, perr := h.svc.ImagePassphrase(r.Context(), img)
			switch {
			case perr != nil:
				// Do not fail the build on this: the operator may be about to
				// supply their own, and an image with nothing filed is a normal
				// state. Say it happened, and let the builder's own error stand
				// if the passphrase really was needed.
				h.svc.log.Warn("imaging: reading the filed passphrase for a bundle build",
					"image", img, "err", perr)
			case pass != "":
				body["luksPassphrase"] = pass
				// Set alongside it, because the sidecar only forwards LUKS_PASS
				// into the build container when this is true -- so supplying the
				// passphrase without it would be the same silent no-op as not
				// supplying it at all. A passphrase is only filed for an image
				// that is encrypted, so finding one settles the question.
				body["encrypted"] = true
				usedFiledPassphrase = true
			}
		}
	}

	job, err := h.svc.StartBuild(r.Context(), kind, body)
	if err != nil {
		// The secret is already filed and the build never ran. Say so: it is not
		// lost, and it is about to be the only thing in the vault with no image.
		if generated != nil {
			fail(w, fmt.Errorf("%w — the recovery passphrase filed at %s is now unused "+
				"and can be deleted", err, generated.Location))
			return
		}
		fail(w, err)
		return
	}
	h.audit(r, "imaging.build.start", job.ID, map[string]any{
		"kind": kind, "label": job.Label,
		// Deliberately not the whole request: it carries the image's login
		// password and, for an encrypted build, the LUKS passphrase. What was
		// built is auditable from the artefact and its sidecar.
		"distro": body["distro"], "suite": body["suite"], "arch": body["arch"],
		"profile": body["profile"], "image": body["image"],
		"usedFiledPassphrase": usedFiledPassphrase,
	})
	if generated != nil {
		// The job as the sidecar described it, plus where the recovery key went.
		// Marshalled and merged rather than re-listing Job's fields, which would
		// be a second copy that silently drops whatever is added to the first.
		out := map[string]any{}
		if raw, mErr := json.Marshal(job); mErr == nil {
			_ = json.Unmarshal(raw, &out)
		}
		out["passphraseStoredIn"] = generated.Backend
		out["passphraseStoredAt"] = generated.Location
		out["passphraseSecretId"] = generated.SecretID
		out["imageName"] = body["name"]
		httpx.WriteJSON(w, http.StatusOK, out)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job)
}

// shouldFilePassphrase decides whether this build's LUKS passphrase is generated
// and stored on this server, or whether the operator supplies one that is used
// and then forgotten.
//
// Named rather than left inline because the false branch is a security property
// somebody relies on, not merely a feature being off. An operator building a
// laptop image turns "generate and store" off precisely so that compromising
// this server does not also hand over the disks -- so a change that made this
// file the passphrase anyway would break a promise the build dialog makes in
// as many words, and would do it silently, in a direction no build failure
// would ever reveal.
//
// All three conditions matter. Only image builds have a root filesystem to
// encrypt; an unencrypted build has no passphrase to file; and generatePassphrase
// is the operator's explicit ask. Anything missing means store nothing.
func shouldFilePassphrase(kind string, body map[string]any) bool {
	return kind == "image" &&
		truthy(body["encrypt"]) &&
		truthy(body["generatePassphrase"])
}

// truthy reads a JSON boolean that may have arrived as a bool or as a string.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	}
	return false
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// imageBaseName is the name a build would produce by default, before the
// free-name search. It mirrors the builder's own default so an unencrypted build
// and a generated-passphrase one land on the same naming convention.
func imageBaseName(body map[string]any) string {
	if n := strings.TrimSpace(asString(body["name"])); n != "" {
		return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(n, ".zst"), ".gz"), ".img")
	}
	distro := asString(body["distro"])
	if distro == "" {
		distro = "debian"
	}
	suite := asString(body["suite"])
	if suite == "" {
		suite = "trixie"
	}
	arch := asString(body["arch"])
	if arch == "" {
		arch = "amd64"
	}
	return distro + "-" + suite + "-" + arch + "-ab"
}

func (h *handler) listJobs(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Jobs(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"builds": out})
}

func (h *handler) jobLog(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	job, err := h.svc.JobLog(r.Context(), chi.URLParam(r, "id"), offset)
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job)
}

func (h *handler) forgetJob(w http.ResponseWriter, r *http.Request) {
	id := pathID(r, "id")
	if err := h.svc.ForgetJob(r.Context(), id); err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.build.forget", id, map[string]any{"job": id})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) forgetFinishedJobs(w http.ResponseWriter, r *http.Request) {
	n, err := h.svc.ForgetFinishedJobs(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.build.forget_finished", "builds", map[string]any{"removed": n})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"removed": n})
}

func (h *handler) cancelJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, err := h.svc.CancelJob(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.build.cancel", id, nil)
	httpx.WriteJSON(w, http.StatusOK, job)
}

func (h *handler) deleteImage(w http.ResponseWriter, r *http.Request) {
	h.deleteArtifact(w, r, "images")
}

func (h *handler) deleteBundle(w http.ResponseWriter, r *http.Request) {
	h.deleteArtifact(w, r, "bundles")
}

func (h *handler) deleteArtifact(w http.ResponseWriter, r *http.Request, kind string) {
	name := chi.URLParam(r, "name")
	// A bundle a live rollout is still handing out must not disappear from under
	// it: machines that have not yet taken their turn would each fail to
	// download, be re-offered, and eventually be marked failed -- which reads as
	// "the update is broken" rather than "somebody deleted it".
	if kind == "bundles" {
		rollouts, err := h.d.Store.ListRollouts(r.Context())
		if err == nil {
			for i := range rollouts {
				if rollouts[i].Bundle == name && rollouts[i].State == RolloutRunning {
					httpx.WriteError(w, http.StatusConflict,
						"a running rollout is still handing this bundle out; cancel it first")
					return
				}
			}
		}
	}
	if err := h.svc.DeleteArtifact(r.Context(), kind, name); err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.artifact.delete", name, map[string]any{"kind": kind})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) disk(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.DiskUsage(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// --- the build overlay -------------------------------------------------------

func (h *handler) overlayList(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.OverlayFiles(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) overlayRead(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.OverlayRead(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type overlayWriteReq struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	// ContentBase64 carries a file that is not text. Uploads use it for
	// everything, because a browser reading a file cannot know whether what it
	// holds is UTF-8 and guessing wrong corrupts the file silently.
	ContentBase64 string `json:"contentBase64"`
	Mode          *int   `json:"mode"`
}

func (h *handler) overlayWrite(w http.ResponseWriter, r *http.Request) {
	var req overlayWriteReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.OverlayWrite(r.Context(), req.Path, req.Content, req.ContentBase64, req.Mode)
	if err != nil {
		fail(w, err)
		return
	}
	// The content is not audited, only that it changed and by whom. An overlay
	// file is routinely a config carrying a token or a key, and an audit log is
	// read by more people than the thing it describes.
	//
	// Base64 length is reported as the decoded size, so the number means the same
	// thing whichever way the file arrived.
	size := len(req.Content)
	if req.ContentBase64 != "" {
		size = base64.StdEncoding.DecodedLen(len(req.ContentBase64))
	}
	h.audit(r, "imaging.overlay.write", req.Path, map[string]any{"bytes": size})
	httpx.WriteJSON(w, http.StatusOK, out)
}

// overlayDownload returns a file's bytes for anything the editor cannot show —
// a binary, or something too large to open in a browser.
func (h *handler) overlayDownload(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.OverlayDownload(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type overlayMoveReq struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// overlayMove renames a file within the overlay. Both paths are resolved against
// the overlay root by the sidecar, so neither can name somewhere else.
func (h *handler) overlayMove(w http.ResponseWriter, r *http.Request) {
	var req overlayMoveReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.OverlayMove(r.Context(), req.From, req.To)
	if err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.overlay.move", req.From, map[string]any{"to": req.To})
	httpx.WriteJSON(w, http.StatusOK, out)
}

type overlayChmodReq struct {
	Path string `json:"path"`
	Mode int    `json:"mode"`
}

// overlayChmod sets a file's mode. It is its own operation because a browser
// cannot read a file's permissions when uploading it — so a folder of scripts
// arrives without its executable bits, and setting them is the step that makes
// the difference between a boot that runs them and one that does not.
func (h *handler) overlayChmod(w http.ResponseWriter, r *http.Request) {
	var req overlayChmodReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.OverlayChmod(r.Context(), req.Path, req.Mode)
	if err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.overlay.chmod", req.Path, map[string]any{"mode": req.Mode})
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) overlayDelete(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if err := h.svc.OverlayDelete(r.Context(), path); err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.overlay.delete", path, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// serveArtifact streams a file from the output directory as an attachment.
//
// Streamed with http.ServeFile rather than read into memory: an image is several
// gigabytes, and reading one into a buffer to hand it to a browser is how a
// backend with plenty of memory runs out of it.
func (h *handler) serveArtifact(w http.ResponseWriter, r *http.Request, path, filename, contentType string) {
	f, err := os.Open(path)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such artefact")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the artefact")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	http.ServeContent(w, r, filename, st.ModTime(), f)
}

func (h *handler) downloadImage(w http.ResponseWriter, r *http.Request) {
	// This route is outside the authenticated group (see Mount), so it does its own
	// check. The permission is the same one the rest of the section requires.
	principal, err := h.d.Auth.AuthenticateToken(r.Context(), r.URL.Query().Get("token"))
	if err != nil || principal == nil || !principal.Has("Imaging.View") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := chi.URLParam(r, "name")
	path, err := h.svc.ImagePath(name)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	// Recorded with the principal in hand rather than through h.audit, which reads
	// the request context -- and this route has no principal there, so going through
	// it would file "somebody downloaded a machine image" with no name on it.
	_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
		Action: "imaging.image.download", TargetKind: "imaging", TargetID: name,
		ActorID: &principal.UserID, ActorName: principal.Username, IP: httpx.ClientIP(r),
	})
	h.serveArtifact(w, r, path, filepath.Base(path), "application/octet-stream")
}

func (h *handler) downloadSBOM(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	path, err := h.svc.SBOMPath(name)
	if err != nil {
		// Distinguished from a missing image: an image built before SBOMs existed
		// has one and not the other, and "no such image" would send somebody
		// looking for the wrong thing.
		httpx.WriteError(w, http.StatusNotFound,
			"no SBOM for that image — it may predate SBOM generation")
		return
	}
	h.audit(r, "imaging.sbom.download", name, nil)
	h.serveArtifact(w, r, path, filepath.Base(path), "application/spdx+json")
}

func (h *handler) keyStatus(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.KeyBackupStatus(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) keyBackup(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.KeyBackupCreate(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	// The archive's name and digest, never its contents. Auditing that somebody
	// made a copy of the signing key is the point of the entry.
	h.audit(r, "imaging.keys.backup", asString(out["name"]),
		map[string]any{"sha256": out["sha256"], "size": out["size"]})
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) keyInspect(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.KeyBackupInspect(r.Context(), r.URL.Query().Get("name"))
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// --- the provisioning stack --------------------------------------------------

// provisioning is the whole page in one call: status, configuration, and what
// is wrong before anything is started.
//
// One call because they are read together and are individually useless. A status
// of "running" means something different depending on whether preflight is
// complaining that something else on the segment is already serving DHCP.
func (h *handler) provisioning(w http.ResponseWriter, r *http.Request) {
	env, err := h.svc.ProvisioningEnv(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"env": env.Env, "controlUrl": env.ControlURL}
	// Status and preflight are best-effort: a failure in either is a fact about
	// the provisioning stack, not a reason to refuse to render the page that
	// would tell someone about it.
	if status, serr := h.svc.ProvisioningStatus(r.Context()); serr == nil {
		out["status"] = status
	}
	if problems, perr := h.svc.ProvisioningPreflight(r.Context()); perr == nil {
		out["problems"] = problems
	}
	if ifaces, ierr := h.svc.ProvisioningInterfaces(r.Context()); ierr == nil {
		out["interfaces"] = ifaces
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type provisioningEnvReq struct {
	Env map[string]string `json:"env"`
}

func (h *handler) setProvisioningEnv(w http.ResponseWriter, r *http.Request) {
	var req provisioningEnvReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.SetProvisioningEnv(r.Context(), req.Env)
	if err != nil {
		fail(w, err)
		return
	}
	// Keys, not values: the set of settings someone changed is the useful record,
	// and the values include addresses and ranges that are already readable by
	// anyone who may read this page.
	keys := make([]string, 0, len(req.Env))
	for k := range req.Env {
		keys = append(keys, k)
	}
	h.audit(r, "imaging.provisioning.configure", "server", map[string]any{"keys": keys})
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) steerProvisioning(w http.ResponseWriter, r *http.Request) {
	verb := chi.URLParam(r, "verb")
	var out string
	var err error
	switch verb {
	case "up":
		out, err = h.svc.StartProvisioning(r.Context())
	case "down":
		out, err = h.svc.StopProvisioning(r.Context())
	default:
		httpx.WriteError(w, http.StatusBadRequest, "verb must be up or down")
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	h.audit(r, "imaging.provisioning."+verb, "server", nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (h *handler) provisioningClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.svc.ProvisioningClients(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	// Never null: the UI distinguishes "nobody is booting" from "this call did
	// not work", and a null array renders as neither.
	if clients == nil {
		clients = []map[string]any{}
	}
	// This is polled, and every answer is about the last few seconds. A cached
	// copy is not a stale optimisation here, it is the wrong answer -- a machine
	// that has just booted and is not shown looks like a machine the server
	// cannot see.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (h *handler) assignments(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Assignments(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"assignments": out})
}

type assignmentsReq struct {
	Assignments []map[string]any `json:"assignments"`
}

func (h *handler) setAssignments(w http.ResponseWriter, r *http.Request) {
	var req assignmentsReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.SetAssignments(r.Context(), req.Assignments)
	if err != nil {
		fail(w, err)
		return
	}
	macs := make([]string, 0, len(out))
	for _, a := range out {
		if m, ok := a["mac"].(string); ok {
			macs = append(macs, m)
		}
	}
	h.audit(r, "imaging.assignments.set", "assignments", map[string]any{
		"count": len(out), "macs": strings.Join(macs, " ")})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"assignments": out})
}

// overlayClientPackage names the package a machine needs to join this
// deployment's overlay, or "" when the deployment has none configured.
//
// Same package name on both families; what differs is where it comes from, and
// that is already handled by installing it in the post-EPEL transaction.

// overlayClientsFor is the set of overlay client packages an image must carry:
// the configured default, plus every transport an enrolled host is actually
// using. Sorted and deduplicated, so the same inputs always produce the same
// package list.
func overlayClientsFor(configured string, inUse []string) []string {
	want := map[string]bool{}
	for _, m := range append([]string{configured}, inUse...) {
		if pkg := overlayClientPackage(m); pkg != "" {
			want[pkg] = true
		}
	}
	pkgs := make([]string, 0, len(want))
	for pkg := range want {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	return pkgs
}

func overlayClientPackage(overlay string) string {
	switch strings.ToLower(strings.TrimSpace(overlay)) {
	case "openvpn":
		return "openvpn"
	case "wireguard":
		return "wireguard-tools"
	default:
		// Unset means the deployment has not chosen, and guessing would put a
		// VPN client on every machine for an overlay that may never be used.
		return ""
	}
}
