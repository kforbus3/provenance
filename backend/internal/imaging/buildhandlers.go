package imaging

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/blackfriars/backend/internal/httpx"
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
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/images/{name}", h.deleteImage)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/bundles/{name}", h.deleteBundle)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/disk", h.disk)

	// The build overlay: files layered into an image.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/overlay", h.overlayList)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/overlay/file", h.overlayRead)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Put("/imaging/overlay/file", h.overlayWrite)
	r.With(h.d.Auth.RequirePermission("Imaging.Build")).Delete("/imaging/overlay/file", h.overlayDelete)

	// The provisioning stack. Its own permission: this is the part that
	// reconfigures a network segment, and the blast radius of a wrong DHCP range
	// is every machine on that switch, imaged or not.
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/provisioning", h.provisioning)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Put("/imaging/provisioning/env", h.setProvisioningEnv)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Post("/imaging/provisioning/{verb}", h.steerProvisioning)
	r.With(h.d.Auth.RequirePermission("Imaging.View")).Get("/imaging/assignments", h.assignments)
	r.With(h.d.Auth.RequirePermission("Imaging.Provision")).Put("/imaging/assignments", h.setAssignments)
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
	job, err := h.svc.StartBuild(r.Context(), kind, body)
	if err != nil {
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
	})
	httpx.WriteJSON(w, http.StatusOK, job)
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
	Mode    *int   `json:"mode"`
}

func (h *handler) overlayWrite(w http.ResponseWriter, r *http.Request) {
	var req overlayWriteReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	out, err := h.svc.OverlayWrite(r.Context(), req.Path, req.Content, req.Mode)
	if err != nil {
		fail(w, err)
		return
	}
	// The content is not audited, only that it changed and by whom. An overlay
	// file is routinely a config carrying a token or a key, and an audit log is
	// read by more people than the thing it describes.
	h.audit(r, "imaging.overlay.write", req.Path, map[string]any{"bytes": len(req.Content)})
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
