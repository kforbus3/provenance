package containerupdate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/registry"
	"github.com/kforbus3/provenance/backend/internal/store"
)

type handler struct {
	d  *app.Deps
	st *store.Store
	e  *Engine
	// reg resolves what a target tag points at. The server does this itself
	// rather than believing the client; see resolveTargets.
	reg *registry.Client
}

// Mount attaches container-update rollout routes.
//
// Starting one needs Command.Run: it writes a compose file to a host and brings
// containers up, which is running something on that host -- the same permission
// the stack deploy it drives already requires. Pausing, resuming and cancelling
// need it too: they change what is about to run on machines.
//
// Reading needs only Host.View, so an operator who cannot change anything can
// still see what is happening to the fleet.
func Mount(r chi.Router, d *app.Deps, st *store.Store, e *Engine) {
	h := &handler{d: d, st: st, e: e, reg: registry.New()}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/container-update-rollouts", h.list)
		pr.With(d.Auth.RequirePermission("Host.View")).Get("/container-update-rollouts/{id}", h.get)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/container-update-rollouts", h.create)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/container-update-rollouts/{id}/pause", h.pause)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/container-update-rollouts/{id}/resume", h.resume)
		pr.With(d.Auth.RequirePermission("Command.Run")).Post("/container-update-rollouts/{id}/cancel", h.cancel)
		pr.With(d.Auth.RequirePermission("Command.Run")).Delete("/container-update-rollouts/{id}", h.del)
		pr.With(d.Auth.RequirePermission("Command.Run")).Delete("/container-update-rollouts", h.clearFinished)
	})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	out, err := h.st.ListUpdateRollouts(r.Context())
	if err != nil {
		h.d.Log.Warn("listing update rollouts", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not list rollouts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rollouts": out})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := h.st.GetUpdateRollout(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such rollout")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type createRequest struct {
	Repository   string `json:"repository"`
	FromTag      string `json:"fromTag"`
	ToTag        string `json:"toTag"`
	TargetDigest string `json:"targetDigest"`
	// Images covers several at once. When set, the single repository/fromTag/
	// toTag fields are ignored: one rollout over many images is paced as one
	// operation, which is the whole reason it is one rollout and not ten.
	Images      []store.RolloutImage `json:"images"`
	Hosts       []uuid.UUID          `json:"hosts"`
	Canary      int                  `json:"canary"`
	BatchSize   int                  `json:"batchSize"`
	SoakSeconds int                  `json:"soakSeconds"`
	MaxFailures int                  `json:"maxFailures"`
	WindowStart string               `json:"windowStart"`
	WindowEnd   string               `json:"windowEnd"`
	WindowDays  []int32              `json:"windowDays"`
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "could not read the request")
		return
	}
	req.Repository = strings.TrimSpace(req.Repository)
	req.FromTag = strings.TrimSpace(req.FromTag)
	req.ToTag = strings.TrimSpace(req.ToTag)

	images := req.Images
	for i := range images {
		images[i].Repository = strings.TrimSpace(images[i].Repository)
		images[i].FromTag = strings.TrimSpace(images[i].FromTag)
		images[i].ToTag = strings.TrimSpace(images[i].ToTag)
	}
	if len(images) == 0 {
		if req.Repository == "" || req.FromTag == "" || req.ToTag == "" {
			httpx.WriteError(w, http.StatusBadRequest,
				"repository, fromTag and toTag are required (or a list of images)")
			return
		}
		images = []store.RolloutImage{{
			Repository: req.Repository, FromTag: req.FromTag,
			ToTag: req.ToTag, TargetDigest: req.TargetDigest,
		}}
	}
	for _, im := range images {
		if im.Repository == "" || im.FromTag == "" || im.ToTag == "" {
			httpx.WriteError(w, http.StatusBadRequest,
				"every image needs a repository, a fromTag and a toTag")
			return
		}
	}

	hosts := req.Hosts
	if len(hosts) == 0 {
		// No explicit list means "every host running any of these images".
		// Resolved ONCE, here, rather than re-read as the rollout runs: a rollout
		// whose membership changed underneath it could never be complete, and a
		// host that started running the image after the operator approved the
		// change was never part of what they approved.
		var err error
		hosts, err = h.st.HostsRunningAnyImage(r.Context(), images)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not find the hosts running these images")
			return
		}
	}
	if len(hosts) == 0 {
		if len(images) == 1 {
			httpx.WriteError(w, http.StatusBadRequest,
				"no host is running "+images[0].Repository+":"+images[0].FromTag)
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "no host is running any of these images")
		return
	}

	// Defaults that are cautious rather than fast. An operator who says nothing
	// about pacing gets one host first and a soak, not the whole fleet at once:
	// the cost of being slow is waiting, and the cost of being fast is every
	// host on a broken image simultaneously.
	if req.Canary < 0 {
		req.Canary = 0
	}
	if req.BatchSize < 1 {
		req.BatchSize = 1
	}
	if req.SoakSeconds < 0 {
		req.SoakSeconds = 0
	}
	if req.MaxFailures < 0 {
		req.MaxFailures = 0
	}

	roll := store.UpdateRollout{
		// The first image also fills the summary columns, so a single-image
		// rollout reads exactly as it did and a multi-image one has something to
		// show in a list before its images are loaded.
		Repository: images[0].Repository, FromTag: images[0].FromTag,
		ToTag: images[0].ToTag, TargetDigest: images[0].TargetDigest,
		Images: images,
		Canary: req.Canary, BatchSize: req.BatchSize,
		SoakSeconds: req.SoakSeconds, MaxFailures: req.MaxFailures,
		WindowDays: req.WindowDays,
	}
	if req.WindowStart != "" && req.WindowEnd != "" {
		roll.WindowStart, roll.WindowEnd = &req.WindowStart, &req.WindowEnd
	}

	// Refuse before anything is recorded. The engine checks again per host, but an
	// operator who asked to update this application's own database should be told
	// no at the moment they ask — not have a rollout created that fails later.
	self := selfProject(r.Context(), h.st)
	for _, hostID := range hosts {
		containers, cerr := h.st.HostContainers(r.Context(), hostID)
		if cerr != nil {
			continue
		}
		for _, c := range containers {
			if !isSelfContainer(self, c.ComposeProject, c.Image) {
				continue
			}
			for _, im := range images {
				if c.Repository == im.Repository && c.Tag == im.FromTag {
					httpx.WriteError(w, http.StatusBadRequest, c.Name+" is part of Provenance "+
						"itself. This application is upgraded by signed bundle — which verifies "+
						"the signature, backs up the database, applies migrations and keeps a "+
						"rollback — not by replacing its containers underneath it.")
					return
				}
			}
		}
	}

	// Refuse a major-version bump of a stateful image, for the same reason and at
	// the same moment: the operator asked for something a rollout cannot do, and
	// should be told now rather than discover it as a crash-looping database.
	for _, im := range images {
		if how, yes := isStatefulMajorBump(im.Repository, im.FromTag, im.ToTag); yes {
			httpx.WriteError(w, http.StatusBadRequest, im.Repository+" "+im.FromTag+" → "+
				im.ToTag+" crosses a major version. This image owns its on-disk format: the "+
				"new version will refuse the existing data directory and the container will "+
				"restart forever with the service down. It needs "+how+" first, with both "+
				"versions available — which a container rollout cannot do. Migrate the data, "+
				"then pin the new tag in the stack.")
			return
		}
	}

	// The server decides what each target points at.
	//
	// The client was sending the digest from the updates row, which is what the
	// FROM tag points at now. For a rebuild those are the same thing and it was
	// right; for a version bump it is the OLD image's digest, so verification
	// compared a correctly-updated container against the bytes it had just moved
	// away from:
	//
	//	deployed, but curlimages/curl:8.22.0 is running sha256:58adaa4e…
	//	rather than the sha256:d9b4541e… this rollout targets
	//
	// The deploy had worked. The rollout failed itself on its own expectation,
	// which is worse than failing to act: the fleet moved and the record says it
	// did not. A value the server can look up is not one to accept from a caller.
	h.resolveTargets(r.Context(), images)

	var by *uuid.UUID
	if p := auth.MustPrincipal(r); p != nil {
		id := p.UserID
		by = &id
	}
	out, err := h.st.CreateUpdateRollout(r.Context(), roll, hosts, by)
	if err != nil {
		h.d.Log.Warn("creating update rollout", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not create the rollout")
		return
	}
	h.d.Log.Info("container update rollout created",
		"images", len(images), "repository", roll.Repository,
		"from", roll.FromTag, "to", roll.ToTag,
		"hosts", len(hosts), "canary", roll.Canary, "batch", roll.BatchSize)
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *handler) setState(w http.ResponseWriter, r *http.Request, state string) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.st.SetUpdateRolloutState(r.Context(), id, state, ""); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not change the rollout")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"state": state})
}

func (h *handler) pause(w http.ResponseWriter, r *http.Request) {
	h.setState(w, r, store.UpdateRolloutPaused)
}

func (h *handler) cancel(w http.ResponseWriter, r *http.Request) {
	h.setState(w, r, store.UpdateRolloutCancelled)
}

// resume restarts a halted or paused rollout, forgiving what stopped it.
//
// Not setState: resuming a HALTED rollout without forgiving the failures that
// halted it re-halts on the very next tick, which makes this a button that
// reports success and does nothing.
func (h *handler) resume(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.st.ResumeUpdateRollout(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not resume the rollout")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"state": store.UpdateRolloutRunning})
}

// del removes one finished rollout from the history.
//
// The containers it updated are untouched; this clears the record, not the
// state. A rollout still running is refused rather than deleted -- see
// DeleteUpdateRollout.
func (h *handler) del(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.st.DeleteUpdateRollout(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrRolloutNotFinished) {
			httpx.WriteError(w, http.StatusConflict,
				"only a finished rollout can be cleared — cancel it first")
			return
		}
		h.d.Log.Warn("deleting update rollout", "id", id, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear the rollout")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": 1})
}

// clearFinished removes every finished rollout in one call.
//
// One statement rather than a delete per id from the client: clearing thirty
// rollouts should not be thirty requests that can half-fail and leave the list
// in a state nobody asked for.
func (h *handler) clearFinished(w http.ResponseWriter, r *http.Request) {
	n, err := h.st.DeleteFinishedUpdateRollouts(r.Context())
	if err != nil {
		h.d.Log.Warn("clearing finished update rollouts", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not clear the rollouts")
		return
	}
	h.d.Log.Info("cleared finished container update rollouts", "count", n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// resolveTargets fills in what each image's TARGET tag points at, in place.
//
// Best-effort. A registry that will not answer leaves the digest empty, and
// verification then accepts the tag alone — weaker, but it is the difference
// between "we could not pin this exactly" and refusing to do the update at all.
func (h *handler) resolveTargets(ctx context.Context, images []store.RolloutImage) {
	for i := range images {
		d, err := h.reg.Digest(ctx, images[i].Repository, images[i].ToTag)
		if err != nil {
			h.d.Log.Info("update rollout: could not resolve the target digest",
				"repository", images[i].Repository, "tag", images[i].ToTag, "err", err)
			images[i].TargetDigest = ""
			continue
		}
		images[i].TargetDigest = d
	}
}
