package imaging

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/blackfriars/backend/internal/app"
	"github.com/kforbus3/blackfriars/backend/internal/auth"
	"github.com/kforbus3/blackfriars/backend/internal/httpx"
	"github.com/kforbus3/blackfriars/backend/internal/models"
)

// Mount registers the imaging routes.
//
// One of them is unlike everything else in this product: the agent heartbeat is
// reached by machines, not by people, and is deliberately open. See heartbeat.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}

	// Machines. No session, no role -- see the comment on heartbeat, and the
	// stronger version of the same argument at the top of imagerhandlers.go.
	r.Post("/imaging/heartbeat", h.heartbeat)
	mountImager(r, h)

	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/images", h.images)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/bundles", h.bundles)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/machines", h.machines)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/now", h.imagingNow)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Delete("/imaging/now/{id}", h.forgetImaging)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/rollouts", h.rollouts)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/rollouts/{id}", h.rollout)

		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/rollouts", h.createRollout)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/rollouts/{id}/{verb}", h.steerRollout)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Delete("/imaging/rollouts/{id}", h.deleteRollout)

		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Put("/imaging/machines/{id}", h.updateMachine)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/machines/{id}/nudge", h.nudge)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/machines/{id}/install", h.install)

		// Building artefacts and running the provisioning stack; see
		// buildhandlers.go for why those are separate permissions.
		mountBuilds(pr, h)
	})
}

// MountMachineCompat registers the machine-facing endpoints at the *unversioned*
// paths that software already in the field posts to.
//
// `/api/fleet/heartbeat` is compiled into every ab-agent on every image ever
// built, and `/api/imaging/report` is derived inside a netboot initramfs from
// the address the image came from. Neither can be changed by editing this
// repository: the change would have to reach machines that only take an update
// by asking these endpoints for one, which is the definition of a path that
// cannot be migrated.
//
// So they are not deprecated aliases waiting to be removed. They are the wire
// contract, and the versioned routes are the convenience. Mounted outside
// /api/v1 deliberately, and outside its CSRF and session middleware, because a
// machine has neither.
func MountMachineCompat(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Post("/api/fleet/heartbeat", h.heartbeat)
	r.Post("/api/imaging/report", h.imagerReport)
	r.Post("/api/imaging/checkin", h.imagerCheckin)
}

type handler struct {
	d   *app.Deps
	svc *Service
}

func clean(v string, limit int) string {
	v = strings.ReplaceAll(strings.ReplaceAll(v, "\n", " "), "\r", " ")
	v = strings.TrimSpace(v)
	if len(v) > limit {
		v = v[:limit]
	}
	return v
}

// --- the machine-facing endpoint ---------------------------------------------

// heartbeat is one agent check-in. It answers with what, if anything, the
// machine should do.
//
// Unauthenticated on purpose, and it is the only endpoint here that is. It is
// reached by a machine this system provisioned and handed no credential to: at
// the moment of its first check-in the machine has just been imaged and has
// nothing to authenticate with. What it can assert is bounded to the fields
// below, and what it can cause is bounded to "install a bundle this server is
// already offering, signed by a key the machine already trusts" -- so a machine
// that lies its way into a rollout receives an update it would have been given
// anyway. Set AGENT_TOKEN when the control plane is reachable from a network
// that is not the provisioning one.
//
// It answers `key=value` lines rather than JSON. The agent is a shell script on
// a minimal image that ships neither jq nor python3; adding a JSON parser to
// every machine in order to read six fields would be a strange price, and
// hand-rolling one in sed to avoid it would be worse.
func (h *handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	if tok := h.svc.cfg.AgentToken; tok != "" {
		if !agentTokenOK(r, tok) {
			httpx.WriteError(w, http.StatusUnauthorized, "bad or missing agent token")
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		writeKV(w, map[string]string{"ok": "false", "error": "unreadable form"})
		return
	}
	id := clean(r.PostForm.Get("id"), 128)
	if id == "" {
		writeKV(w, map[string]string{"ok": "false", "error": "id is required"})
		return
	}

	m := &models.ImagingMachine{
		ID:            id,
		Hostname:      clean(r.PostForm.Get("hostname"), 200),
		Address:       clientIP(r),
		Slot:          clean(r.PostForm.Get("slot"), 8),
		Version:       clean(r.PostForm.Get("version"), 200),
		Arch:          clean(r.PostForm.Get("arch"), 32),
		AgentVersion:  clean(r.PostForm.Get("agent_version"), 32),
		BootID:        clean(r.PostForm.Get("boot_id"), 64),
		Health:        clean(r.PostForm.Get("health"), 32),
		UpdateState:   clean(r.PostForm.Get("update_state"), 32),
		UpdateError:   clean(r.PostForm.Get("update_error"), 300),
		UpdateRollout: clean(r.PostForm.Get("update_rollout"), 64),
		ReportedBy:    id,
		ReportSource:  "agent",
	}
	// Note what is absent: groups, held, label. Those are an operator's word
	// about a machine, never the machine's word about itself -- otherwise any
	// machine on the network could put itself into a rollout it was never
	// targeted by.
	if _, err := h.svc.store.ReportMachine(r.Context(), m); err != nil {
		h.svc.log.Warn("imaging: recording a heartbeat", "machine", id, "err", err)
		writeKV(w, map[string]string{"ok": "false", "error": "could not record"})
		return
	}

	out := map[string]string{
		"ok":       "true",
		"interval": itoa(int(h.svc.AgentInterval().Seconds())),
	}
	if url := h.svc.cfg.ControlURL; url != "" {
		// Re-point the fleet centrally. This is the way out of the
		// imaging-address trap: the URL the imager wrote is the provisioning
		// server's, which a machine stops being able to reach the moment it is
		// unracked.
		out["control_url"] = strings.TrimRight(url, "/")
	}
	if act := h.svc.EvaluateFor(r.Context(), id, Report{
		Version: m.Version, Health: m.Health,
		UpdateState: m.UpdateState, UpdateError: m.UpdateError,
	}); act != nil {
		out["action"] = act.Type
		out["bundle_url"] = act.BundleURL
		out["version"] = act.Version
		out["rollout"] = act.RolloutID
	} else {
		out["action"] = "none"
	}
	writeKV(w, out)
}

// AgentAuthHeader is the header every deployed agent sends its token in.
//
// Named for the header rather than for what it carries: gosec's G101 flags any
// constant whose identifier looks like a credential, and a header NAME that
// trips a hardcoded-secret check is a false positive somebody has to re-decide
// every time they read it.
//
// The name is not one this code gets to choose. It is compiled into ab-agent on
// every image ever built, and an agent cannot be corrected without an update it
// would have to authenticate to receive -- so the server accepts what the fleet
// sends, exactly as it serves the unversioned machine paths.
//
// Getting this wrong is silent and total. FLEET_AGENT_TOKEN is set precisely
// when the control plane is reachable from a network that is not the
// provisioning one, which is the moment a fleet is at its most spread out; a
// mismatch 401s every heartbeat from every machine at once, and the only symptom
// is machines quietly ceasing to check in.
const AgentAuthHeader = "X-Flipside-Agent-Token"

// agentAuthAltHeader is accepted as well, for anything written against this
// API rather than shipped in an image -- a load balancer health check, a
// third-party agent. Not preferred, and not what any real machine sends.
const agentAuthAltHeader = "X-Agent-Token"

func agentTokenOK(r *http.Request, want string) bool {
	// Constant-time, because this compares a shared secret and the timing of a
	// byte-wise comparison is a real if slow oracle.
	for _, h := range []string{AgentAuthHeader, agentAuthAltHeader} {
		if got := r.Header.Get(h); got != "" &&
			subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

func writeKV(w http.ResponseWriter, kv map[string]string) {
	var b strings.Builder
	for _, k := range []string{"ok", "error", "interval", "control_url", "action",
		"bundle_url", "version", "rollout"} {
		if v, present := kv[k]; present && v != "" {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func itoa(n int) string {
	if n <= 0 {
		return "300"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// --- the operator-facing endpoints -------------------------------------------

// images and bundles are the artefact library, read off the same directory the
// builder writes to and the provisioning server serves from.
func (h *handler) images(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Images()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the image library")
		return
	}
	// imagerArches travels with the image library because the two are read
	// together: an image is not deployable without an imager to write it, and
	// finding that out from the provisioning preflight — after choosing a network
	// and pressing Start — is late.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"images": out, "dir": h.svc.artifactDir(), "imagerArches": h.svc.ImagerArches()})
}

// bundles also reports how many machines are running each version, because the
// question an operator actually has in front of the bundle list is "is anything
// still on the old one", and answering it anywhere else means reading two pages
// and doing the join by eye.
func (h *handler) bundles(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Bundles()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the bundle library")
		return
	}
	running := map[string]int{}
	if fleet, ferr := h.svc.FleetView(r.Context(), auth.MustPrincipal(r)); ferr == nil {
		for i := range fleet {
			if v := fleet[i].Version; v != "" {
				running[v]++
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"bundles": out, "runningVersions": running, "controlUrl": h.svc.cfg.ControlURL})
}

func (h *handler) machines(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.FleetView(r.Context(), auth.MustPrincipal(r))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the fleet")
		return
	}
	counts := map[string]int{"online": 0, "stale": 0, "offline": 0, "unknown": 0}
	versions := map[string]int{}
	for i := range rows {
		counts[rows[i].Presence]++
		if rows[i].Version != "" && (rows[i].Presence == "online" || rows[i].Presence == "stale") {
			versions[rows[i].Version]++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"machines": rows, "counts": counts, "versions": versions,
		"interval": int(h.svc.AgentInterval().Seconds()),
	})
}

func (h *handler) rollouts(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.Rollouts(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list rollouts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rollouts": out})
}

func (h *handler) rollout(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	out, err := h.svc.RolloutDetail(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such rollout")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) createRollout(w http.ResponseWriter, r *http.Request) {
	// Decoded straight into the type the service takes. There is no separate
	// request struct: it had exactly these fields, and a second definition of a
	// rollout's inputs is a place for the two to drift.
	var req NewRollout
	if !httpx.Decode(w, r, &req) {
		return
	}
	p := auth.MustPrincipal(r)
	out, err := h.svc.CreateRollout(r.Context(), req, p)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "imaging.rollout.create", out.ID.String(), map[string]any{
		"bundle": out.Bundle, "version": out.Version, "machines": out.Total,
	})
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) steerRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	verb := chi.URLParam(r, "verb")
	switch verb {
	case "pause", "resume", "cancel":
	default:
		httpx.WriteError(w, http.StatusBadRequest, "verb must be pause, resume or cancel")
		return
	}
	if err := h.svc.SteerRollout(r.Context(), id, verb); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "imaging.rollout."+verb, id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) deleteRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	rec, err := h.d.Store.GetRollout(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such rollout")
		return
	}
	if rec.State == RolloutRunning {
		httpx.WriteError(w, http.StatusConflict, "cancel the rollout before deleting it")
		return
	}
	if err := h.d.Store.DeleteRollout(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete it")
		return
	}
	h.audit(r, "imaging.rollout.delete", id.String(), nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type updateMachineReq struct {
	HostID *string `json:"hostId"` // "" clears the pairing
	Label  *string `json:"label"`
	Held   *bool   `json:"held"`
}

// updateMachine writes the operator-owned half of a machine record: which host
// it is, what it is called, and whether it is held back from rollouts.
func (h *handler) updateMachine(w http.ResponseWriter, r *http.Request) {
	id := clean(chi.URLParam(r, "id"), 128)
	m, err := h.d.Store.GetMachine(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such machine")
		return
	}
	var req updateMachineReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	if req.HostID != nil {
		var hostID *uuid.UUID
		if s := strings.TrimSpace(*req.HostID); s != "" {
			parsed, perr := uuid.Parse(s)
			if perr != nil {
				httpx.WriteError(w, http.StatusBadRequest, "bad host id")
				return
			}
			// A caller may not pair a machine to a host they cannot see; that
			// would be a way to act on one through the back door.
			if !h.canSee(r, auth.MustPrincipal(r), parsed) {
				httpx.WriteError(w, http.StatusNotFound, "host not found")
				return
			}
			hostID = &parsed
		}
		if err := h.d.Store.LinkMachine(r.Context(), id, hostID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not save the pairing")
			return
		}
		h.audit(r, "imaging.machine.link", id, map[string]any{"hostId": req.HostID})
	}
	if req.Label != nil || req.Held != nil {
		label, held := m.Label, m.Held
		if req.Label != nil {
			label = clean(*req.Label, 128)
		}
		if req.Held != nil {
			held = *req.Held
		}
		if err := h.d.Store.SetMachineOperatorFields(r.Context(), id, label, held); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not save")
			return
		}
		h.audit(r, "imaging.machine.update", id, map[string]any{"label": label, "held": held})
	}
	out, err := h.d.Store.GetMachine(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not re-read the machine")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) nudge(w http.ResponseWriter, r *http.Request) {
	host, _, ok := h.machineHost(w, r)
	if !ok {
		return
	}
	out, err := h.svc.Nudge(r.Context(), host)
	h.audit(r, "imaging.machine.nudge", host.ID.String(), map[string]any{"ok": err == nil})
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": false, "output": out, "error": err.Error(),
			// A failed nudge is not a failed update, and saying so stops it
			// being read as one.
			"note": "The machine's agent still checks in on its own timer, so this " +
				"delays the update rather than preventing it.",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

type installReq struct {
	BundleURL string `json:"bundleUrl"`
}

func (h *handler) install(w http.ResponseWriter, r *http.Request) {
	host, machineID, ok := h.machineHost(w, r)
	if !ok {
		return
	}
	var req installReq
	if !httpx.Decode(w, r, &req) {
		return
	}
	p := auth.MustPrincipal(r)
	out, err := h.svc.InstallAndReport(r.Context(), host, machineID,
		strings.TrimSpace(req.BundleURL), "operator:"+p.Username)
	h.audit(r, "imaging.machine.install", machineID, map[string]any{
		"bundleUrl": req.BundleURL, "ok": err == nil, "host": host.Hostname,
	})
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": false, "output": out, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out,
		"note": "Installed to the inactive slot. The machine boots it on the next " +
			"reboot; until then it is still running the old version."})
}

// machineHost resolves the machine in the path to the host it is paired with,
// checking the caller may touch that host.
func (h *handler) machineHost(w http.ResponseWriter, r *http.Request) (*models.Host, string, bool) {
	id := clean(chi.URLParam(r, "id"), 128)
	m, err := h.d.Store.GetMachine(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "no such machine")
		return nil, "", false
	}
	if m.HostID == nil {
		httpx.WriteError(w, http.StatusBadRequest,
			"this machine is not paired with a host, so there is no way to reach it")
		return nil, "", false
	}
	if !h.canSee(r, auth.MustPrincipal(r), *m.HostID) {
		// Not found rather than forbidden: whether a host exists is itself
		// something a caller without access should not learn.
		httpx.WriteError(w, http.StatusNotFound, "no such machine")
		return nil, "", false
	}
	host, err := h.d.Store.GetHost(r.Context(), *m.HostID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "the paired host no longer exists")
		return nil, "", false
	}
	return host, id, true
}

func (h *handler) canSee(r *http.Request, p *auth.Principal, hostID uuid.UUID) bool {
	if p == nil {
		return false
	}
	if p.IsSuperAdmin {
		return true
	}
	ok, err := h.d.Store.UserCanAccessHost(r.Context(), p.UserID, hostID)
	return err == nil && ok
}

func parseUUID(w http.ResponseWriter, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad id")
		return uuid.Nil, false
	}
	return id, true
}

func (h *handler) audit(r *http.Request, action, target string, detail map[string]any) {
	httpx.Audit(r, h.d.Store, models.AuditEvent{
		Action: action, TargetKind: "imaging", TargetID: target, Detail: detail,
	})
}
