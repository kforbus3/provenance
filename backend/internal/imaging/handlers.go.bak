package imaging

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/Moorgate/backend/internal/app"
	"github.com/kforbus3/Moorgate/backend/internal/auth"
	"github.com/kforbus3/Moorgate/backend/internal/httpx"
	"github.com/kforbus3/Moorgate/backend/internal/models"
	"github.com/kforbus3/Moorgate/backend/internal/store"
)

// Mount registers the imaging routes.
//
// Everything proxies to Flipside rather than exposing it directly, so that
// Moorgate's authentication, roles, host-access rules and audit log apply to
// OS updates exactly as they do to everything else — and so the Flipside
// operator token never leaves the backend. A browser holding that token would
// be a second, weaker way into the imaging server.
func Mount(r chi.Router, d *app.Deps, svc *Service) {
	h := &handler{d: d, svc: svc}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)

		// Always answerable, even when nothing is configured: the UI needs to
		// know whether to show the section at all, and "not configured" is a
		// legitimate answer rather than an error.
		pr.Get("/imaging/status", h.status)

		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/images", h.images)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/bundles", h.bundles)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/fleet", h.fleet)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/groups", h.groups)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/rollouts", h.rollouts)
		pr.With(d.Auth.RequirePermission("Imaging.View")).Get("/imaging/rollouts/{id}", h.rollout)

		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/rollouts", h.createRollout)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/rollouts/{id}/{verb}", h.steerRollout)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Put("/imaging/hosts/{hostId}/link", h.link)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/hosts/{hostId}/nudge", h.nudge)
		pr.With(d.Auth.RequirePermission("Imaging.Manage")).Post("/imaging/hosts/{hostId}/install", h.install)
	})
}

type handler struct {
	d   *app.Deps
	svc *Service
}

// fail turns a Flipside error into an HTTP response that says which system
// failed and why. Without this every problem reads as "500 from Moorgate",
// and the first hour of debugging goes to the wrong service.
func (h *handler) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotConfigured) {
		httpx.WriteError(w, http.StatusServiceUnavailable,
			"no Flipside server is configured (set FLEET_FLIPSIDE_URL)")
		return
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Unauthorized():
			httpx.WriteError(w, http.StatusBadGateway,
				"Flipside rejected this server's token — check FLEET_FLIPSIDE_TOKEN "+
					"and that it still exists and has the operator role")
		case apiErr.Status >= 400 && apiErr.Status < 500:
			// Flipside's own refusal, passed through: it validates rollouts and
			// says exactly what is wrong with one, and rewording that here
			// would only lose detail.
			httpx.WriteError(w, apiErr.Status, apiErr.Detail)
		default:
			httpx.WriteError(w, http.StatusBadGateway, apiErr.Error())
		}
		return
	}
	httpx.WriteError(w, http.StatusBadGateway, err.Error())
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	if !h.svc.Enabled() {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	version, err := h.svc.client.Health(r.Context())
	out := map[string]any{
		"configured": true,
		"url":        h.svc.cfg.FlipsideURL,
		"nudge":      h.svc.cfg.FlipsideNudge,
		"reachable":  err == nil,
	}
	if err != nil {
		// The reason, not just a red dot. "Flipside rejected this token" and
		// "nothing is listening" need different people to do different things.
		out["error"] = err.Error()
	} else {
		out["version"] = version
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) images(w http.ResponseWriter, r *http.Request) {
	images, err := h.svc.client.Images(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"images": images})
}

func (h *handler) bundles(w http.ResponseWriter, r *http.Request) {
	bundles, err := h.svc.client.Bundles(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, bundles)
}

func (h *handler) groups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.svc.client.Groups(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// fleetRow is one line of the merged view: a Moorgate host and whatever
// Flipside knows about the same machine.
type fleetRow struct {
	HostID    string   `json:"hostId,omitempty"`
	Hostname  string   `json:"hostname"`
	Env       string   `json:"environment,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Enrolled  bool     `json:"enrolled"`
	MachineID string   `json:"machineId,omitempty"`
	LinkedBy  string   `json:"linkedBy"` // linked | hostname | none
	Machine   *Machine `json:"machine,omitempty"`
	// Reachable is whether Moorgate could push to this host — which is the
	// whole reason the two systems are joined, and the thing an operator wants
	// to see at a glance before starting a rollout.
	Reachable bool `json:"reachable"`
}

func (h *handler) fleet(w http.ResponseWriter, r *http.Request) {
	view, err := h.svc.client.Fleet(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	hosts, err := h.svc.store.ListHosts(r.Context(), 10000, 0)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list hosts")
		return
	}
	p := auth.MustPrincipal(r)
	links, orphans := Correlate(hosts, view.Machines)

	rows := make([]fleetRow, 0, len(links)+len(orphans))
	for _, l := range links {
		// A host the caller may not see must not appear here just because it
		// also exists in Flipside. Host access is Moorgate's rule and applies
		// to every view of a host, including this one.
		if !h.canSee(r, p, l.Host.ID) {
			continue
		}
		rows = append(rows, fleetRow{
			HostID:    l.Host.ID.String(),
			Hostname:  l.Host.Hostname,
			Env:       l.Host.Environment,
			Tags:      l.Host.Tags,
			Enrolled:  l.Host.Enrolled,
			MachineID: machineID(l.Machine),
			LinkedBy:  l.How,
			Machine:   l.Machine,
			Reachable: l.Host.Enrolled && l.Host.Protocol != "rdp",
		})
	}
	// Machines Flipside has and Moorgate does not — imaged but never enrolled,
	// usually. Shown without a host id, so nothing about them is actionable
	// here; the point is that they are visible at all.
	for i := range orphans {
		m := orphans[i]
		rows = append(rows, fleetRow{
			Hostname:  firstNonEmpty(m.Hostname, m.ID),
			MachineID: m.ID,
			LinkedBy:  "none",
			Machine:   &m,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"rows":       rows,
		"counts":     view.Counts,
		"versions":   view.Versions,
		"interval":   view.Interval,
		"controlUrl": view.ControlURL,
	})
}

func machineID(m *Machine) string {
	if m == nil {
		return ""
	}
	return m.ID
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (h *handler) rollouts(w http.ResponseWriter, r *http.Request) {
	rollouts, err := h.svc.client.Rollouts(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rollouts": rollouts})
}

func (h *handler) rollout(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.client.Rollout(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) createRollout(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !httpx.Decode(w, r, &body) {
		return
	}
	out, err := h.svc.client.CreateRollout(r.Context(), body)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.audit(r, "imaging.rollout.create", out.ID, map[string]any{
		"bundle": out.Bundle, "version": out.Version, "machines": out.Total,
	})
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *handler) steerRollout(w http.ResponseWriter, r *http.Request) {
	id, verb := chi.URLParam(r, "id"), chi.URLParam(r, "verb")
	switch verb {
	case "pause", "resume", "cancel":
	default:
		httpx.WriteError(w, http.StatusBadRequest, "verb must be pause, resume or cancel")
		return
	}
	if err := h.svc.client.SteerRollout(r.Context(), id, verb); err != nil {
		h.fail(w, err)
		return
	}
	h.audit(r, "imaging.rollout."+verb, id, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type linkReq struct {
	MachineID string `json:"machineId"`
}

// link pins a host to a Flipside machine, or clears the pin with an empty id.
func (h *handler) link(w http.ResponseWriter, r *http.Request) {
	host, p, ok := h.host(w, r)
	if !ok {
		return
	}
	var body linkReq
	if !httpx.Decode(w, r, &body) {
		return
	}
	id := strings.TrimSpace(body.MachineID)
	// The id reaches a URL path when Flipside is called about this machine, and
	// it comes from a browser. Bounded and free of separators; Flipside's own
	// ids are MAC addresses or similar.
	if len(id) > 128 || strings.ContainsAny(id, "/\\?#") {
		httpx.WriteError(w, http.StatusBadRequest, "that is not a usable machine id")
		return
	}
	in := hostInputFrom(host)
	in.Options.FlipsideMachineID = id
	if _, err := h.svc.store.UpdateHost(r.Context(), host.ID, in); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the link")
		return
	}
	_ = p
	h.audit(r, "imaging.host.link", host.ID.String(), map[string]any{"machineId": id})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "machineId": id})
}

func (h *handler) nudge(w http.ResponseWriter, r *http.Request) {
	host, _, ok := h.host(w, r)
	if !ok {
		return
	}
	out, err := h.svc.Nudge(r.Context(), host)
	h.audit(r, "imaging.host.nudge", host.ID.String(), map[string]any{"ok": err == nil})
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": false, "output": out, "error": err.Error(),
			// A failed nudge is not a failed update, and saying so here stops
			// it being read as one.
			"note": "The machine's agent still checks in on its own timer, so this " +
				"delays the update rather than preventing it.",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

type installReq struct {
	BundleURL string `json:"bundleUrl"`
	Reboot    bool   `json:"reboot"`
}

// install writes a bundle to a host directly and then tells Flipside what it
// found there, for machines that cannot reach Flipside themselves.
func (h *handler) install(w http.ResponseWriter, r *http.Request) {
	host, _, ok := h.host(w, r)
	if !ok {
		return
	}
	var body installReq
	if !httpx.Decode(w, r, &body) {
		return
	}
	// Reported back to Flipside afterwards, because a machine that cannot reach
	// it cannot say it took the update -- and a rollout containing that machine
	// would otherwise wait for a check-in that can never arrive.
	machineID := MachineIDFor(host)
	if machineID == "" {
		// Without a pairing there is nothing to report against. The install
		// still happens; it just does not advance any rollout, and saying so
		// is better than silently doing half the job.
		machineID = ""
	}
	p := auth.MustPrincipal(r)
	out, err := h.svc.InstallAndReport(r.Context(), host, machineID,
		strings.TrimSpace(body.BundleURL), "moorgate:"+p.Username)
	h.audit(r, "imaging.host.install", host.ID.String(), map[string]any{
		"bundleUrl": body.BundleURL, "ok": err == nil, "machineId": machineID,
	})
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok": false, "output": out, "error": err.Error()})
		return
	}
	note := "Installed to the inactive slot. The machine boots it on the next " +
		"reboot; until then it is still running the old version."
	if machineID == "" {
		note += " This host is not paired with a Flipside machine, so no rollout " +
			"was told about it — pair it if you want the rollout to count this."
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out, "note": note})
}

// hostInputFrom copies a host into the shape UpdateHost writes back.
//
// UpdateHost is a whole-row write: every column in HostInput is assigned, so a
// field left unset is a field *cleared*. Setting one option by hand-listing the
// others is a trap, and it had already sprung -- the first version of this
// omitted WGAddress, so pairing a host with a Flipside machine would have wiped
// its overlay address, which is how Moorgate reaches it. Pairing a host would
// have broken the ability to push to it, silently, and the page that did it
// would have said "Paired."
//
// One conversion, in one place, with a test that fails when a field is added to
// HostInput and not copied here.
func hostInputFrom(h *models.Host) store.HostInput {
	return store.HostInput{
		Hostname:     h.Hostname,
		Description:  h.Description,
		Environment:  h.Environment,
		Owner:        h.Owner,
		Address:      h.Address,
		WGAddress:    h.WGAddress,
		SSHPort:      h.SSHPort,
		SSHUser:      h.SSHUser,
		Tags:         h.Tags,
		AuthMethod:   h.AuthMethod,
		CredentialID: h.CredentialID,
		Protocol:     h.Protocol,
		RDPPort:      h.RDPPort,
		RDPOptions:   h.RDPOptions,
		Options:      h.Options,
	}
}

// host resolves the host in the path and checks the caller may touch it.
func (h *handler) host(w http.ResponseWriter, r *http.Request) (*models.Host, *auth.Principal, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "hostId"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad host id")
		return nil, nil, false
	}
	p := auth.MustPrincipal(r)
	if !h.canSee(r, p, id) {
		// Not found rather than forbidden: whether a host exists is itself
		// something a caller without access should not learn.
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, nil, false
	}
	host, err := h.svc.store.GetHost(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "host not found")
		return nil, nil, false
	}
	return host, p, true
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

func (h *handler) audit(r *http.Request, action, target string, detail map[string]any) {
	httpx.Audit(r, h.d.Store, models.AuditEvent{
		Action: action, TargetKind: "imaging", TargetID: target, Detail: detail,
	})
}
