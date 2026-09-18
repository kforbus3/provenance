package logsbroker

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// Mount attaches the log search routes.
//
// One permission, Logs.View, and it is a read-only surface: there is nothing
// here that changes a log, because changing a log is not a thing an audit trail
// should offer. Retention is the collector's business.
func Mount(r chi.Router, d *app.Deps) {
	c := New(d.Cfg.AldgateURL, d.Cfg.AldgateUser, d.Cfg.AldgatePassword)
	h := &handler{d: d, c: c}
	r.Group(func(pr chi.Router) {
		pr.Use(d.Auth.RequireAuth)
		pr.With(d.Auth.RequirePermission("Logs.View")).Get("/logs/search", h.search)
		pr.With(d.Auth.RequirePermission("Logs.View")).Get("/logs/hosts", h.hosts)
		pr.With(d.Auth.RequirePermission("Logs.View")).Get("/logs/status", h.status)
	})
}

type handler struct {
	d *app.Deps
	c *Client
}

// status says whether a collector is configured and reachable.
//
// Its own endpoint because "no logs" and "no collector" look identical in a
// search result and are completely different problems. The UI uses this to say
// which one it is instead of showing an empty table.
func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	if h.c == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"hint": "Set PROV_ALDGATE_URL (and PROV_ALDGATE_USER / PROV_ALDGATE_PASSWORD) " +
				"to the Aldgate collector to search logs here.",
		})
		return
	}
	hosts, err := h.c.Hosts(r.Context(), "now-24h")
	if err != nil && !IsNoData(err) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"configured": true, "reachable": false, "error": err.Error(),
			"url": h.c.BaseURL,
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"configured": true, "reachable": true, "url": h.c.BaseURL,
		"hostsSending": len(hosts),
	})
}

func (h *handler) hosts(w http.ResponseWriter, r *http.Request) {
	if h.c == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": []Bucket{}})
		return
	}
	hosts, err := h.c.Hosts(r.Context(), r.URL.Query().Get("since"))
	if err != nil {
		if IsNoData(err) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": []Bucket{}})
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (h *handler) search(w http.ResponseWriter, r *http.Request) {
	if h.c == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable,
			"no log collector is configured — set PROV_ALDGATE_URL")
		return
	}
	q := r.URL.Query()
	minSev, _ := strconv.Atoi(q.Get("minSeverity"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	query := Query{
		Text:      strings.TrimSpace(q.Get("q")),
		Host:      strings.TrimSpace(q.Get("host")),
		Program:   strings.TrimSpace(q.Get("program")),
		MinSev:    minSev,
		Since:     strings.TrimSpace(q.Get("since")),
		Until:     strings.TrimSpace(q.Get("until")),
		Limit:     limit,
		Ascending: q.Get("order") == "asc",
	}

	res, err := h.c.Search(r.Context(), query)
	if err != nil {
		if IsNoData(err) {
			httpx.WriteJSON(w, http.StatusOK, &Result{Entries: []Entry{}, ByHost: []Bucket{}, BySev: []Bucket{}})
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Recorded, including WHAT was searched for. A log system that cannot say who
	// went looking at which host's authentication messages is missing the part
	// that matters most about itself.
	h.audit(r, "logs.search", map[string]any{
		"q": query.Text, "host": query.Host, "program": query.Program,
		"minSeverity": query.MinSev, "since": query.Since, "until": query.Until,
		"matched": res.Total,
	})
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *handler) audit(r *http.Request, action string, detail map[string]any) {
	p := auth.MustPrincipal(r)
	ev := models.AuditEvent{
		Action: action, TargetKind: "logs", Detail: detail, IP: httpx.ClientIP(r),
	}
	if p != nil {
		id := p.UserID
		if id != uuid.Nil {
			ev.ActorID = &id
		}
		ev.ActorName = p.Username
	}
	_, _ = h.d.Store.AppendAudit(r.Context(), ev)
}
