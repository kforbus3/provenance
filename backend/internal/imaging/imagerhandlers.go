package imaging

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// The endpoints a machine *being imaged* posts into, and the page that watches
// them.
//
// These are the third and last unauthenticated route in this product, and they
// are unauthenticated for a stronger reason than the heartbeat is. The imager
// runs from a netboot initramfs. It has no credentials and no way to obtain
// any -- it is on the provisioning network precisely because it has not been
// provisioned yet. There is no moment at which a credential could have been
// given to it.
//
// What that costs is bounded. `report` accepts progress text, holds it in
// memory, and expires it on its own, so the worst a stranger on that segment can
// do is add a row that disappears again. `checkin` records that a machine
// booted. Neither causes anything to be installed anywhere. The provisioning
// network is the trust boundary here, as it already is for DHCP and TFTP -- and
// anyone who can speak DHCP on that segment can do considerably worse than post
// a progress bar.

func mountImager(r chi.Router, h *handler) {
	r.Post("/imaging/report", h.imagerReport)
	r.Post("/imaging/checkin", h.imagerCheckin)
}

// imagerReport receives one progress report from a machine being written.
func (h *handler) imagerReport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "unreadable form"})
		return
	}
	id := clean(r.PostForm.Get("id"), 128)
	if id == "" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "id is required"})
		return
	}
	phase := clean(r.PostForm.Get("phase"), 32)
	if phase == "" {
		phase = "booted"
	}
	var pct *int
	if raw := r.PostForm.Get("percent"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			pct = &n
		}
	}
	// The machine's own word for its address, not the address this request
	// arrived from.
	//
	// This is the ONLY endpoint anything sends `address=` to: imager/init posts
	// it here, and the agent's heartbeat does not send it at all. The two
	// handlers that were switched to reportedAddress() are the two that never
	// receive the field, so the change had no effect anywhere and this -- the
	// one place it mattered -- was left reading the peer address.
	//
	// It matters because a machine with several NICs knows which of them is on
	// the imaging network and this server does not, and because the address
	// recorded here is what "Add as host" later offers to create the host at.
	row := h.svc.progress.Report(id, phase,
		pct,
		clean(r.PostForm.Get("detail"), 300),
		clean(r.PostForm.Get("disk"), 64),
		clean(r.PostForm.Get("url"), 500),
		reportedAddress(r))

	// A finished imaging run is worth keeping; the live view is not. This is the
	// moment a machine first exists as far as the fleet is concerned -- before
	// it has booted, before it is a host, before anything else knows about it.
	if phase == "done" {
		now := row.LastSeen
		if _, err := h.svc.store.ReportMachine(r.Context(), &models.ImagingMachine{
			ID: id, Address: row.Address, Image: row.Image,
			ImagedAt: &now, ReportedBy: "imager", ReportSource: "observed",
		}); err != nil {
			h.svc.log.Warn("imaging: recording a completed imaging run", "machine", id, "err", err)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "phase": row.Phase, "percent": row.Percent})
}

// imagerCheckin is a machine reporting that it booted the image it was given.
//
// Without this, "imaged" is the last thing ever heard from a machine, and it is
// sent *before* the reboot -- so a machine that images perfectly and then fails
// to boot looks exactly like a success. That gap is the whole reason a machine
// is its own record here rather than a column on a host: the failure lives
// between the last report and the first heartbeat, and something has to be
// holding the machine for it to be visible at all.
func (h *handler) imagerCheckin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "unreadable form"})
		return
	}
	id := clean(r.PostForm.Get("id"), 128)
	if id == "" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "id is required"})
		return
	}
	now := timeNow()
	m := &models.ImagingMachine{
		ID:           id,
		Hostname:     clean(r.PostForm.Get("hostname"), 200),
		Slot:         clean(r.PostForm.Get("slot"), 8),
		Version:      clean(r.PostForm.Get("version"), 200),
		Address:      reportedAddress(r),
		BootedAt:     &now,
		ReportedBy:   id,
		ReportSource: "agent",
	}
	if _, err := h.svc.store.ReportMachine(r.Context(), m); err != nil {
		h.svc.log.Warn("imaging: recording a first boot", "machine", id, "err", err)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "could not record"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- the operator-facing view ------------------------------------------------

func (h *handler) imagingNow(w http.ResponseWriter, r *http.Request) {
	rows := h.svc.progress.Active()
	active := 0
	for i := range rows {
		if rows[i].State == "active" || rows[i].State == "stalled" {
			active++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"imaging": rows, "active": active})
}

// forgetImaging drops a row for a machine that will never report again -- one
// that was unplugged mid-write, most often. It expires on its own; this is for
// the operator who does not want to look at it for the next ten minutes.
func (h *handler) forgetImaging(w http.ResponseWriter, r *http.Request) {
	id := pathID(r, "id")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": h.svc.progress.Forget(id)})
}
