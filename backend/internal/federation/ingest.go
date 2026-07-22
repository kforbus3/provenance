package federation

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// hostPush is one host snapshot a site sends on a push stream.
type hostPush struct {
	HostID uuid.UUID       `json:"hostId"`
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
}

// ingestPush consumes a site→hub push stream, updating the hub read-model and
// re-broadcasting live events (re-tagged with site_id) to hub dashboards. ctx runs
// under bypass; siteTenant is the site's hub tenant, supplied to every cache write so
// the aggregated read-model is correctly tenant-scoped (site-as-tenant).
func (s *Service) ingestPush(ctx context.Context, siteID, siteTenant uuid.UUID, r io.Reader) {
	dec := json.NewDecoder(r)
	for {
		var msg PushMsg
		if err := dec.Decode(&msg); err != nil {
			return // stream closed
		}
		switch msg.Type {
		case "host":
			var h hostPush
			if err := json.Unmarshal(msg.Data, &h); err != nil {
				continue
			}
			if err := s.deps.Store.UpsertCacheHost(ctx, siteID, h.HostID, h.Status, h.Data, siteTenant); err != nil {
				s.log.Warn("ingest host", "site", siteID, "err", err)
				continue
			}
			// Fan the status out to hub dashboards, tagged with the owning site.
			if s.deps.Events != nil {
				s.deps.Events.Broadcast("host.status", map[string]any{
					"siteId": siteID.String(), "hostId": h.HostID.String(), "status": h.Status,
				})
			}
		case "heartbeat":
			_ = s.deps.Store.SetSiteLink(ctx, siteID, "up", 0, time.Now())
		}
		_ = s.deps.Store.SetSyncState(ctx, siteID, msg.Type, "", 0, time.Now(), siteTenant)
	}
}
