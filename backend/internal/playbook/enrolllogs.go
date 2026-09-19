package playbook

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// canonicalLogEnrolmentPlaybook is the name Aldgate's enrolment playbook carries when
// imported as documented. Matched first, exactly, so an install that followed the
// documentation gets a predictable answer.
const canonicalLogEnrolmentPlaybook = "enroll syslog to aldgate"

// logEnrolmentDocHint is the whole error message for an install with no enrolment
// playbook imported. It names the file and where to put it, because "no playbook
// found" tells an operator nothing they can act on.
const logEnrolmentDocHint = "No log-enrolment playbook is imported. Import " +
	"aldgate/ansible/enroll-syslog.yml under Automation → Playbooks (see docs/aldgate.md), " +
	"then run this again."

// enrollLogsReq is the selection from the Hosts page.
type enrollLogsReq struct {
	HostIDs []string `json:"hostIds"`
}

type enrollLogsSkip struct {
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

// enrollLogs points the selected hosts at the log collector by running the imported
// enrolment playbook against them.
//
// It runs the operator's OWN playbook rather than a copy embedded here. A second copy
// would drift from Aldgate's -- the file that gets fixed when a new host type turns
// out to have no rsyslog -- and the operator would have no way to tell which one had
// just run on their fleet.
func (h *handler) enrollLogs(w http.ResponseWriter, r *http.Request) {
	var rq enrollLogsReq
	if !httpx.Decode(w, r, &rq) {
		return
	}
	if len(rq.HostIDs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no hosts selected")
		return
	}
	p := auth.MustPrincipal(r)

	all, err := h.d.Store.ListPlaybooks(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list playbooks")
		return
	}
	chosen := pickLogEnrolmentPlaybook(all)
	if chosen == nil {
		httpx.WriteError(w, http.StatusPreconditionFailed, logEnrolmentDocHint)
		return
	}
	pb, err := h.d.Store.GetPlaybook(r.Context(), chosen.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the enrolment playbook")
		return
	}

	var (
		hosts   []*models.Host
		skipped []enrollLogsSkip
		seen    = map[uuid.UUID]bool{}
	)
	for _, raw := range rq.HostIDs {
		hid, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "bad host id")
			return
		}
		if seen[hid] {
			continue
		}
		seen[hid] = true
		host, err := h.d.Store.GetHost(r.Context(), hid)
		if err != nil {
			httpx.WriteError(w, http.StatusNotFound, "host not found")
			return
		}
		if !h.canAccessHost(r, p, host.ID) {
			httpx.WriteError(w, http.StatusForbidden, "not authorized for host "+host.Hostname)
			return
		}
		// A network device does not have rsyslog and this playbook would fail on it.
		// Say so by name instead of running and reporting a red run: the operator's
		// next step is a different playbook, and they need to know that, not a stack
		// trace from Ansible.
		if host.IsRouterOS() {
			skipped = append(skipped, enrollLogsSkip{host.Hostname,
				"RouterOS device — use “Enroll Syslog And SNMP To Aldgate (RouterOS)”"})
			continue
		}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"playbook": pb.Name, "hostCount": 0, "skipped": skipped,
		})
		return
	}

	targetName := fmt.Sprintf("%d hosts", len(hosts))
	var targetID *uuid.UUID
	if len(hosts) == 1 {
		targetName = hosts[0].Hostname
		targetID = &hosts[0].ID
	}
	rec, err := h.d.Store.CreatePlaybookRun(r.Context(), models.PlaybookRun{
		PlaybookID:      pb.ID,
		PlaybookVersion: pb.Version,
		Requester:       p.Username,
		TargetKind:      "host",
		TargetID:        targetID,
		TargetName:      targetName,
		HostCount:       len(hosts),
	}, &p.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create run")
		return
	}
	go h.svc.Run(context.WithoutCancel(r.Context()), rec.ID, pb.Content, hosts, false)

	names := make([]string, 0, len(hosts))
	for _, hh := range hosts {
		names = append(names, hh.Hostname)
	}
	// Audited as a playbook run, because that is exactly what it is -- the audit trail
	// must not show a gentler action than the one that ran as root on these hosts.
	h.audit(r, "playbook.run", pb.ID.String(), map[string]any{
		"name": pb.Name, "version": pb.Version, "runId": rec.ID,
		"targetKind": "host", "target": targetName, "hosts": names,
		"hostCount": len(hosts), "via": "logs.enroll",
	})
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"runId": rec.ID, "playbook": pb.Name, "hostCount": len(hosts), "skipped": skipped,
	})
}

// pickLogEnrolmentPlaybook chooses the playbook that enrols a Linux host into log
// collection, or nil when none is imported.
//
// Matching by name because that is what the operator sees and can change. The
// device-specific variants share the same words ("Enroll Syslog To Aldgate
// (OpenWrt)"), and running one of those against a Debian fleet would do nothing
// useful, so they are excluded explicitly rather than by hoping the exact-name
// match wins.
func pickLogEnrolmentPlaybook(all []*models.Playbook) *models.Playbook {
	var candidates []*models.Playbook
	for _, pb := range all {
		name := strings.ToLower(strings.TrimSpace(pb.Name))
		if name == canonicalLogEnrolmentPlaybook {
			return pb
		}
		if !strings.Contains(name, "syslog") && !strings.Contains(name, "log collection") {
			continue
		}
		if isDeviceSpecific(name) {
			continue
		}
		candidates = append(candidates, pb)
	}
	if len(candidates) == 0 {
		return nil
	}
	// Most recently updated first: if an operator keeps two, the one they have been
	// working on is the one they mean.
	sort.SliceStable(candidates, func(a, b int) bool {
		return candidates[a].UpdatedAt.After(candidates[b].UpdatedAt)
	})
	return candidates[0]
}

// isDeviceSpecific reports whether a playbook name marks it as for a network device
// rather than a general Linux host.
func isDeviceSpecific(lowerName string) bool {
	for _, d := range []string{"routeros", "openwrt", "swos", "mikrotik", "docker"} {
		if strings.Contains(lowerName, d) {
			return true
		}
	}
	return false
}
