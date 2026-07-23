package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
)

// This file holds the second wave of read-only assistant tools that closed the
// coverage gaps an IT/sysadmin hits: availability/downtime history, CVE results,
// users/roles, pending approvals + just-in-time grants, Windows software, and
// platform (HA cluster + enrollment) health. Each mirrors the RBAC-scoping and
// (table, payload) conventions of the tools in service.go.

// ---------------------------------------------------------------------------
// host_availability — online<->offline transition history (downtime/outages)
// ---------------------------------------------------------------------------

type hostAvailabilityArgs struct {
	Hostname string `json:"hostname"`
	Hours    int    `json:"hours"`
	Limit    int    `json:"limit"`
}

// availabilityRoll is a per-host downtime summary reconstructed from the events.
type availabilityRoll struct {
	Hostname        string     `json:"hostname"`
	WentOffline     int        `json:"wentOffline"`
	DowntimeMinutes int64      `json:"downtimeMinutes"`
	StillOffline    bool       `json:"stillOffline"`
	LastOfflineAt   *time.Time `json:"lastOfflineAt,omitempty"`
	LastRecoveredAt *time.Time `json:"lastRecoveredAt,omitempty"`
}

// runHostAvailability answers uptime/downtime/outage-history questions from the
// recorded online<->offline transitions (scoped to the caller's hosts). It is the
// ONLY source for "did anything go offline?" — current status (query_hosts /
// fleet_insights) cannot see a host that already went down and recovered.
func (s *Service) runHostAvailability(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	var a hostAvailabilityArgs
	_ = json.Unmarshal(raw, &a)
	events, err := s.store.StatusEventsForAssistant(ctx, who.UserID, who.IsSuperAdmin, strings.TrimSpace(a.Hostname), a.Hours, a.Limit)
	if err != nil {
		s.log.Warn("assistant host_availability", "err", err)
		return nil, map[string]any{"error": "could not read availability history"}
	}
	hours := a.Hours
	if hours <= 0 {
		hours = 168
	}
	if len(events) == 0 {
		return nil, map[string]any{
			"count": 0, "windowHours": hours, "events": []any{},
			"note": "no host went offline or recovered in this window (all monitored hosts stayed in the same reachability state)",
		}
	}

	// Reconstruct per-host downtime by walking each host's events oldest-first and
	// pairing an online->offline with the following offline->online.
	perHost := map[string][]models.HostStatusEvent{}
	var order []string
	for i := len(events) - 1; i >= 0; i-- { // events are newest-first; reverse
		e := events[i]
		if _, ok := perHost[e.Hostname]; !ok {
			order = append(order, e.Hostname)
		}
		perHost[e.Hostname] = append(perHost[e.Hostname], e)
	}
	summary := make([]availabilityRoll, 0, len(order))
	for _, host := range order {
		r := availabilityRoll{Hostname: host}
		var offlineSince *time.Time
		for _, e := range perHost[host] {
			switch {
			case e.ToStatus == "offline":
				r.WentOffline++
				at := e.At
				r.LastOfflineAt = &at
				offlineSince = &at
			case e.ToStatus == "online":
				at := e.At
				r.LastRecoveredAt = &at
				if offlineSince != nil {
					r.DowntimeMinutes += int64(at.Sub(*offlineSince).Minutes())
					offlineSince = nil
				}
			}
		}
		r.StillOffline = offlineSince != nil
		summary = append(summary, r)
	}

	tbl := &AssistantTable{
		Title:   "Availability history",
		Columns: []TableColumn{{Label: "Time", Kind: "time"}, {Label: "Host"}, {Label: "Change"}, {Label: "Detail"}},
	}
	for _, e := range events { // newest-first for the UI
		change := e.FromStatus + " → " + e.ToStatus
		tbl.Rows = append(tbl.Rows, []string{tableTime(e.At), e.Hostname, change, e.LastError})
	}
	return tbl, map[string]any{
		"count": len(events), "windowHours": hours,
		"summary": summary, "events": events,
	}
}

// ---------------------------------------------------------------------------
// vulnerabilities — CVE scan results (grype), gated by Host.Scan
// ---------------------------------------------------------------------------

type vulnArgs struct {
	Hostname    string  `json:"hostname"`
	MinSeverity string  `json:"minSeverity"`
	MinCVSS     float64 `json:"minCvss"`
	Limit       int     `json:"limit"`
}

var severityRank = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0,
}

// runVulnerabilities answers "what CVEs are on web-01" / "which hosts have critical
// vulnerabilities". With a hostname it returns that host's latest completed scan's
// findings (optionally filtered by severity/CVSS); without one it returns the
// fleet CVE roll-up (latest scan per accessible host, worst first).
func (s *Service) runVulnerabilities(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewScans && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view vulnerability scans"}
	}
	var a vulnArgs
	_ = json.Unmarshal(raw, &a)
	minRank := severityRank[strings.ToLower(strings.TrimSpace(a.MinSeverity))]

	hostname := strings.TrimSpace(a.Hostname)
	if hostname == "" {
		// Fleet roll-up: latest completed scan per accessible host.
		scans, err := s.store.LatestVulnScansForAssistant(ctx, who.UserID, who.IsSuperAdmin)
		if err != nil {
			s.log.Warn("assistant vulnerabilities rollup", "err", err)
			return nil, map[string]any{"error": "could not read vulnerability scans"}
		}
		if len(scans) == 0 {
			return nil, map[string]any{"count": 0, "scans": []any{}, "note": "no completed vulnerability scans on any accessible host"}
		}
		tbl := &AssistantTable{
			Title:   "Vulnerability posture",
			Columns: []TableColumn{{Label: "Host"}, {Label: "Critical"}, {Label: "High"}, {Label: "Medium"}, {Label: "Low"}, {Label: "Max CVSS"}, {Label: "Scanned", Kind: "time"}},
		}
		for _, v := range scans {
			tbl.Rows = append(tbl.Rows, []string{
				v.Hostname, fmt.Sprint(v.Critical), fmt.Sprint(v.High), fmt.Sprint(v.Medium),
				fmt.Sprint(v.Low), fmt.Sprintf("%.1f", v.MaxCVSS), tableTimePtr(v.FinishedAt),
			})
		}
		return tbl, map[string]any{"count": len(scans), "scans": scans}
	}

	// Per-host findings: latest completed scan for the host.
	host, err := s.store.HostByHostname(ctx, hostname)
	if err != nil {
		return nil, map[string]any{"error": "no host named " + hostname}
	}
	if !who.IsSuperAdmin {
		ok, aerr := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
		if aerr != nil || !ok {
			return nil, map[string]any{"error": "you do not have access to that host"}
		}
	}
	scans, err := s.store.ListVulnScans(ctx, &host.ID, 10)
	if err != nil {
		s.log.Warn("assistant vulnerabilities host", "err", err)
		return nil, map[string]any{"error": "could not read vulnerability scans"}
	}
	var latest *models.VulnScan
	for i := range scans {
		if scans[i].Status == "completed" {
			latest = &scans[i]
			break
		}
	}
	if latest == nil {
		return nil, map[string]any{"count": 0, "note": "no completed vulnerability scan for " + hostname + " (run a scan to populate results)"}
	}
	findings, err := s.store.GetVulnFindings(ctx, latest.ID)
	if err != nil {
		s.log.Warn("assistant vulnerabilities findings", "err", err)
		return nil, map[string]any{"error": "could not read scan findings"}
	}
	limit := a.Limit
	if limit <= 0 || limit > 300 {
		limit = 100
	}
	tbl := &AssistantTable{
		Title:   "Vulnerabilities on " + hostname,
		Columns: []TableColumn{{Label: "CVE"}, {Label: "Package"}, {Label: "Installed"}, {Label: "Fixed in"}, {Label: "Severity"}, {Label: "CVSS"}},
	}
	kept := make([]models.VulnFinding, 0, len(findings))
	for _, f := range findings {
		if minRank > 0 && severityRank[strings.ToLower(f.Severity)] < minRank {
			continue
		}
		if a.MinCVSS > 0 && f.CVSSScore < a.MinCVSS {
			continue
		}
		kept = append(kept, f)
		if len(tbl.Rows) < limit {
			tbl.Rows = append(tbl.Rows, []string{f.CVE, f.Package, f.InstalledVersion, f.FixedVersion, f.Severity, fmt.Sprintf("%.1f", f.CVSSScore)})
		}
	}
	if len(kept) == 0 {
		return nil, map[string]any{"count": 0, "host": hostname, "scan": latest, "note": "no findings match that filter"}
	}
	return tbl, map[string]any{"host": hostname, "count": len(kept), "scan": latest, "findings": kept}
}

// ---------------------------------------------------------------------------
// list_users — accounts, roles, MFA, status (gated by User.Edit)
// ---------------------------------------------------------------------------

type listUsersArgs struct {
	UsernameContains string `json:"usernameContains"`
	Role             string `json:"role"`
	WithoutMFA       bool   `json:"withoutMfa"`
	DisabledOnly     bool   `json:"disabledOnly"`
	Limit            int    `json:"limit"`
}

// runListUsers answers account/role/MFA questions: "who are the admins", "what
// role does bob have", "any accounts without MFA", "who is disabled". Gated by
// User.Edit — the same permission that guards the Users admin page.
func (s *Service) runListUsers(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewUsers && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view user accounts"}
	}
	var a listUsersArgs
	_ = json.Unmarshal(raw, &a)
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		s.log.Warn("assistant list_users", "err", err)
		return nil, map[string]any{"error": "could not list users"}
	}
	nameSub := strings.ToLower(strings.TrimSpace(a.UsernameContains))
	roleFilter := strings.ToLower(strings.TrimSpace(a.Role))
	limit := a.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	type userRow struct {
		Username    string     `json:"username"`
		DisplayName string     `json:"displayName,omitempty"`
		Roles       []string   `json:"roles"`
		AuthSource  string     `json:"authSource"`
		MFAEnabled  bool       `json:"mfaEnabled"`
		Disabled    bool       `json:"disabled"`
		SuperAdmin  bool       `json:"superAdmin"`
		LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	}
	tbl := &AssistantTable{
		Title:   "Users",
		Columns: []TableColumn{{Label: "Username"}, {Label: "Roles"}, {Label: "Source"}, {Label: "MFA"}, {Label: "Disabled"}, {Label: "Last login", Kind: "time"}},
	}
	out := []userRow{}
	for _, u := range users {
		if nameSub != "" && !strings.Contains(strings.ToLower(u.Username), nameSub) && !strings.Contains(strings.ToLower(u.DisplayName), nameSub) {
			continue
		}
		if roleFilter != "" {
			has := false
			for _, r := range u.Roles {
				if strings.ToLower(r) == roleFilter {
					has = true
					break
				}
			}
			if !has {
				continue
			}
		}
		if a.DisabledOnly && !u.IsDisabled {
			continue
		}
		// MFA enrolled = has a confirmed factor. External (SSO) accounts authenticate
		// at the IdP, so Fleet MFA does not apply to them.
		mfa := false
		if u.AuthSource == "" || u.AuthSource == "local" {
			mfa, _ = s.store.HasConfirmedMFA(ctx, u.ID)
		}
		if a.WithoutMFA && (mfa || (u.AuthSource != "" && u.AuthSource != "local")) {
			continue
		}
		src := u.AuthSource
		if src == "" {
			src = "local"
		}
		out = append(out, userRow{
			Username: u.Username, DisplayName: u.DisplayName, Roles: u.Roles, AuthSource: src,
			MFAEnabled: mfa, Disabled: u.IsDisabled, SuperAdmin: u.IsSuperAdmin, LastLoginAt: u.LastLoginAt,
		})
		if len(tbl.Rows) < limit {
			mfaCell := yesNo(mfa)
			if u.AuthSource != "" && u.AuthSource != "local" {
				mfaCell = "IdP"
			}
			roleList := u.Roles
			if u.IsSuperAdmin {
				roleList = append([]string{"Super Administrator"}, roleList...)
			}
			tbl.Rows = append(tbl.Rows, []string{u.Username, strings.Join(roleList, ", "), src, mfaCell, yesNo(u.IsDisabled), tableTimePtr(u.LastLoginAt)})
		}
	}
	if len(out) == 0 {
		return nil, map[string]any{"count": 0, "users": []any{}, "note": "no user accounts match that filter"}
	}
	return tbl, map[string]any{"count": len(out), "users": out}
}

// ---------------------------------------------------------------------------
// list_approvals — pending access requests + active JIT grants
// ---------------------------------------------------------------------------

type listApprovalsArgs struct {
	Status string `json:"status"`
}

// runListApprovals answers "what is waiting for approval" and "who has elevated
// access right now". Gated by Approval.Request/Approval.Decide (whoever can see
// the approvals queue).
func (s *Service) runListApprovals(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewApprovals && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view approvals"}
	}
	var a listApprovalsArgs
	_ = json.Unmarshal(raw, &a)
	status := strings.ToLower(strings.TrimSpace(a.Status))
	if status == "" {
		status = "pending"
	}
	if status == "all" || status == "any" {
		status = ""
	}
	reqs, err := s.store.ListApprovalRequests(ctx, status, nil)
	if err != nil {
		s.log.Warn("assistant list_approvals", "err", err)
		return nil, map[string]any{"error": "could not list approval requests"}
	}
	grants, err := s.store.ActiveTemporaryPermissions(ctx)
	if err != nil {
		s.log.Warn("assistant list_approvals grants", "err", err)
		grants = nil // still return the requests
	}
	tbl := &AssistantTable{
		Title:   "Access approvals",
		Columns: []TableColumn{{Label: "Requested", Kind: "time"}, {Label: "Requester"}, {Label: "Target"}, {Label: "Status"}, {Label: "Reason"}},
	}
	for _, r := range reqs {
		tbl.Rows = append(tbl.Rows, []string{tableTime(r.CreatedAt), r.Requester, r.TargetName, r.Status, r.Reason})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"statusFilter": status, "requestCount": len(reqs), "requests": reqs,
		"activeGrantCount": len(grants), "activeGrants": grants,
	}
}

// ---------------------------------------------------------------------------
// windows_software — installed apps on a Windows (RDP) host, gated by host access
// ---------------------------------------------------------------------------

type windowsSoftwareArgs struct {
	Hostname string `json:"hostname"`
	Contains string `json:"contains"`
	Limit    int    `json:"limit"`
}

// runWindowsSoftware lists the software inventory collected from a Windows host's
// registry over WinRM. Access-scoped exactly like host_detail.
func (s *Service) runWindowsSoftware(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	var a windowsSoftwareArgs
	_ = json.Unmarshal(raw, &a)
	hostname := strings.TrimSpace(a.Hostname)
	if hostname == "" {
		return nil, map[string]any{"error": "hostname is required (Windows software inventory is per-host)"}
	}
	host, err := s.store.HostByHostname(ctx, hostname)
	if err != nil {
		return nil, map[string]any{"error": "no host named " + hostname}
	}
	if !who.IsSuperAdmin {
		ok, aerr := s.store.UserCanAccessHost(ctx, who.UserID, host.ID)
		if aerr != nil || !ok {
			return nil, map[string]any{"error": "you do not have access to that host"}
		}
	}
	if host.Protocol != "rdp" {
		return nil, map[string]any{"error": hostname + " is not a Windows/RDP host; for Linux packages use host_updates"}
	}
	sw, err := s.store.ListWindowsSoftware(ctx, host.ID)
	if err != nil {
		s.log.Warn("assistant windows_software", "err", err)
		return nil, map[string]any{"error": "could not read Windows software inventory"}
	}
	sub := strings.ToLower(strings.TrimSpace(a.Contains))
	limit := a.Limit
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	tbl := &AssistantTable{
		Title:   "Software on " + hostname,
		Columns: []TableColumn{{Label: "Name"}, {Label: "Version"}, {Label: "Publisher"}},
	}
	kept := make([]models.WindowsSoftware, 0, len(sw))
	for _, item := range sw {
		if sub != "" && !strings.Contains(strings.ToLower(item.Name), sub) {
			continue
		}
		kept = append(kept, item)
		if len(tbl.Rows) < limit {
			tbl.Rows = append(tbl.Rows, []string{item.Name, item.Version, item.Publisher})
		}
	}
	if len(kept) == 0 {
		return nil, map[string]any{"count": 0, "host": hostname, "note": "no Windows software inventory recorded for that host yet"}
	}
	return tbl, map[string]any{"host": hostname, "count": len(kept), "software": kept}
}

// ---------------------------------------------------------------------------
// platform_status — HA cluster roster + recent enrollment jobs
// ---------------------------------------------------------------------------

// runPlatformStatus reports control-plane health: the HA cluster instance roster
// with the current leader (System.Configure), and recent host-enrollment jobs
// (Host.Enroll). Each section is included only if the caller may see it.
func (s *Service) runPlatformStatus(ctx context.Context, who Caller) any {
	if !who.CanViewCluster && !who.CanViewEnrollment && !who.IsSuperAdmin {
		return map[string]any{"error": "you do not have permission to view platform status"}
	}
	res := map[string]any{}

	if who.CanViewCluster || who.IsSuperAdmin {
		instances, err := s.store.ListClusterInstances(ctx)
		if err != nil {
			s.log.Warn("assistant platform_status cluster", "err", err)
		} else {
			// An instance is "live" if it heartbeated within the lease window (30s);
			// stale rows are prior instances that stopped without unregistering.
			const lease = 30 * time.Second
			now := time.Now()
			type inst struct {
				Hostname      string    `json:"hostname"`
				Version       string    `json:"version"`
				IsLeader      bool      `json:"isLeader"`
				Live          bool      `json:"live"`
				StartedAt     time.Time `json:"startedAt"`
				LastHeartbeat time.Time `json:"lastHeartbeat"`
			}
			live, leaders := 0, 0
			list := make([]inst, 0, len(instances))
			for _, c := range instances {
				isLive := now.Sub(c.LastHeartbeat) <= lease
				if isLive {
					live++
					if c.IsLeader {
						leaders++
					}
				}
				list = append(list, inst{c.Hostname, c.Version, c.IsLeader, isLive, c.StartedAt, c.LastHeartbeat})
			}
			res["cluster"] = map[string]any{
				"liveInstances": live, "totalInstances": len(instances),
				"liveLeaders": leaders, "instances": list,
				"healthy": live >= 1 && leaders == 1,
			}
		}
	}

	if who.CanViewEnrollment || who.IsSuperAdmin {
		jobs, err := s.store.ListEnrollmentJobs(ctx, 20)
		if err != nil {
			s.log.Warn("assistant platform_status enrollment", "err", err)
		} else {
			sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
			type job struct {
				Target     string     `json:"target"`
				Status     string     `json:"status"`
				Error      string     `json:"error,omitempty"`
				CreatedAt  time.Time  `json:"createdAt"`
				FinishedAt *time.Time `json:"finishedAt,omitempty"`
			}
			list := make([]job, 0, len(jobs))
			for _, j := range jobs {
				list = append(list, job{j.Target, j.Status, j.Error, j.CreatedAt, j.FinishedAt})
			}
			res["enrollmentJobs"] = list
		}
	}
	if len(res) == 0 {
		return map[string]any{"note": "no platform status available"}
	}
	return res
}
