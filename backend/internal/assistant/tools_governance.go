package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Governance coverage: the Moorgate admin surfaces that had no assistant
// tool at all — groups, roles, service accounts, access reviews, and the
// credential/certificate lifecycle. An operator looking at those pages asks the
// assistant about them ("who can reach nas", "what expires this month"), and the
// honest-but-useless "I have no tool for that" was the whole complaint.
//
// These are deliberately TWO tools with a topic enum rather than eight tools. The
// system prompt plus tool schemas already cost ~9k tokens per request, and the
// context window is the scarce resource here (see numCtx) — a topic enum keeps each
// surface discoverable to the model at a fraction of the schema cost, and the enum
// values double as the catalogue of what exists.

// ---------------------------------------------------------------------------
// access_control — groups, roles, service accounts, access reviews
// ---------------------------------------------------------------------------

type accessControlArgs struct {
	Topic string `json:"topic"`
	Name  string `json:"name"`
}

// runAccessControl answers "who/what is allowed" questions. Each topic carries its
// own permission gate, mirroring the page that shows the same data, and an
// unpermitted topic reports that plainly rather than returning an empty list that
// reads as "there are none".
func (s *Service) runAccessControl(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	var a accessControlArgs
	_ = json.Unmarshal(raw, &a)
	name := strings.TrimSpace(a.Name)
	switch strings.ToLower(strings.TrimSpace(a.Topic)) {
	case "groups", "group":
		return s.accessGroups(ctx, name, who)
	case "roles", "role", "permissions":
		return s.accessRoles(ctx, name, who)
	case "service_accounts", "service accounts", "api_tokens", "tokens":
		return s.accessServiceAccounts(ctx, who)
	case "access_reviews", "access review", "reviews", "certification":
		return s.accessReviews(ctx, who)
	default:
		return nil, map[string]any{
			"error": "unknown topic",
			"validTopics": []string{
				"groups", "roles", "service_accounts", "access_reviews",
			},
		}
	}
}

func (s *Service) accessGroups(ctx context.Context, name string, who Caller) (*AssistantTable, any) {
	if !who.Can("Group.Edit") && !who.Can("Host.View") {
		return nil, map[string]any{"error": "you do not have permission to view groups"}
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		s.log.Warn("assistant access_control groups", "err", err)
		return nil, map[string]any{"error": "could not list groups"}
	}
	counts, err := s.store.GroupHostCounts(ctx)
	if err != nil {
		counts = nil // the roster is still worth returning without the counts
	}
	// Named group -> its host membership, which is what "what is in <group>" means.
	if name != "" {
		for _, g := range groups {
			if !strings.EqualFold(g.Name, name) {
				continue
			}
			hosts, herr := s.store.HostsInGroup(ctx, g.ID)
			if herr != nil {
				return nil, map[string]any{"error": "could not list the hosts in " + g.Name}
			}
			tbl := &AssistantTable{
				Title:   "Hosts in " + g.Name,
				Columns: []TableColumn{{Label: "Host"}, {Label: "Address"}, {Label: "Environment"}},
			}
			names := make([]string, 0, len(hosts))
			for _, h := range hosts {
				tbl.Rows = append(tbl.Rows, []string{h.Hostname, h.Address, h.Environment})
				names = append(names, h.Hostname)
			}
			if len(tbl.Rows) == 0 {
				tbl = nil
			}
			return tbl, map[string]any{
				"topic": "groups", "group": g.Name, "description": g.Description,
				"hostCount": len(hosts), "hosts": names,
			}
		}
		return nil, map[string]any{"topic": "groups", "error": "no group named " + name}
	}
	tbl := &AssistantTable{
		Title:   "Groups",
		Columns: []TableColumn{{Label: "Group"}, {Label: "Hosts"}, {Label: "Description"}},
	}
	type row struct {
		Name        string `json:"name"`
		HostCount   int    `json:"hostCount"`
		Description string `json:"description,omitempty"`
	}
	out := make([]row, 0, len(groups))
	for _, g := range groups {
		n := counts[g.ID]
		out = append(out, row{g.Name, n, g.Description})
		tbl.Rows = append(tbl.Rows, []string{g.Name, strconv.Itoa(n), g.Description})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"topic": "groups", "count": len(out), "groups": out}
}

func (s *Service) accessRoles(ctx context.Context, name string, who Caller) (*AssistantTable, any) {
	if !who.Can("Role.Edit") && !who.Can("User.Edit") {
		return nil, map[string]any{"error": "you do not have permission to view roles"}
	}
	roles, err := s.store.ListRoles(ctx)
	if err != nil {
		s.log.Warn("assistant access_control roles", "err", err)
		return nil, map[string]any{"error": "could not list roles"}
	}
	tbl := &AssistantTable{
		Title:   "Roles",
		Columns: []TableColumn{{Label: "Role"}, {Label: "Permissions"}, {Label: "Description"}},
	}
	type row struct {
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
	}
	out := make([]row, 0, len(roles))
	for _, r := range roles {
		if name != "" && !strings.EqualFold(r.Name, name) {
			continue
		}
		perms := append([]string(nil), r.Permissions...)
		sort.Strings(perms)
		out = append(out, row{r.Name, r.Description, perms})
		// The full permission list only earns its space when one role was asked about;
		// otherwise the count keeps the roster readable.
		cell := strconv.Itoa(len(perms))
		if name != "" {
			cell = strings.Join(perms, ", ")
		}
		tbl.Rows = append(tbl.Rows, []string{r.Name, cell, r.Description})
	}
	if len(tbl.Rows) == 0 {
		if name != "" {
			return nil, map[string]any{"topic": "roles", "error": "no role named " + name}
		}
		tbl = nil
	}
	return tbl, map[string]any{"topic": "roles", "count": len(out), "roles": out}
}

func (s *Service) accessServiceAccounts(ctx context.Context, who Caller) (*AssistantTable, any) {
	if !who.Can("ServiceAccount.Manage") {
		return nil, map[string]any{"error": "you do not have permission to view service accounts"}
	}
	accounts, err := s.store.ListServiceAccounts(ctx)
	if err != nil {
		s.log.Warn("assistant access_control service_accounts", "err", err)
		return nil, map[string]any{"error": "could not list service accounts"}
	}
	tbl := &AssistantTable{
		Title: "Service accounts",
		Columns: []TableColumn{
			{Label: "Account"}, {Label: "Display name"}, {Label: "Disabled"},
			{Label: "API tokens"}, {Label: "Created", Kind: "time"},
		},
	}
	type row struct {
		Username               string     `json:"username"`
		DisplayName            string     `json:"displayName,omitempty"`
		Disabled               bool       `json:"disabled"`
		TokenCount             int        `json:"tokenCount"`
		ExpiredOrRevokedTokens int        `json:"inactiveTokenCount"`
		CreatedAt              time.Time  `json:"createdAt"`
		LastTokenUse           *time.Time `json:"lastTokenUse,omitempty"`
	}
	out := make([]row, 0, len(accounts))
	for _, sa := range accounts {
		r := row{Username: sa.Username, DisplayName: sa.DisplayName, Disabled: sa.IsDisabled, CreatedAt: sa.CreatedAt}
		tokens, terr := s.store.ListAPITokens(ctx, sa.ID)
		if terr == nil {
			for _, t := range tokens {
				if t.RevokedAt != nil || (t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now())) {
					r.ExpiredOrRevokedTokens++
					continue
				}
				r.TokenCount++
				if t.LastUsedAt != nil && (r.LastTokenUse == nil || t.LastUsedAt.After(*r.LastTokenUse)) {
					r.LastTokenUse = t.LastUsedAt
				}
			}
		}
		out = append(out, r)
		disabled := ""
		if sa.IsDisabled {
			disabled = "disabled"
		}
		tbl.Rows = append(tbl.Rows, []string{
			sa.Username, sa.DisplayName, disabled, strconv.Itoa(r.TokenCount), tableTime(sa.CreatedAt),
		})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{"topic": "service_accounts", "count": len(out), "serviceAccounts": out}
}

func (s *Service) accessReviews(ctx context.Context, who Caller) (*AssistantTable, any) {
	if !who.Can("AccessReview.Manage") {
		return nil, map[string]any{"error": "you do not have permission to view access reviews"}
	}
	reviews, err := s.store.ListAccessReviews(ctx)
	if err != nil {
		s.log.Warn("assistant access_control access_reviews", "err", err)
		return nil, map[string]any{"error": "could not list access reviews"}
	}
	tbl := &AssistantTable{
		Title: "Access reviews",
		Columns: []TableColumn{
			{Label: "Review"}, {Label: "Status"}, {Label: "Pending"}, {Label: "Kept"},
			{Label: "Revoked"}, {Label: "Due", Kind: "time"},
		},
	}
	open := 0
	for _, r := range reviews {
		if r.Status != "completed" {
			open++
		}
		tbl.Rows = append(tbl.Rows, []string{
			r.Name, r.Status, strconv.Itoa(r.Pending), strconv.Itoa(r.Kept),
			strconv.Itoa(r.Revoked), tableTimePtr(r.DueAt),
		})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"topic": "access_reviews", "count": len(reviews), "openCount": open, "reviews": reviews,
	}
}

// ---------------------------------------------------------------------------
// expiring_credentials — certificate + token + password + CA lifecycle
// ---------------------------------------------------------------------------

type expiringArgs struct {
	Days int `json:"days"`
}

// runExpiringCredentials answers "what is about to expire" across SSH certificates,
// API tokens, vault credentials, user passwords and the CA keys — the Lifecycle and
// Certificates pages. Everything here is metadata; no secret or key material is read.
func (s *Service) runExpiringCredentials(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.Can("System.Configure") && !who.Can("Certificate.Manage") {
		return nil, map[string]any{"error": "you do not have permission to view credential lifecycle data"}
	}
	var a expiringArgs
	_ = json.Unmarshal(raw, &a)
	days := a.Days
	if days <= 0 || days > 365 {
		days = 30
	}
	now := time.Now()

	tbl := &AssistantTable{
		Title: "Expiring / ageing credentials",
		Columns: []TableColumn{
			{Label: "Kind"}, {Label: "Name"}, {Label: "Owner"}, {Label: "Status"}, {Label: "Due", Kind: "time"},
		},
	}
	type item struct {
		Kind    string     `json:"kind"`
		Name    string     `json:"name"`
		Owner   string     `json:"owner,omitempty"`
		Status  string     `json:"status"`
		DueAt   *time.Time `json:"dueAt,omitempty"`
		AgeDays int        `json:"ageDays,omitempty"`
	}
	items := []item{}

	// API tokens, vault credentials, passwords, CA keys — already thresholded by the
	// same report the Lifecycle page renders, so the assistant and the UI agree.
	if lifecycle, err := s.store.LifecycleReport(ctx, now); err == nil {
		for _, l := range lifecycle {
			items = append(items, item{l.Kind, l.Name, l.Owner, l.Status, l.DueAt, l.AgeDays})
		}
	} else {
		s.log.Warn("assistant expiring_credentials lifecycle", "err", err)
	}

	// SSH certificates expiring inside the window. Fleet's session certificates are
	// short-lived by design, so a bare "expiring certificate" count would be pure
	// noise — only ones still valid now are reported, and the note says why.
	if certs, err := s.store.ExpiringCertificates(ctx, now.Add(time.Duration(days)*24*time.Hour)); err == nil {
		for _, c := range certs {
			if c.ExpiresAt.Before(now) || c.RevokedAt != nil {
				continue
			}
			exp := c.ExpiresAt
			items = append(items, item{
				Kind: "ssh_certificate", Name: c.KeyID, Owner: strings.Join(c.Principals, ","),
				Status: "expiring", DueAt: &exp,
			})
		}
	} else {
		s.log.Warn("assistant expiring_credentials certs", "err", err)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt == nil || items[j].DueAt == nil {
			return items[j].DueAt == nil && items[i].DueAt != nil
		}
		return items[i].DueAt.Before(*items[j].DueAt)
	})
	expired := 0
	for _, it := range items {
		if it.Status == "expired" {
			expired++
		}
		tbl.Rows = append(tbl.Rows, []string{it.Kind, it.Name, it.Owner, it.Status, tableTimePtr(it.DueAt)})
	}
	if len(tbl.Rows) == 0 {
		tbl = nil
	}
	return tbl, map[string]any{
		"windowDays": days, "count": len(items), "expiredCount": expired, "items": items,
		"note": "kinds are api_token, credential (vault secret), password, ca_key and ssh_certificate; " +
			"statuses are expired, expiring, stale (unused) or aging (overdue for rotation). " +
			"An empty list means nothing needs attention in this window.",
	}
}

// expiringDirectAnswer states the expiry picture in code — a count plus the soonest
// items. Left to the model, a "what expires soon" answer reliably loses rows.
func expiringDirectAnswer(payload any) string {
	m, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	if _, bad := m["error"]; bad {
		return ""
	}
	count, _ := m["count"].(int)
	days, _ := m["windowDays"].(int)
	if count == 0 {
		return fmt.Sprintf("Nothing is expired or expiring in the next %d days — no API tokens, vault credentials, passwords, CA keys or SSH certificates need attention.", days)
	}
	return ""
}
