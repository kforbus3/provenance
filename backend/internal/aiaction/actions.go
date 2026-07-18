package aiaction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// ---- scan.vulnerability ----------------------------------------------------

type vulnScanArgs struct {
	Hostname string `json:"hostname"`
	Group    string `json:"group"`
}

type vulnScanResolved struct {
	HostIDs []uuid.UUID `json:"hostIds"`
	Names   []string    `json:"names"`
	Label   string      `json:"label"`
}

// vulnScanAction proposes a CVE vulnerability scan of a host or a group. Safe: it
// only produces a report, never changes the host.
func vulnScanAction() ActionDef {
	return ActionDef{
		Kind: KindVulnScan, Permission: "Host.Scan", Risk: RiskSafe,
		Prepare: func(ctx context.Context, r *Registry, actor Actor, raw json.RawMessage) (json.RawMessage, string, error) {
			var a vulnScanArgs
			_ = json.Unmarshal(raw, &a)

			var hosts []models.Host
			label := ""
			switch {
			case strings.TrimSpace(a.Hostname) != "":
				h, err := r.store.HostByHostname(ctx, strings.TrimSpace(a.Hostname))
				if err != nil {
					return nil, "", fmt.Errorf("no host named %q", a.Hostname)
				}
				hosts, label = []models.Host{*h}, h.Hostname
			case strings.TrimSpace(a.Group) != "":
				g, err := r.groupByName(ctx, strings.TrimSpace(a.Group))
				if err != nil {
					return nil, "", fmt.Errorf("no group named %q", a.Group)
				}
				members, err := r.store.HostsInGroup(ctx, g.ID)
				if err != nil {
					return nil, "", errors.New("could not resolve the group's hosts")
				}
				hosts, label = members, "group "+g.Name
			default:
				return nil, "", errors.New("a hostname or group is required")
			}

			var ids []uuid.UUID
			var names []string
			for _, h := range hosts {
				if !actor.IsSuper {
					if ok, _ := r.store.UserCanAccessHost(ctx, actor.UserID, h.ID); !ok {
						continue
					}
				}
				ids = append(ids, h.ID)
				names = append(names, h.Hostname)
			}
			if len(ids) == 0 {
				return nil, "", errors.New("you don't have access to any matching host")
			}
			resolved, _ := json.Marshal(vulnScanResolved{HostIDs: ids, Names: names, Label: label})
			preview := "Run a vulnerability (CVE) scan on " + describeTargets(label, names) + "."
			return resolved, preview, nil
		},
		Execute: func(ctx context.Context, r *Registry, actor Actor, params json.RawMessage) (string, error) {
			var p vulnScanResolved
			if err := json.Unmarshal(params, &p); err != nil {
				return "", err
			}
			started := 0
			for _, id := range p.HostIDs {
				if !actor.IsSuper {
					if ok, _ := r.store.UserCanAccessHost(ctx, actor.UserID, id); !ok {
						continue
					}
				}
				h, err := r.store.GetHost(ctx, id)
				if err != nil {
					continue
				}
				scanID, err := r.store.CreateVulnScan(ctx, id, &actor.UserID, actor.Username, false)
				if err != nil {
					continue
				}
				if r.runVulnScan != nil {
					r.runVulnScan(scanID, h)
				}
				started++
			}
			if started == 0 {
				return "", errors.New("no scans could be started")
			}
			return fmt.Sprintf("Started %d vulnerability scan(s) on %s.", started, p.Label), nil
		},
	}
}

// ---- host.tag --------------------------------------------------------------

type tagHostArgs struct {
	Hostname   string   `json:"hostname"`
	AddTags    []string `json:"addTags"`
	RemoveTags []string `json:"removeTags"`
}

type tagHostResolved struct {
	HostID     uuid.UUID `json:"hostId"`
	Hostname   string    `json:"hostname"`
	AddTags    []string  `json:"addTags"`
	RemoveTags []string  `json:"removeTags"`
}

// tagHostAction proposes adding/removing tags on a host. Safe and reversible.
func tagHostAction() ActionDef {
	return ActionDef{
		Kind: KindTagHost, Permission: "Host.Edit", Risk: RiskSafe,
		Prepare: func(ctx context.Context, r *Registry, actor Actor, raw json.RawMessage) (json.RawMessage, string, error) {
			var a tagHostArgs
			_ = json.Unmarshal(raw, &a)
			if strings.TrimSpace(a.Hostname) == "" {
				return nil, "", errors.New("a hostname is required")
			}
			add := cleanTags(a.AddTags)
			remove := cleanTags(a.RemoveTags)
			if len(add) == 0 && len(remove) == 0 {
				return nil, "", errors.New("specify at least one tag to add or remove")
			}
			h, err := r.store.HostByHostname(ctx, strings.TrimSpace(a.Hostname))
			if err != nil {
				return nil, "", fmt.Errorf("no host named %q", a.Hostname)
			}
			if !actor.IsSuper {
				if ok, _ := r.store.UserCanAccessHost(ctx, actor.UserID, h.ID); !ok {
					return nil, "", errors.New("you don't have access to that host")
				}
			}
			resolved, _ := json.Marshal(tagHostResolved{HostID: h.ID, Hostname: h.Hostname, AddTags: add, RemoveTags: remove})
			var parts []string
			if len(add) > 0 {
				parts = append(parts, "add "+strings.Join(add, ", "))
			}
			if len(remove) > 0 {
				parts = append(parts, "remove "+strings.Join(remove, ", "))
			}
			preview := fmt.Sprintf("Update tags on host %s: %s.", h.Hostname, strings.Join(parts, "; "))
			return resolved, preview, nil
		},
		Execute: func(ctx context.Context, r *Registry, actor Actor, params json.RawMessage) (string, error) {
			var p tagHostResolved
			if err := json.Unmarshal(params, &p); err != nil {
				return "", err
			}
			if !actor.IsSuper {
				if ok, _ := r.store.UserCanAccessHost(ctx, actor.UserID, p.HostID); !ok {
					return "", errors.New("you no longer have access to that host")
				}
			}
			h, err := r.store.GetHost(ctx, p.HostID)
			if err != nil {
				return "", errors.New("host not found")
			}
			// Recompute against the host's CURRENT tags so a concurrent change isn't
			// clobbered — apply the add/remove delta, not a stale snapshot.
			final := applyTags(h.Tags, p.AddTags, p.RemoveTags)
			if _, err := r.store.UpdateHost(ctx, h.ID, store.HostInput{
				Hostname: h.Hostname, Description: h.Description, Environment: h.Environment,
				Owner: h.Owner, Address: h.Address, WGAddress: h.WGAddress,
				SSHPort: h.SSHPort, SSHUser: h.SSHUser, Tags: final,
			}); err != nil {
				return "", errors.New("could not update the host")
			}
			return fmt.Sprintf("Updated tags on %s; now: %s.", h.Hostname, tagList(final)), nil
		},
	}
}

// ---- helpers ---------------------------------------------------------------

func (r *Registry) groupByName(ctx context.Context, name string) (*models.Group, error) {
	groups, err := r.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if strings.EqualFold(groups[i].Name, name) {
			return &groups[i], nil
		}
	}
	return nil, errors.New("not found")
}

func describeTargets(label string, names []string) string {
	if strings.HasPrefix(label, "group ") {
		return fmt.Sprintf("%d host(s) in %s (%s)", len(names), label, strings.Join(names, ", "))
	}
	return "host " + label
}

// cleanTags trims, lowercases, and de-duplicates a tag list, dropping empties.
func cleanTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// applyTags returns current with add merged in and remove taken out (order-stable).
func applyTags(current, add, remove []string) []string {
	rm := map[string]bool{}
	for _, t := range remove {
		rm[strings.ToLower(strings.TrimSpace(t))] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range current {
		k := strings.ToLower(strings.TrimSpace(t))
		if k == "" || rm[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, t)
	}
	for _, t := range add {
		k := strings.ToLower(strings.TrimSpace(t))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

func tagList(tags []string) string {
	if len(tags) == 0 {
		return "(none)"
	}
	return strings.Join(tags, ", ")
}
