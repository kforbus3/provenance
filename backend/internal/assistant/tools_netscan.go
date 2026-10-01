package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/netscan"
)

type netExposureArgs struct {
	Hostname string `json:"hostname"`
}

// runNetworkExposure answers "what is exposed on <host>" / "what does the fleet
// expose". Unreachable scans are reported as not assessed, never as clean.
func (s *Service) runNetworkExposure(ctx context.Context, raw json.RawMessage, who Caller) (*AssistantTable, any) {
	if !who.CanViewScans && !who.IsSuperAdmin {
		return nil, map[string]any{"error": "you do not have permission to view network scans"}
	}
	var a netExposureArgs
	_ = json.Unmarshal(raw, &a)
	hostname := strings.TrimSpace(a.Hostname)

	if hostname == "" {
		scans, err := s.store.LatestNetScansForAssistant(ctx, who.UserID, who.IsSuperAdmin)
		if err != nil {
			s.log.Warn("assistant network exposure rollup", "err", err)
			return nil, map[string]any{"error": "could not read network scans"}
		}
		if len(scans) == 0 {
			return nil, map[string]any{"count": 0, "note": "no network scans on any accessible host"}
		}
		tbl := &AssistantTable{
			Title: "Network exposure",
			Columns: []TableColumn{{Label: "Host / address"}, {Label: "Path"}, {Label: "Status"},
				{Label: "Open ports"}, {Label: "Critical"}, {Label: "High"}, {Label: "Medium"},
				{Label: "Unexpected"}, {Label: "Scanned", Kind: "time"}},
		}
		unreachable := 0
		for _, v := range scans {
			name := v.Hostname
			if name == "" {
				name = v.Target
			}
			status := v.Status
			if v.Status == models.NetScanUnreachable {
				unreachable++
				status = "not assessed (unreachable)"
			}
			tbl.Rows = append(tbl.Rows, []string{name, v.Path, status, fmt.Sprint(v.OpenPorts),
				fmt.Sprint(v.Critical), fmt.Sprint(v.High), fmt.Sprint(v.Medium), fmt.Sprint(v.Unexpected),
				tableTimePtr(v.FinishedAt)})
		}
		return tbl, map[string]any{"count": len(scans), "scans": scans, "unreachable": unreachable,
			"note": "One row per host (scanned on its overlay address, or its LAN address when it has none) " +
				"and per range address. An unreachable row was NOT assessed and says nothing about what that " +
				"address exposes. 'Unexpected' ports answered but are not bound on the host."}
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
	scans, err := s.store.LatestNetScansForHost(ctx, host.ID)
	if err != nil {
		s.log.Warn("assistant network exposure host", "err", err)
		return nil, map[string]any{"error": "could not read network scans"}
	}
	if len(scans) == 0 {
		return nil, map[string]any{"count": 0, "note": "no network scan of " + hostname + " yet"}
	}
	netscan.CorroborateHostScans(ctx, s.store, host.ID, scans)
	tbl := &AssistantTable{
		Title: "Network exposure: " + hostname,
		Columns: []TableColumn{{Label: "Path"}, {Label: "Port"}, {Label: "Service"}, {Label: "Process"},
			{Label: "Finding"}, {Label: "Severity"}, {Label: "CVE"}},
	}
	for _, sc := range scans {
		if sc.Status != models.NetScanCompleted {
			tbl.Rows = append(tbl.Rows, []string{sc.Path, "", "", "", "not assessed: " + sc.Reason + sc.Error, "", ""})
			continue
		}
		byPort := map[string][]models.NetFinding{}
		for _, f := range sc.Findings {
			k := fmt.Sprintf("%d/%s", f.Port, f.Proto)
			byPort[k] = append(byPort[k], f)
		}
		for _, sv := range sc.Services {
			k := fmt.Sprintf("%d/%s", sv.Port, sv.Proto)
			proc := sv.Process
			if sv.Unexpected {
				proc = "UNEXPECTED (not bound on the host)"
			}
			fs := byPort[k]
			if len(fs) == 0 {
				tbl.Rows = append(tbl.Rows, []string{sc.Path, k, sv.Service, proc, "", "", ""})
				continue
			}
			for _, f := range fs {
				cve := strings.Join(f.CVEs, " ")
				if f.Corroboration != "" {
					cve += " (" + f.Corroboration + ")"
				}
				tbl.Rows = append(tbl.Rows, []string{sc.Path, k, sv.Service, proc, f.Name, f.Severity, cve})
			}
		}
	}
	return tbl, map[string]any{"count": len(scans), "scans": scans,
		"note": "'confirmed' CVEs are also reported by the host's package scan; 'banner-only' ones are " +
			"matched from a version banner the package scan contradicts and are most likely false positives."}
}
