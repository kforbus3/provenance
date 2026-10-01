package store

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

func TestNetScanRoundTrip(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "net-" + uuid.NewString()[:8], Address: "10.9.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	run := uuid.New()
	lan, err := s.CreateNetScan(ctx, run, &h.ID, nil, "10.9.0.5", models.NetPathLAN, nil, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := s.CreateNetScan(ctx, run, &h.ID, nil, "10.100.0.9", models.NetPathOverlay, nil, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{lan, ov} {
		if err := s.StartNetScan(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	listeners := []models.NetListener{{Proto: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx",
		Package: "nginx", LibPackages: []string{"libssl3"}, Exposed: true}}
	if err := s.CompleteNetScan(ctx, lan, NetScanResult{
		Status: models.NetScanCompleted, OpenPorts: 2, Listeners: listeners, TemplatesVersion: "v10.4.9",
		Services: []models.NetService{
			{Port: 443, Proto: "tcp", Service: "http", TLS: true, Process: "nginx",
				Detections: []models.NetDetection{{TemplateID: "nginx-version", Name: "nginx"}}},
			{Port: 8443, Proto: "tcp", Unexpected: true},
		},
		Findings: []models.NetFinding{
			{TemplateID: "deprecated-tls", Name: "Deprecated TLS", Severity: "medium", Port: 443, Proto: "tcp"},
			{TemplateID: "exposed-redis", Name: "Redis", Severity: "high", Port: 8443, Proto: "tcp",
				CVEs: []string{"CVE-2025-49844"}, References: []string{"https://example.invalid"}},
		},
		Warnings: []string{"w1"},
	}); err != nil {
		t.Fatal(err)
	}
	// The overlay did not answer. That is recorded as unreachable -- never as a
	// completed scan with nothing on it.
	if err := s.CompleteNetScan(ctx, ov, NetScanResult{Status: models.NetScanUnreachable,
		Reason: "no response on any port"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetNetScan(ctx, lan)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.NetScanCompleted || got.High != 1 || got.Medium != 1 || got.Total != 2 ||
		got.Unexpected != 1 || !got.ListenersKnown || len(got.Listeners) != 1 {
		t.Fatalf("scan = %+v", got)
	}
	if got.Listeners[0].LibPackages[0] != "libssl3" {
		t.Fatalf("listener packages lost: %+v", got.Listeners[0])
	}
	if got.Findings[0].Severity != "high" || got.Findings[0].CVEs[0] != "CVE-2025-49844" {
		t.Fatalf("findings not worst-first or CVEs lost: %+v", got.Findings)
	}
	if len(got.Services) != 2 || got.Services[0].Detections[0].TemplateID != "nginx-version" {
		t.Fatalf("services = %+v", got.Services)
	}

	ovScan, err := s.GetNetScan(ctx, ov)
	if err != nil {
		t.Fatal(err)
	}
	if ovScan.Status != models.NetScanUnreachable || ovScan.ListenersKnown {
		t.Fatalf("overlay = %+v (an uncollected listener list must stay unknown, not empty)", ovScan)
	}

	perHost, err := s.LatestNetScansForHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(perHost) != 2 {
		t.Fatalf("want one scan per path, got %d", len(perHost))
	}

	exposed, err := s.ExposedServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []ExposedService
	for _, e := range exposed {
		if e.HostID != nil && *e.HostID == h.ID {
			mine = append(mine, e)
		}
	}
	if len(mine) != 2 || mine[1].WorstSeverity != "high" || !mine[1].Unexpected {
		t.Fatalf("exposed = %+v", mine)
	}

	// The audit export lists every finding AND the address nobody could assess.
	tbl, err := s.ExportNetScanFindings(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var lanRows, darkRows int
	for _, r := range tbl.Rows {
		if r[0] != h.Hostname {
			continue
		}
		switch r[3] {
		case models.NetScanCompleted:
			lanRows++
		case models.NetScanUnreachable:
			darkRows++
			if r[12] == "" {
				t.Errorf("unreachable row has no reason: %v", r)
			}
		}
	}
	if lanRows != 2 || darkRows != 1 {
		t.Fatalf("export rows: %d findings, %d unreachable (want 2, 1)", lanRows, darkRows)
	}

	// The first scan of a path has nothing to compare with; the next one does.
	if _, ok, err := s.PreviousNetPorts(ctx, lan); err != nil || ok {
		t.Fatalf("first scan has a predecessor? ok=%v err=%v", ok, err)
	}
	next, _ := s.CreateNetScan(ctx, uuid.New(), &h.ID, nil, "10.9.0.5", models.NetPathLAN, nil, "test", false)
	prev, ok, err := s.PreviousNetPorts(ctx, next)
	if err != nil || !ok || !prev["tcp/443"] || !prev["tcp/8443"] {
		t.Fatalf("previous ports = %v ok=%v err=%v", prev, ok, err)
	}
}

// A scan deleted while it ran (the host removed, failures cleared) must not have
// its result reported as stored.
func TestNetScanWriteToVanishedScanIsAnError(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	gone := uuid.New()
	if err := s.CompleteNetScan(ctx, gone, NetScanResult{Status: models.NetScanCompleted}); !errors.Is(err, ErrNetScanGone) {
		t.Fatalf("complete on a missing scan returned %v", err)
	}
	if err := s.FailNetScan(ctx, gone, "x"); !errors.Is(err, ErrNetScanGone) {
		t.Fatalf("fail on a missing scan returned %v", err)
	}
	if err := s.StartNetScan(ctx, gone); !errors.Is(err, ErrNetScanGone) {
		t.Fatalf("start on a missing scan returned %v", err)
	}
}

func TestNetScanRangesAndRangeScans(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	name := "lab-" + uuid.NewString()[:8]
	// A /24 of its own per run, so reruns against the same database do not collide.
	third := int(uuid.New()[0])
	r, err := s.CreateNetScanRange(ctx, name, fmt.Sprintf("10.77.%d.0/24", third), "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.LastScan != nil || r.LastLive != 0 {
		t.Fatalf("new range = %+v", r)
	}
	run := uuid.New()
	for _, a := range []string{fmt.Sprintf("10.77.%d.1", third), fmt.Sprintf("10.77.%d.9", third)} {
		id, err := s.CreateNetScan(ctx, run, nil, &r.ID, a, models.NetPathRange, nil, "test", true)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteNetScan(ctx, id, NetScanResult{Status: models.NetScanCompleted}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetNetScanRange(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastScan == nil || got.LastLive != 2 {
		t.Fatalf("range after scan = %+v", got)
	}
	if _, err := s.UpdateNetScanRange(ctx, uuid.New(), "x", "10.0.0.0/24", "", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing range returned %v", err)
	}
	scans, err := s.ListNetScans(ctx, nil, &r.ID, 10)
	if err != nil || len(scans) != 2 || scans[0].RangeName != name {
		t.Fatalf("range scans = %+v err=%v", scans, err)
	}
	if err := s.DeleteNetScanRange(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	// Deleting the range keeps what it found, detached.
	scans, err = s.ListNetScans(ctx, nil, nil, 500)
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, sc := range scans {
		if sc.RunID == run {
			kept++
			if sc.RangeID != nil {
				t.Fatal("scan still points at a deleted range")
			}
		}
	}
	if kept != 2 {
		t.Fatalf("range scans kept = %d", kept)
	}
}

func TestLatestVulnCVEsForHost(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	h, err := s.CreateHost(ctx, HostInput{Hostname: "cve-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LatestVulnCVEsForHost(ctx, h.ID); err != nil || ok {
		t.Fatalf("no package scan yet: ok=%v err=%v", ok, err)
	}
	id, _ := s.CreateVulnScan(ctx, h.ID, nil, "test", false)
	if err := s.CompleteVulnScan(ctx, id, VulnSummary{Total: 1},
		[]models.VulnFinding{{CVE: "cve-2025-49844", Package: "redis-server"}}, nil); err != nil {
		t.Fatal(err)
	}
	cves, ok, err := s.LatestVulnCVEsForHost(ctx, h.ID)
	if err != nil || !ok || !cves["CVE-2025-49844"] {
		t.Fatalf("cves = %v ok=%v err=%v", cves, ok, err)
	}
}
