package store

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// "Which hosts are vulnerable to CVE-X" must find the CVE wherever Provenance
// records it -- a host package, a GHSA-keyed finding that names it only as an
// alias, a running container image, a network check -- must ignore a host whose
// LATEST scan no longer has it, and must keep a never-scanned host visible as
// unscanned rather than as clean.
func TestCVEExposureFindsEveryKindOfMatchAndOnlyTheLatestScan(t *testing.T) {
	s, pool, ctx := scheduleTestStore(t)
	sfx := uuid.NewString()[:8]
	cve := "CVE-2099-" + sfx[:4] + "1" // unique per run; the test DB is shared
	host := func(name string) uuid.UUID {
		h, err := s.CreateHost(ctx, HostInput{Hostname: name + "-" + sfx})
		if err != nil {
			t.Fatalf("create host: %v", err)
		}
		return h.ID
	}
	scan := func(hostID uuid.UUID, findings ...models.VulnFinding) uuid.UUID {
		id, err := s.CreateVulnScan(ctx, hostID, nil, "test", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteVulnScan(ctx, id, VulnSummary{Total: len(findings)}, findings, nil); err != nil {
			t.Fatal(err)
		}
		return id
	}

	pkgHost, aliasHost, patched, never, ctrHost, netHost :=
		host("pkg"), host("alias"), host("patched"), host("never"), host("ctr"), host("net")

	// Lower-case on purpose: the lookup is case-insensitive.
	scan(pkgHost, models.VulnFinding{CVE: "cve-2099-" + sfx[:4] + "1", Package: "openssh-server", InstalledVersion: "1:9.2p1-2", FixedVersion: "1:9.2p1-3", Severity: "High"})
	scan(aliasHost, models.VulnFinding{CVE: "GHSA-aaaa-bbbb-cccc", Aliases: []string{cve}, Package: "stdlib", InstalledVersion: "go1.22.1", Severity: "Medium"})
	old := scan(patched, models.VulnFinding{CVE: cve, Package: "openssh-server", InstalledVersion: "1:9.2p1-2"})
	if _, err := pool.Exec(ctx, `UPDATE vuln_scans SET created_at = now() - interval '1 day' WHERE id=$1`, old); err != nil {
		t.Fatal(err)
	}
	scan(patched, models.VulnFinding{CVE: "CVE-2000-0001", Package: "bash"}) // latest: patched
	scan(netHost)                                                            // scanned, clean packages

	// A running container whose image scan carries the CVE.
	digest := "sha256:" + uuid.NewString()
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{Digest: digest, Image: "gitea/gitea@" + digest,
		Findings: []models.VulnFinding{{CVE: cve, Package: "openssh", InstalledVersion: "9.6_p1-r0", Severity: "High"}}}); err != nil {
		t.Fatal(err)
	}
	ctrs, _ := json.Marshal([]map[string]string{{"name": "gitea", "image": "gitea/gitea:1.21", "repository": "gitea/gitea", "digest": digest}})
	if _, err := pool.Exec(ctx, `INSERT INTO host_inventory (host_id, containers) VALUES ($1, $2)
		ON CONFLICT (host_id) DO UPDATE SET containers = EXCLUDED.containers`, ctrHost, ctrs); err != nil {
		t.Fatal(err)
	}

	// A network check naming the CVE.
	var nsID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO net_scans (run_id, host_id, target, path, status, finished_at)
		VALUES (gen_random_uuid(), $1, '192.0.2.10', 'lan', 'completed', now()) RETURNING id`, netHost).Scan(&nsID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO net_findings (scan_id, template_id, name, severity, port, cves)
		VALUES ($1, 'openssh-regresshion', 'OpenSSH regreSSHion', 'high', 22, $2)`, nsID, []string{cve}); err != nil {
		t.Fatal(err)
	}

	exp, err := s.CVEExposureForAssistant(ctx, uuid.Nil, true, []string{cve})
	if err != nil {
		t.Fatalf("CVEExposureForAssistant: %v", err)
	}
	got := map[string]string{}
	for _, m := range exp.Hosts {
		got[m.Hostname] = "pkg:" + m.ID
	}
	for _, m := range exp.Containers {
		got[m.Hostname] = "ctr:" + m.Container
	}
	for _, m := range exp.Network {
		got[m.Hostname] = "net:" + m.Name
	}
	want := map[string]string{
		"pkg-" + sfx:   "pkg:cve-2099-" + sfx[:4] + "1",
		"alias-" + sfx: "pkg:GHSA-aaaa-bbbb-cccc",
		"ctr-" + sfx:   "ctr:gitea",
		"net-" + sfx:   "net:OpenSSH regreSSHion",
	}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s: got %q, want %q", h, got[h], w)
		}
	}
	if _, ok := got["patched-"+sfx]; ok {
		t.Errorf("a host whose LATEST scan no longer has the CVE was reported affected")
	}
	if len(got) != len(want) {
		t.Errorf("unexpected matches: %v", got)
	}
	unscanned := map[string]bool{}
	for _, u := range exp.Unscanned {
		unscanned[u] = true
	}
	if !unscanned["never-"+sfx] || !unscanned["ctr-"+sfx] {
		t.Errorf("never-scanned hosts not reported as unscanned: %v", exp.Unscanned)
	}
	if unscanned["pkg-"+sfx] {
		t.Errorf("a scanned host was reported as unscanned")
	}
	if exp.Scanned+len(exp.Unscanned) != exp.AccessibleHosts {
		t.Errorf("coverage does not add up: %d scanned + %d unscanned != %d", exp.Scanned, len(exp.Unscanned), exp.AccessibleHosts)
	}

	// Aliases round-trip through the findings read the UI and Ask use.
	scans, err := s.ListVulnScans(ctx, &aliasHost, 1)
	if err != nil || len(scans) != 1 {
		t.Fatalf("list scans: %v %v", scans, err)
	}
	fs, err := s.GetVulnFindings(ctx, scans[0].ID)
	if err != nil || len(fs) != 1 || len(fs[0].Aliases) != 1 || fs[0].Aliases[0] != cve {
		t.Fatalf("aliases did not round-trip: %+v err=%v", fs, err)
	}
	_ = never
}
