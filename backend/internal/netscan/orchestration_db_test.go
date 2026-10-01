package netscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/db"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// fakeSidecar answers like the net-scanner, records what it was asked, and checks
// the token on every request it should.
type fakeSidecar struct {
	mu      sync.Mutex
	targets []string
	rates   map[string]int
	overlay string
	results map[string]any
	found   []string // what /discover reports
}

func (f *fakeSidecar) handler(t *testing.T, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "overlay": f.overlay, "templates": true})
			return
		}
		if r.Header.Get("X-Netscan-Token") != token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/scan":
			b, _ := io.ReadAll(r.Body)
			var req scanRequest
			_ = json.Unmarshal(b, &req)
			f.mu.Lock()
			f.targets = append(f.targets, req.Target)
			if f.rates == nil {
				f.rates = map[string]int{}
			}
			f.rates[req.Target] = req.NucleiRate
			res, ok := f.results[req.Target]
			f.mu.Unlock()
			if !ok {
				res = map[string]any{"target": req.Target, "reachable": false,
					"reason": "no response on any port"}
			}
			_ = json.NewEncoder(w).Encode(res)
		case "/discover":
			_ = json.NewEncoder(w).Encode(map[string]any{"addresses": f.found})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func testService(t *testing.T, sidecarURL, token string) (*Service, *store.Store, context.Context) {
	t.Helper()
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	cfg := &config.Config{NetScanURL: sidecarURL, NetScanToken: token, NetScanTimeout: time.Minute, NetScanHostRate: 300,
		WGJumpIP: "10.100.0.1", JumpHost: "jumphost:22"}
	svc := New(st, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil)
	svc.resolve = fakeResolve(map[string]string{"jumphost": "172.30.0.10"})
	return svc, st, ctx
}

// The whole path a scan takes: a host on the overlay is scanned at its overlay
// address only; a host with no overlay address at its LAN address; the jump host is
// skipped; results are stored with their status; the sidecar is asked with the token,
// the right addresses and the host rate.
func TestStartHostsEndToEnd(t *testing.T) {
	n := int(uuid.New()[0])
	lanIP, ovIP, plainIP := fmt.Sprintf("10.88.%d.5", n), fmt.Sprintf("10.100.%d.77", n), fmt.Sprintf("10.88.%d.6", n)
	fs := &fakeSidecar{overlay: "ok", results: map[string]any{
		ovIP: map[string]any{
			"target": ovIP, "reachable": true, "openPorts": []int{443},
			"services": []map[string]any{{"port": 443, "proto": "tcp", "service": "http", "tls": true}},
			"findings": []map[string]any{{"templateId": "deprecated-tls", "name": "Deprecated TLS",
				"severity": "medium", "port": 443, "proto": "tcp"}},
			"templates": map[string]any{"version": "v10.4.9"},
		},
	}}
	srv := httptest.NewServer(fs.handler(t, "tok"))
	defer srv.Close()
	svc, st, ctx := testService(t, srv.URL, "tok")

	web, err := st.CreateHost(ctx, store.HostInput{Hostname: "web-" + uuid.NewString()[:6],
		Address: lanIP, WGAddress: ovIP})
	if err != nil {
		t.Fatal(err)
	}
	web.Enrolled = true // on the overlay; listener collection has no gateway here and says so
	plain, err := st.CreateHost(ctx, store.HostInput{Hostname: "plain-" + uuid.NewString()[:6], Address: plainIP})
	if err != nil {
		t.Fatal(err)
	}
	jump := &models.Host{ID: uuid.New(), Hostname: "jumphost", Address: "172.30.0.10"}

	started, skipped, wait, err := svc.StartHosts(ctx, ctx, []*models.Host{web, plain, jump}, nil, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	wait()
	if len(skipped) != 1 || skipped[0].Hostname != "jumphost" {
		t.Fatalf("skipped = %+v", skipped)
	}
	if len(started) != 2 || len(started[0].ScanIDs) != 1 || len(started[1].ScanIDs) != 1 {
		t.Fatalf("started = %+v (want one scan per host)", started)
	}

	scans, err := st.LatestNetScansForHost(ctx, web.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].Path != models.NetPathOverlay {
		t.Fatalf("web scans = %+v", scans)
	}
	ov := scans[0]
	if ov.Status != models.NetScanCompleted || ov.Medium != 1 || ov.TemplatesVersion != "v10.4.9" {
		t.Fatalf("overlay = %+v", ov)
	}
	if ov.ListenersKnown || len(ov.Warnings) == 0 || !strings.Contains(ov.Warnings[0], "listener list") {
		t.Fatalf("listener warning missing: %+v", ov.Warnings)
	}

	ps, err := st.LatestNetScansForHost(ctx, plain.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing answers at plainIP in the fake: recorded unreachable, on the LAN path.
	if len(ps) != 1 || ps[0].Path != models.NetPathLAN || ps[0].Status != models.NetScanUnreachable {
		t.Fatalf("plain scans = %+v", ps)
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if strings.Contains(strings.Join(fs.targets, ","), lanIP) {
		t.Fatalf("the LAN address of an overlay host was scanned: %v", fs.targets)
	}
	// The enrolled host is a server: the host rate. The unenrolled one is network
	// gear as far as anyone knows: the sidecar's gentle default (0 = not asked).
	if fs.rates[ovIP] != 300 || fs.rates[plainIP] != 0 {
		t.Fatalf("rates = %v: want 300 for the enrolled host, 0 (default) for the unenrolled one", fs.rates)
	}
}

// A host that was scanned on its LAN address before it joined the overlay must not
// keep showing that old LAN scan once it is scanned on the overlay.
func TestRollupShowsOnlyAHostsLatestPath(t *testing.T) {
	svc, st, ctx := testService(t, "http://unused", "tok")
	_ = svc
	h, err := st.CreateHost(ctx, store.HostInput{Hostname: "moved-" + uuid.NewString()[:6]})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := st.CreateNetScan(ctx, uuid.New(), &h.ID, nil, "10.0.2.9", models.NetPathLAN, nil, "t", false)
	if err := st.CompleteNetScan(ctx, old, store.NetScanResult{Status: models.NetScanCompleted}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	cur, _ := st.CreateNetScan(ctx, uuid.New(), &h.ID, nil, "10.100.0.9", models.NetPathOverlay, nil, "t", false)
	if err := st.CompleteNetScan(ctx, cur, store.NetScanResult{Status: models.NetScanCompleted}); err != nil {
		t.Fatal(err)
	}
	all, err := st.LatestNetScans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []models.NetScan
	for _, s := range all {
		if s.HostID != nil && *s.HostID == h.ID {
			mine = append(mine, s)
		}
	}
	if len(mine) != 1 || mine[0].ID != cur {
		t.Fatalf("roll-up for the host = %+v, want only the overlay scan", mine)
	}
	perHost, err := st.LatestNetScansForHost(ctx, h.ID)
	if err != nil || len(perHost) != 1 || perHost[0].ID != cur {
		t.Fatalf("host scans = %+v err=%v", perHost, err)
	}
}

// With a wrong token every scan fails with a message that names the cause.
func TestWrongTokenFailsWithACause(t *testing.T) {
	fs := &fakeSidecar{overlay: "not-configured"}
	srv := httptest.NewServer(fs.handler(t, "right"))
	defer srv.Close()
	svc, st, ctx := testService(t, srv.URL, "wrong")
	h, err := st.CreateHost(ctx, store.HostInput{Hostname: "tok-" + uuid.NewString()[:6], Address: "10.88.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	started, _, wait, err := svc.StartHosts(ctx, ctx, []*models.Host{h}, nil, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	wait()
	got, err := st.GetNetScan(ctx, started[0].ScanIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.NetScanFailed || !strings.Contains(got.Error, "PROV_NETSCAN_TOKEN") {
		t.Fatalf("scan = %s %q", got.Status, got.Error)
	}
}

func TestNotConfiguredRefusesUpFront(t *testing.T) {
	svc := New(nil, &config.Config{NetScanURL: "http://x"}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil)
	if _, _, _, err := svc.StartHosts(context.Background(), context.Background(), nil, nil, "t", false); err != ErrNotConfigured {
		t.Fatalf("got %v", err)
	}
}

// A range scan discovers, attaches what it finds to known hosts, and skips the
// jump host.
func TestRangeScanAttachesKnownHosts(t *testing.T) {
	// Addresses of its own per run, so a host left by an earlier run against the
	// same database cannot be the one matched.
	n := int(uuid.New()[0])
	addr := func(last int) string { return fmt.Sprintf("10.89.%d.%d", n, last) }
	fs := &fakeSidecar{overlay: "ok", found: []string{addr(1), addr(7)}, results: map[string]any{
		addr(7): map[string]any{"target": addr(7), "reachable": true, "openPorts": []int{22}},
	}}
	srv := httptest.NewServer(fs.handler(t, "tok"))
	defer srv.Close()
	svc, st, ctx := testService(t, srv.URL, "tok")
	svc.cfg.WGJumpIP = addr(1) // the first discovered address is the jump host
	h, err := st.CreateHost(ctx, store.HostInput{Hostname: "known-" + uuid.NewString()[:6], Address: addr(7)})
	if err != nil {
		t.Fatal(err)
	}
	rng, err := st.CreateNetScanRange(ctx, "r-"+uuid.NewString()[:6], fmt.Sprintf("10.89.%d.0/29", n), "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteNetScanRange(context.Background(), rng.ID) })
	_, wait, err := svc.StartRange(ctx, rng, nil, "test", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	scans, err := st.ListNetScans(ctx, nil, &rng.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].Target != addr(7) || scans[0].HostID == nil || *scans[0].HostID != h.ID {
		t.Fatalf("range scans = %+v", scans)
	}
	// A range address may be a printer: it keeps the sidecar's default rate, even
	// when it turns out to be a known host.
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if r := fs.rates[addr(7)]; r != 0 {
		t.Fatalf("range scan asked for rate %d, want the sidecar default (0)", r)
	}
}
