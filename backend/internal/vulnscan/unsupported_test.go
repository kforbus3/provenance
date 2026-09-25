package vulnscan

import (
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The failure: a host with no dpkg or rpm database sent an archive of
// /etc/os-release alone, grype found no packages in it, and the scan completed
// with zero findings -- an OpenWrt router reading as fully patched. It must fail,
// and say why.
func TestAHostWithNoPackageDatabaseCannotScanClean(t *testing.T) {
	_, err := decodeCollected(noPackageDBMarker + "openwrt\n")
	if err == nil {
		t.Fatal("a host with no package database must not produce a scannable archive")
	}
	for _, want := range []string{"cannot assess", `"openwrt"`, "dpkg or rpm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("reason %q does not mention %q", err, want)
		}
	}
}

// The script itself, run for real, on a machine with neither database -- this
// test's own when it is not a Debian or RPM system. Asserting on decodeCollected
// alone would prove the parser, not that the script ever says the words.
func TestTheCollectScriptSaysSoWhenThereIsNoDatabase(t *testing.T) {
	for _, p := range []string{"/var/lib/dpkg/status", "/var/lib/rpm"} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("%s exists here; this test needs a system without one", p)
		}
	}
	out, err := exec.Command("sh", "-c", collectScript).CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), noPackageDBMarker) {
		t.Fatalf("expected the no-database marker, got %q", out)
	}
	if _, err := decodeCollected(string(out)); err == nil || !strings.Contains(err.Error(), "cannot assess") {
		t.Fatalf("expected a cannot-assess failure, got %v", err)
	}
}

// A real archive still decodes.
func TestAnArchiveStillDecodes(t *testing.T) {
	raw, err := decodeCollected(base64.StdEncoding.EncodeToString([]byte("tarball")) + "\n")
	if err != nil || string(raw) != "tarball" {
		t.Fatalf("got %q, %v", raw, err)
	}
}

func TestAStaleCVEDatabaseIsCalledOut(t *testing.T) {
	now := time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC)
	fresh := now.Add(-23 * time.Hour)
	if w := staleDBWarning(&fresh, now); w != "" {
		t.Errorf("a database from the last refresh is not stale: %q", w)
	}
	old := now.Add(-50 * time.Hour)
	w := staleDBWarning(&old, now)
	if !strings.Contains(w, "50 hours ago") || !strings.Contains(w, "refresh") {
		t.Errorf("expected a stale-database warning naming its age, got %q", w)
	}
	if staleDBWarning(nil, now) != "" {
		t.Error("an unknown build time is not evidence of staleness")
	}
}
