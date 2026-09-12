package appsupport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type fakeSource struct {
	failDiagnostics bool
	failMigrations  bool
}

func (f *fakeSource) Version() string { return "1.2.15" }
func (f *fakeSource) Instances(context.Context) ([]InstanceInfo, error) {
	return []InstanceInfo{{ID: "i1", Hostname: "control01", Version: "1.2.15", Leader: true}}, nil
}
func (f *fakeSource) Jobs() []JobInfo {
	return []JobInfo{{Name: "container-image-check", LastRun: time.Now(), Error: "2 image(s) could not be checked"}}
}
func (f *fakeSource) Migrations(context.Context) ([]string, error) {
	if f.failMigrations {
		return nil, errors.New("database unreachable")
	}
	return []string{"0092_rollout_images", "0093_clean_stack_compose"}, nil
}
func (f *fakeSource) Settings() []Setting {
	return []Setting{
		{Name: "FLEET_ENV", Value: "production"},
		{Name: "audit HMAC key", Value: Set("a-real-secret")},
	}
}
func (f *fakeSource) Health(context.Context) []Check {
	return []Check{{Name: "database", OK: true}, {Name: "updater", OK: false, Detail: "connection refused to 10.10.0.5:9000"}}
}
func (f *fakeSource) FleetSummary(context.Context) (FleetSummary, error) {
	return FleetSummary{Hosts: 19, ByStatus: map[string]int{"online": 17}}, nil
}
func (f *fakeSource) UpgradeStatus(context.Context) (any, error) {
	return map[string]string{"state": "success", "targetVersion": "1.2.15"}, nil
}
func (f *fakeSource) Diagnostics(context.Context) (Diagnostics, error) {
	if f.failDiagnostics {
		return Diagnostics{}, errors.New("the updater is not reachable")
	}
	return Diagnostics{
		Containers: "fleet-terminal-backend-1\tbackend:1.2.15\tUp 2 hours",
		Logs: map[string]string{
			"fleet-terminal-backend-1": `level=info msg="listening" addr=0.0.0.0:8080
level=error msg="db" url=postgres://fleet:s3cr3t@10.10.0.9:5432/fleet
level=info peer=10.10.0.9 retried peer=10.10.0.9`,
		},
	}, nil
}

func read(t *testing.T, b []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		out[strings.TrimPrefix(h.Name, "provenance-support/")] = string(body)
	}
	return out
}

func collect(t *testing.T, src Source) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	if err := New(src).Collect(context.Background(), &buf, "keith"); err != nil {
		t.Fatal(err)
	}
	return read(t, buf.Bytes())
}

func TestABundleCarriesTheThingsYouWouldOtherwiseGoAndFetch(t *testing.T) {
	files := collect(t, &fakeSource{})
	for _, want := range []string{
		"manifest.json", "instances.json", "migrations.txt", "settings.json",
		"jobs.json", "health.json", "upgrade-status.json", "fleet-summary.json",
		"containers.txt", "logs/fleet-terminal-backend-1.log",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s — an operator would have to go and get it by hand", want)
		}
	}
}

// The security question a bundle raises, since it exists to be sent somewhere.
func TestNoSecretSurvivesIntoTheBundle(t *testing.T) {
	files := collect(t, &fakeSource{})
	all := strings.Join(valuesOf(files), "\n")
	for _, secret := range []string{"s3cr3t", "a-real-secret"} {
		if strings.Contains(all, secret) {
			t.Errorf("%q reached the bundle", secret)
		}
	}
	// And the diagnostic half survives: which database, and that the key is set.
	if !strings.Contains(all, "postgres://fleet:") {
		t.Error("scrubbing removed which database it was, which is the diagnostic part")
	}
	if !strings.Contains(files["settings.json"], `"set"`) {
		t.Error("a configured secret should be reported as set")
	}
}

func TestHostnamesStayAndAddressesAreConsistentlyReplaced(t *testing.T) {
	files := collect(t, &fakeSource{})
	all := strings.Join(valuesOf(files), "\n")

	if !strings.Contains(all, "control01") {
		t.Error("hostnames should be kept — they are what makes a bundle readable")
	}
	if strings.Contains(all, "10.10.0.9") || strings.Contains(all, "10.10.0.5") {
		t.Errorf("a real address survived:\n%s", all)
	}
	// 0.0.0.0 is diagnostic and identifies nobody.
	if !strings.Contains(all, "0.0.0.0:8080") {
		t.Error("the listen address was replaced, which loses a useful fact")
	}
	// The two mentions of 10.10.0.9 in one log line must map to the same thing —
	// otherwise "the same peer twice" is no longer visible.
	logLines := files["logs/fleet-terminal-backend-1.log"]
	last := logLines[strings.LastIndex(logLines, "peer="):]
	first := logLines[strings.Index(logLines, "peer="):]
	f := strings.Fields(first)[0]
	l := strings.Fields(last)[0]
	if f != l {
		t.Errorf("the same peer got two placeholders (%s vs %s)", f, l)
	}

	var m Manifest
	if err := json.Unmarshal([]byte(files["manifest.json"]), &m); err != nil {
		t.Fatal(err)
	}
	if m.Anonymised == 0 {
		t.Error("the manifest does not record that anonymisation happened")
	}
	if len(m.Notes) == 0 {
		t.Error("the manifest should say what was done to the contents")
	}
}

// A bundle is wanted precisely when something is broken. A collector that
// produces nothing because one source is down fails at the only moment it counts.
func TestAFailedSourceDoesNotLoseTheRestOfTheBundle(t *testing.T) {
	files := collect(t, &fakeSource{failDiagnostics: true, failMigrations: true})

	if _, ok := files["instances.json"]; !ok {
		t.Error("a working source was dropped because another failed")
	}
	var m Manifest
	if err := json.Unmarshal([]byte(files["manifest.json"]), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.CollectErrors) != 2 {
		t.Errorf("the manifest records %d collection errors, want 2: %v",
			len(m.CollectErrors), m.CollectErrors)
	}
	joined := strings.Join(m.CollectErrors, " ")
	if !strings.Contains(joined, "updater is not reachable") ||
		!strings.Contains(joined, "database unreachable") {
		t.Errorf("the reasons are not preserved: %v", m.CollectErrors)
	}
}

func TestAContainerNameCannotEscapeTheArchive(t *testing.T) {
	if got := safeName("../../etc/passwd"); strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Errorf("safeName(%q) = %q", "../../etc/passwd", got)
	}
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
