package netscan

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

func fakeResolve(m map[string]string) func(context.Context, string) (string, error) {
	return func(_ context.Context, name string) (string, error) {
		if ip, ok := m[name]; ok {
			return ip, nil
		}
		if strings.Count(name, ".") == 3 {
			return name, nil
		}
		return "", errors.New("no such host")
	}
}

func paths(ts []target) string {
	var p []string
	for _, t := range ts {
		s := t.Path + "=" + t.Addr
		if t.Unreachable != "" {
			s += "!"
		}
		p = append(p, s)
	}
	return strings.Join(p, ",")
}

// An enrolled host with both addresses is scanned on both, LAN first.
func TestPlanScansBothPaths(t *testing.T) {
	h := &models.Host{Hostname: "web", Address: "10.0.2.50", WGAddress: "10.100.0.21", Enrolled: true}
	got := paths(planPaths(context.Background(), h, fakeResolve(nil), overlayState{ok: true}))
	if got != "lan=10.0.2.50,overlay=10.100.0.21" {
		t.Fatalf("got %s", got)
	}
}

// A roaming host behind NAT is reachable only over the overlay. When the scanner
// cannot reach the overlay, that path must be RECORDED as unreachable -- dropping it
// would leave the host looking covered by a LAN scan of an address nothing answers on.
func TestOverlayRecordedUnreachableWhenScannerHasNoRoute(t *testing.T) {
	h := &models.Host{Hostname: "laptop", Address: "192.168.1.20", WGAddress: "10.100.0.30", Enrolled: true}
	ts := planPaths(context.Background(), h, fakeResolve(nil), overlayState{why: "no route"})
	if got := paths(ts); got != "lan=192.168.1.20,overlay=10.100.0.30!" {
		t.Fatalf("got %s", got)
	}
}

// An overlay address assigned at enrollment but never joined is not a path yet.
func TestUnenrolledHostHasNoOverlayPath(t *testing.T) {
	h := &models.Host{Hostname: "new", Address: "10.0.2.60", WGAddress: "10.100.0.40", Enrolled: false}
	if got := paths(planPaths(context.Background(), h, fakeResolve(nil), overlayState{ok: true})); got != "lan=10.0.2.60" {
		t.Fatalf("got %s", got)
	}
}

func TestHostnameResolvedWhenNoAddress(t *testing.T) {
	h := &models.Host{Hostname: "nas.homenet.com"}
	got := paths(planPaths(context.Background(), h, fakeResolve(map[string]string{"nas.homenet.com": "10.0.2.6"}), overlayState{}))
	if got != "lan=10.0.2.6" {
		t.Fatalf("got %s", got)
	}
}

func TestUnresolvableNameIsUnreachableNotSkipped(t *testing.T) {
	h := &models.Host{Hostname: "ghost.invalid"}
	ts := planPaths(context.Background(), h, fakeResolve(nil), overlayState{})
	if len(ts) != 1 || ts[0].Unreachable == "" || !strings.Contains(ts[0].Unreachable, "resolve") {
		t.Fatalf("got %+v", ts)
	}
}

// A host whose only address is its overlay address is scanned once.
func TestLANEqualToOverlayScannedOnce(t *testing.T) {
	h := &models.Host{Hostname: "x", Address: "10.100.0.21", WGAddress: "10.100.0.21", Enrolled: true}
	if got := paths(planPaths(context.Background(), h, fakeResolve(nil), overlayState{ok: true})); got != "overlay=10.100.0.21" {
		t.Fatalf("got %s", got)
	}
}

// ss -lntupH as root on a Debian host running nginx, sshd, a Docker-published
// redis and a loopback-only postgres, with the ownership lines the script appends.
const ssOut = `tcp   LISTEN 0      511          0.0.0.0:443        0.0.0.0:*    users:(("nginx",pid=812,fd=8),("nginx",pid=811,fd=8))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=640,fd=3))
tcp   LISTEN 0      4096         0.0.0.0:6379       0.0.0.0:*    users:(("docker-proxy",pid=1502,fd=4))
tcp   LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=700,fd=6))
udp   UNCONN 0      0            0.0.0.0:161        0.0.0.0:*    users:(("snmpd",pid=655,fd=6))
#--
#proc	811	/usr/sbin/nginx
#lib	811	/usr/lib/x86_64-linux-gnu/libssl.so.3
#lib	811	/usr/lib/x86_64-linux-gnu/libcrypto.so.3
#lib	811	/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2
#proc	640	/usr/sbin/sshd (deleted)
#lib	640	/usr/lib/x86_64-linux-gnu/libcrypto.so.3
#own	/usr/sbin/nginx	nginx
#own	/usr/lib/x86_64-linux-gnu/libssl.so.3	libssl3
#own	/usr/lib/x86_64-linux-gnu/libcrypto.so.3	libssl3
#own	/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2	libpcre2-8-0
#own	/usr/sbin/sshd	openssh-server
`

func TestParseListenersWithOwners(t *testing.T) {
	ls := parseListeners(ssOut)
	by := map[int]models.NetListener{}
	for _, l := range ls {
		by[l.Port] = l
	}
	if len(ls) != 5 {
		t.Fatalf("want 5 listeners, got %d: %+v", len(ls), ls)
	}
	ng := by[443]
	if ng.PID != 812 && ng.PID != 811 {
		t.Fatalf("nginx pid = %d", ng.PID)
	}
	// ss lists the worker (812) first; only the master (811) has /proc details in
	// this sample, so the worker's package is unknown -- not wrongly attributed.
	if ng.PID == 811 && (ng.Package != "nginx" || strings.Join(ng.LibPackages, ",") != "libpcre2-8-0,libssl3") {
		t.Fatalf("nginx owners = %q %v", ng.Package, ng.LibPackages)
	}
	// A binary replaced on disk after the process started is still owned by its package.
	if ssh := by[22]; ssh.Exe != "/usr/sbin/sshd" || ssh.Package != "openssh-server" {
		t.Fatalf("sshd = %+v", ssh)
	}
	if by[5432].Exposed {
		t.Fatal("a loopback-only listener reported exposed")
	}
	if by[161].Proto != "udp" {
		t.Fatalf("snmpd proto = %q", by[161].Proto)
	}
}

func TestPidOf(t *testing.T) {
	if got := pidOf(`users:(("nginx",pid=812,fd=8))`); got != 812 {
		t.Fatalf("got %d", got)
	}
	if got := pidOf(`no process info`); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestParseWindowsListeners(t *testing.T) {
	out := "tcp\t0.0.0.0\t3389\t1044\tsvchost\tC:\\Windows\\System32\\svchost.exe\r\n" +
		"tcp\t::\t3389\t1044\tsvchost\tC:\\Windows\\System32\\svchost.exe\r\n" +
		"tcp\t127.0.0.1\t5939\t2200\tTeamViewer\t\r\n" +
		"udp\t0.0.0.0\t161\t900\tsnmp\t\r\n" +
		"garbage line\r\n"
	ls := parseWindowsListeners(out)
	if len(ls) != 4 {
		t.Fatalf("want 4, got %d %+v", len(ls), ls)
	}
	if ls[2].Exposed {
		t.Fatal("loopback listener reported exposed")
	}
	if ls[0].Process != "svchost" || ls[0].PID != 1044 {
		t.Fatalf("got %+v", ls[0])
	}
}

func sampleResult() *sidecarResult {
	return &sidecarResult{
		Reachable: true,
		OpenPorts: []int{22, 443, 6379, 8443},
		Services: []sidecarService{
			{Port: 22, Proto: "tcp", Service: "ssh", Version: "OpenSSH_9.2p1"},
			{Port: 443, Proto: "tcp", Service: "http", TLS: true},
			{Port: 6379, Proto: "tcp", Service: "redis"},
		},
		Findings: []sidecarFinding{
			{TemplateID: "deprecated-tls", Name: "Deprecated TLS", Severity: "medium", Port: 443, Proto: "tcp"},
			{TemplateID: "exposed-redis", Name: "Redis exposed", Severity: "high", Port: 6379, Proto: "tcp",
				CVEs: []string{"cve-2025-49844"}},
			{TemplateID: "snmpv1-community-detect-string", Name: "SNMP public", Severity: "high", Port: 161, Proto: "udp"},
		},
		Detections: []sidecarFinding{{TemplateID: "nginx-version", Name: "nginx", Port: 443, Proto: "tcp"}},
	}
}

func TestMergeMarksUnexpectedOnlyWhenListenersKnown(t *testing.T) {
	ls := parseListeners(ssOut)
	services, findings := merge(sampleResult(), ls)
	by := map[string]models.NetService{}
	for _, s := range services {
		by[s.Proto+"/"+strconv.Itoa(s.Port)] = s
	}
	// 8443 answers but nothing on the host is bound to it.
	if !by["tcp/8443"].Unexpected {
		t.Fatal("8443 should be unexpected")
	}
	if by["tcp/443"].Unexpected || by["tcp/443"].Process != "nginx" {
		t.Fatalf("443 = %+v", by["tcp/443"])
	}
	// UDP finding ports become services so they show up in the exposure table.
	if s, ok := by["udp/161"]; !ok || s.Service != "snmp" || s.Unexpected {
		t.Fatalf("udp/161 = %+v ok=%v", s, ok)
	}
	if len(by["tcp/443"].Detections) != 1 {
		t.Fatalf("detections not attached: %+v", by["tcp/443"])
	}
	if findings[1].CVEs[0] != "CVE-2025-49844" {
		t.Fatalf("cve not normalised: %v", findings[1].CVEs)
	}

	// No listener list: nothing can be called unexpected.
	services, _ = merge(sampleResult(), nil)
	for _, s := range services {
		if s.Unexpected {
			t.Fatalf("%d/%s marked unexpected with no listener list", s.Port, s.Proto)
		}
	}
	if w := unexpectedWarning(services); w != "" {
		t.Fatalf("warning without listeners: %s", w)
	}
}

// A socket bound only to loopback does not explain a port the network reached.
func TestLoopbackListenerDoesNotExplainReachablePort(t *testing.T) {
	ls := []models.NetListener{{Proto: "tcp", Address: "127.0.0.1", Port: 5432, Exposed: false}}
	res := &sidecarResult{Reachable: true, OpenPorts: []int{5432}}
	services, _ := merge(res, ls)
	if !services[0].Unexpected {
		t.Fatal("a loopback-bound port answering from the network must be unexpected")
	}
}

func scanWith(path string, ls []models.NetListener, services []models.NetService, findings []models.NetFinding) models.NetScan {
	return models.NetScan{Path: path, Status: models.NetScanCompleted, ListenersKnown: ls != nil,
		Listeners: ls, Services: services, Findings: findings}
}

func TestExposureMarksBinaryAndLibraryPackages(t *testing.T) {
	ls := parseListeners(ssOut)
	// Use the master pid line for nginx so ownership is known.
	for i := range ls {
		if ls[i].Port == 443 {
			ls[i].PID = 811
			ls[i].Package = "nginx"
			ls[i].LibPackages = []string{"libpcre2-8-0", "libssl3"}
		}
	}
	lan := scanWith("lan", ls, []models.NetService{{Port: 443, Proto: "tcp"}, {Port: 22, Proto: "tcp"}}, nil)
	ov := scanWith("overlay", ls, []models.NetService{{Port: 22, Proto: "tcp"}},
		[]models.NetFinding{{TemplateID: "x", Port: 6379, Proto: "tcp", CVEs: []string{"CVE-2025-49844"}}})
	idx := buildExposureIndex([]models.NetScan{lan, ov})

	vf := []models.VulnFinding{
		{CVE: "CVE-2024-0001", Package: "libssl3", SourcePackage: "openssl"},
		{CVE: "CVE-2024-0002", Package: "openssh-server", SourcePackage: "openssh"},
		{CVE: "CVE-2024-0003", Package: "libx11-6"},
		{CVE: "CVE-2025-49844", Package: "redis-server"},
	}
	idx.annotate(vf)
	// libssl3 is loaded by nginx (443, LAN) AND by sshd (22, both paths): every
	// way in is listed, not only the first.
	if e := vf[0].Exposure; e == nil || e.Via != "library" || e.Port != 443 ||
		strings.Join(e.Paths, ",") != "lan,overlay" ||
		strings.Join(e.Endpoints, "|") != "443/tcp nginx (lan)|22/tcp sshd (lan)|22/tcp sshd (overlay)" {
		t.Fatalf("libssl3 exposure = %+v", e)
	}
	if e := vf[1].Exposure; e == nil || e.Via != "binary" || strings.Join(e.Paths, ",") != "lan,overlay" {
		t.Fatalf("openssh exposure = %+v", e)
	}
	if vf[2].Exposure != nil {
		t.Fatalf("an idle library is not exposed: %+v", vf[2].Exposure)
	}
	if e := vf[3].Exposure; e == nil || !e.Network {
		t.Fatalf("network-confirmed CVE not marked: %+v", e)
	}
}

// Unexpected ports and unreachable scans contribute no exposure: there is no
// listener to attribute them to.
func TestExposureIgnoresUnreachableScans(t *testing.T) {
	sc := scanWith("lan", parseListeners(ssOut), []models.NetService{{Port: 22, Proto: "tcp"}}, nil)
	sc.Status = models.NetScanUnreachable
	idx := buildExposureIndex([]models.NetScan{sc})
	vf := []models.VulnFinding{{CVE: "CVE-1", Package: "openssh-server"}}
	idx.annotate(vf)
	if vf[0].Exposure != nil {
		t.Fatal("an unreachable scan cannot expose anything")
	}
}

func TestCorroborate(t *testing.T) {
	fs := []models.NetFinding{
		{TemplateID: "a", CVEs: []string{"CVE-2025-49844"}},
		{TemplateID: "b", CVEs: []string{"CVE-2023-0001"}},
		{TemplateID: "c"},
	}
	corroborate(fs, map[string]bool{"CVE-2025-49844": true}, true)
	if fs[0].Corroboration != "confirmed" || fs[1].Corroboration != "banner-only" || fs[2].Corroboration != "" {
		t.Fatalf("got %q %q %q", fs[0].Corroboration, fs[1].Corroboration, fs[2].Corroboration)
	}
	// Without a package scan there is nothing to corroborate against.
	fs2 := []models.NetFinding{{TemplateID: "b", CVEs: []string{"CVE-2023-0001"}}}
	corroborate(fs2, nil, false)
	if fs2[0].Corroboration != "" {
		t.Fatalf("got %q with no package scan", fs2[0].Corroboration)
	}
}

func TestProbePorts(t *testing.T) {
	if got := probePorts(&models.Host{SSHPort: 2222}); got[0] != 2222 {
		t.Fatalf("got %v", got)
	}
	if got := probePorts(&models.Host{Protocol: "rdp"}); got[0] != 3389 {
		t.Fatalf("got %v", got)
	}
}

func TestListenerScriptRunsUnderSudoWhenAllowed(t *testing.T) {
	s := listenerScript()
	if !strings.Contains(s, "sudo -n true") || !strings.Contains(s, "| sudo -n sh") || !strings.Contains(s, "else echo") {
		t.Fatalf("script does not fall back cleanly: %s", s[:80])
	}
}

// A deployment whose scanner cannot reach the overlay by design does not record an
// unreachable overlay scan for every host every night.
func TestOverlaySkippedWhenDeploymentCannotReachIt(t *testing.T) {
	h := &models.Host{Hostname: "web", Address: "10.0.2.50", WGAddress: "10.100.0.21", Enrolled: true}
	if got := paths(planPaths(context.Background(), h, fakeResolve(nil), overlayState{skip: true, why: "k8s"})); got != "lan=10.0.2.50" {
		t.Fatalf("got %s", got)
	}
}

func TestValidateRange(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.2.0/24": "10.0.2.0/24", "10.0.2.77/24": "10.0.2.0/24", "10.0.2.40": "10.0.2.40/32",
		"10.0.0.0/22": "10.0.0.0/22",
	} {
		got, err := ValidateRange(in)
		if err != nil || got != want {
			t.Errorf("ValidateRange(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"10.0.0.0/21", "127.0.0.0/30", "169.254.0.0/24", "224.0.0.0/24",
		"0.0.0.0/32", "nonsense", ""} {
		if _, err := ValidateRange(bad); err == nil {
			t.Errorf("ValidateRange(%q) accepted", bad)
		}
	}
}
