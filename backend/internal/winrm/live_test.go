package winrm

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// A live check against a real Windows host, skipped unless one is offered.
//
// Everything else about this package can be unit tested except the thing most likely
// to be wrong: whether a Windows host configured the way the docs describe actually
// answers. The ports being open says a listener exists; it does not say NTLM
// negotiates, that the HTTPS listener's self-signed certificate is accepted, or that
// the fact script survives -EncodedCommand and comes back parseable.
//
//	PROV_WINRM_TEST_HOST=10.10.0.199 \
//	PROV_WINRM_TEST_USER=Administrator \
//	PROV_WINRM_TEST_PASS=... \
//	go test ./internal/winrm/ -run Live -v
func TestLiveWindowsHost(t *testing.T) {
	host := os.Getenv("PROV_WINRM_TEST_HOST")
	user := os.Getenv("PROV_WINRM_TEST_USER")
	pass := os.Getenv("PROV_WINRM_TEST_PASS")
	if host == "" || user == "" || pass == "" {
		t.Skip("set PROV_WINRM_TEST_HOST/USER/PASS to run against a real Windows host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dial := func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	// Both transports, separately: 5986 first is the path production takes, and a
	// self-signed certificate there is expected (the endpoint sets Insecure).
	for _, port := range []int{5986, 5985} {
		f, err := Collect(ctx, dial, host, user, pass, []int{port}, false)
		if err != nil {
			t.Errorf("port %d: %v", port, err)
			continue
		}
		if f.OS == "" || f.CPUCount == 0 || f.MemoryMB == 0 {
			t.Errorf("port %d: facts came back empty: %+v", port, f)
			continue
		}
		t.Logf("port %d: %s | %s | %s | %d cpu | %d MB (%d free) | up %ds | %d disk(s) | %d nic(s) | gw %s",
			port, f.OS, f.OSVersion, f.Architecture, f.CPUCount, f.MemoryMB, f.MemFreeMB,
			f.UptimeSeconds, len(f.Disks), len(f.Interfaces), f.Gateway)
	}

	// The installed-software inventory is what feeds third-party CVE scanning; an
	// empty list would make a scan report a clean host rather than an unknown one.
	sw, err := CollectSoftware(ctx, dial, host, user, pass, []int{5986, 5985}, 2*time.Minute)
	if err != nil {
		t.Fatalf("software inventory: %v", err)
	}
	if len(sw) == 0 {
		t.Error("no installed software returned; a third-party CVE scan would read this " +
			"as a host with nothing on it")
	}
	t.Logf("software inventory: %d entries", len(sw))
	for i, s := range sw {
		if i >= 8 {
			break
		}
		t.Logf("  %+v", s)
	}
}
