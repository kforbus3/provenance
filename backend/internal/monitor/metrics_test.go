package monitor

import "testing"

const sampleMetricsOutput = `::LOADAVG::
0.80 0.40 0.20 2/512 12345
::MEM::
MemTotal: 16384000
MemAvailable: 4096000
::DF::
Filesystem     1B-blocks       Used  Available Capacity Mounted on
/dev/sda1     107374182400 96636764160 10737418240      90% /
/dev/sda2      53687091200  5368709120 48318382080      10% /data
::IP::
2: eth0    inet 10.10.0.50/24 brd 10.10.0.255 scope global eth0
2: eth0    inet 10.10.0.51/24 brd 10.10.0.255 scope global secondary eth0
3: wg0    inet 10.100.0.5/32 scope global wg0
::ROUTE::
default via 10.10.0.1 dev eth0 proto static metric 100
::SRC::
1.1.1.1 via 10.10.0.1 dev eth0 src 10.10.0.50 uid 1000
::END::
`

func TestParseMetrics(t *testing.T) {
	m := parseMetrics(sampleMetricsOutput, 4)
	if m == nil {
		t.Fatal("nil metrics")
	}

	// Load + per-core (4 cores).
	if m.Load1 == nil || *m.Load1 != 0.80 {
		t.Fatalf("load1 = %v, want 0.80", m.Load1)
	}
	if m.LoadPerCore == nil || *m.LoadPerCore != 0.20 {
		t.Fatalf("loadPerCore = %v, want 0.20", m.LoadPerCore)
	}

	// Memory: 16384000kB total / 4096000kB avail -> 75% used.
	if m.MemTotalMB != 16000 {
		t.Fatalf("memTotalMb = %d, want 16000", m.MemTotalMB)
	}
	if m.MemUsedPct == nil || *m.MemUsedPct != 75 {
		t.Fatalf("memUsedPct = %v, want 75", m.MemUsedPct)
	}

	// Disk: two filesystems; header skipped; min free = 10% (sda1).
	if len(m.Disk) != 2 {
		t.Fatalf("disk count = %d, want 2", len(m.Disk))
	}
	if m.Disk[0].Mount != "/" || m.Disk[0].UsePct != 90 {
		t.Fatalf("disk[0] = %+v, want mount=/ usePct=90", m.Disk[0])
	}
	if m.MinDiskFreePct == nil || *m.MinDiskFreePct != 10 {
		t.Fatalf("minDiskFreePct = %v, want 10", m.MinDiskFreePct)
	}

	// Network: eth0 (two addrs) + wg0; default gw + primary IP.
	if m.Network == nil {
		t.Fatal("nil network")
	}
	if len(m.Network.Interfaces) != 2 {
		t.Fatalf("interfaces = %d, want 2", len(m.Network.Interfaces))
	}
	if m.Network.Interfaces[0].Name != "eth0" || len(m.Network.Interfaces[0].Addrs) != 2 {
		t.Fatalf("eth0 = %+v, want 2 addrs", m.Network.Interfaces[0])
	}
	if m.Network.DefaultGateway != "10.10.0.1" || m.Network.DefaultIface != "eth0" {
		t.Fatalf("default route = %s/%s, want 10.10.0.1/eth0", m.Network.DefaultGateway, m.Network.DefaultIface)
	}
	if m.Network.PrimaryIP != "10.10.0.50" || m.PrimaryIP != "10.10.0.50" {
		t.Fatalf("primaryIp = %q/%q, want 10.10.0.50", m.Network.PrimaryIP, m.PrimaryIP)
	}
}

func TestParseMetricsEmpty(t *testing.T) {
	// Missing tools -> empty sections; should not panic, scalars stay zero/nil.
	m := parseMetrics("::LOADAVG::\n::MEM::\n::DF::\n::IP::\n::ROUTE::\n::SRC::\n::END::\n", 0)
	if m == nil {
		t.Fatal("nil metrics")
	}
	if len(m.Disk) != 0 || m.MinDiskFreePct != nil || m.Network != nil || m.Load1 != nil {
		t.Fatalf("expected empty metrics, got %+v", m)
	}
}

func TestParseDFSkipsBadRows(t *testing.T) {
	df := "Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
		"tmpfs notanumber 0 0 0% /run\n" +
		"/dev/sda1 1000 400 600 40% /mnt/data dir\n"
	got := parseDF(df)
	if len(got) != 1 {
		t.Fatalf("rows = %d, want 1", len(got))
	}
	if got[0].Mount != "/mnt/data dir" { // mount with a space preserved
		t.Fatalf("mount = %q, want '/mnt/data dir'", got[0].Mount)
	}
}
