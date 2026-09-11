package monitor

import "testing"

// Real output, captured from the tools rather than imagined. The parsing is the
// part that silently goes wrong: the local-address column differs between ss and
// netstat and between address families, and an IPv6 address is full of colons —
// so splitting on the first one puts a hostname in the port field and drops the
// row.

// `ss -lntupH` on a current Linux host.
const ssOutput = `tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=1104,fd=5))
tcp   LISTEN 0      511             [::]:443          [::]:*    users:(("nginx",pid=2938,fd=6))
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*    users:(("dhclient",pid=640,fd=6))
tcp   LISTEN 0      4096    10.10.0.208:8080        0.0.0.0:*
`

func TestListeningPortsFromSS(t *testing.T) {
	got := parseListeningPorts(ssOutput)
	if len(got) != 5 {
		t.Fatalf("parsed %d sockets, want 5: %+v", len(got), got)
	}

	by := map[int]int{}
	for i, p := range got {
		by[p.Port] = i
	}
	for _, want := range []struct {
		port    int
		proto   string
		addr    string
		process string
		exposed bool
	}{
		{22, "tcp", "0.0.0.0", "sshd", true},
		{5432, "tcp", "127.0.0.1", "postgres", false}, // loopback: running, not reachable
		{443, "tcp", "[::]", "nginx", true},           // IPv6 wildcard
		{68, "udp", "0.0.0.0", "dhclient", true},
		{8080, "tcp", "10.10.0.208", "", true}, // one interface is still exposed
	} {
		i, ok := by[want.port]
		if !ok {
			t.Errorf("port %d missing", want.port)
			continue
		}
		p := got[i]
		if p.Proto != want.proto || p.Address != want.addr ||
			p.Process != want.process || p.Exposed != want.exposed {
			t.Errorf("port %d = %+v, want proto=%s addr=%s process=%q exposed=%v",
				want.port, p, want.proto, want.addr, want.process, want.exposed)
		}
	}
}

// `netstat -lntup`, for hosts too old for ss. The process column is "pid/name"
// and is "-" when the caller is not root.
const netstatOutput = `tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp6       0      0 :::443                  :::*                    LISTEN      2938/nginx
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
`

func TestListeningPortsFromNetstat(t *testing.T) {
	got := parseListeningPorts(netstatOutput)
	if len(got) != 3 {
		t.Fatalf("parsed %d sockets, want 3: %+v", len(got), got)
	}
	// ":::443" is the IPv6 wildcard and a port. Splitting on the LAST colon gives
	// address "::" and port 443; splitting on the first gives address "" and a
	// port of "::443", which parses as nothing and drops the row.
	if got[1].Port != 443 || got[1].Proto != "tcp" || got[1].Address != "::" {
		t.Errorf("the IPv6 row parsed as %+v; want proto=tcp addr=:: port=443", got[1])
	}
	if got[2].Exposed {
		t.Error("127.0.0.1:5432 reported as exposed")
	}
	// "-" is not a process name.
	if got[2].Process == "-" {
		t.Errorf("process = %q; netstat's '-' means 'not permitted to say', not a "+
			"program called dash", got[2].Process)
	}
}

// The distinction the whole feature exists for.
func TestOnlyLoopbackIsUnexposed(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1":  false,
		"127.0.0.53": false, // systemd-resolved
		"::1":        false,
		"[::1]":      false,
		"0.0.0.0":    true,
		"[::]":       true,
		"*":          true,
		"10.10.0.208": true, // one NIC is still a network
	} {
		if got := isExposed(addr); got != want {
			t.Errorf("isExposed(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestGarbageIsSkippedNotStored(t *testing.T) {
	for _, in := range []string{"", "Netid State Recv-Q Send-Q Local", "nonsense\n\n"} {
		if got := parseListeningPorts(in); len(got) != 0 {
			t.Errorf("parsed %+v from %q", got, in)
		}
	}
}

// Captured from a real AlmaLinux 9 host, unprivileged. Interface-scoped
// addresses are the part worth pinning: systemd-resolved binds 127.0.0.53%lo and
// DHCPv6 binds a link-local with a %ens18 suffix, and both sit in the middle of
// the colon-splitting the IPv6 form already makes delicate.
const realAlmaOutput = `udp UNCONN 0      0                                0.0.0.0:56784 0.0.0.0:*
udp UNCONN 0      0                             127.0.0.54:53    0.0.0.0:*
udp UNCONN 0      0                          127.0.0.53%lo:53    0.0.0.0:*
udp UNCONN 0      0                                0.0.0.0:5355  0.0.0.0:*
udp UNCONN 0      0      [fe80::5bb3:f5e9:5b61:8532]%ens18:546      [::]:*
udp UNCONN 0      0                                   [::]:5355     [::]:*
tcp LISTEN 0      128                              0.0.0.0:22    0.0.0.0:*    users:(("sshd",pid=812,fd=3))
`

func TestRealHostOutput(t *testing.T) {
	got := parseListeningPorts(realAlmaOutput)
	if len(got) != 7 {
		t.Fatalf("parsed %d of 7 sockets: %+v", len(got), got)
	}

	byPort := map[int]int{}
	for i, p := range got {
		byPort[p.Port] = i
	}

	// systemd-resolved on interface-scoped loopback is NOT exposed. Reading the
	// %lo suffix as part of an unknown address and defaulting to "exposed" would
	// report a stub resolver as reachable on every host in the fleet.
	if i, ok := byPort[53]; !ok || got[i].Exposed {
		t.Errorf("127.0.0.53%%lo:53 must not be exposed, got %+v", got[i])
	}
	// The link-local DHCPv6 socket must parse at all — the address contains four
	// colons and an interface suffix before the port.
	if i, ok := byPort[546]; !ok {
		t.Error("the link-local IPv6 socket was dropped entirely")
	} else if got[i].Proto != "udp" {
		t.Errorf("546 parsed as %+v", got[i])
	}
	// And a genuinely exposed one is still flagged.
	if i, ok := byPort[22]; !ok || !got[i].Exposed || got[i].Process != "sshd" {
		t.Errorf("0.0.0.0:22 should be exposed sshd, got %+v", got[i])
	}
}
