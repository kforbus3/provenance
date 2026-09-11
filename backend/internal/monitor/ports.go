package monitor

import (
	"strconv"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
)

// listeningPortsCap bounds what is stored per host. A host with more than this
// many bound sockets has something wrong with it that a longer list will not
// help anybody diagnose.
const listeningPortsCap = 200

// portsScript lists bound sockets. `ss` on anything current, `netstat` for hosts
// old enough not to have it — both are read-only and neither needs root, though
// without root the owning process is hidden for sockets the login user does not
// own. That is why the process column is optional rather than expected: a
// half-attributed list is worth having and a sudo prompt in a monitor sweep is
// not.
const portsScript = `
if command -v ss >/dev/null 2>&1; then
  ss -lntupH 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntup 2>/dev/null | tail -n +3
fi
`

// collectListeningPorts records what the host has bound.
//
// Best-effort and never fatal: a host that will not answer keeps whatever was
// collected last rather than having it blanked, because "we could not ask" and
// "nothing is listening" are very different and must not look the same.
func collectListeningPorts(conn *sshgw.Conn, inv *models.HostInventory) {
	out, err := runCmd(conn, portsScript)
	if err != nil {
		return
	}
	ports := parseListeningPorts(out)
	now := time.Now()
	inv.ListeningPorts = ports
	inv.PortsCheckedAt = &now
}

// parseListeningPorts reads `ss -lntupH` or `netstat -lntup` output.
//
// Split out from the collection so it can be tested against real output from
// both tools, on both address families, without a host.
func parseListeningPorts(out string) []models.ListeningPort {
	seen := map[string]bool{}
	ports := []models.ListeningPort{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" && proto != "tcp6" && proto != "udp6" {
			continue
		}
		proto = strings.TrimSuffix(proto, "6")

		// The local address is in a different column for each tool, which is the
		// kind of thing that looks fine until a host old enough to need netstat
		// reports nothing listening:
		//
		//   ss:      tcp  LISTEN 0 4096  0.0.0.0:22 ...   -> column 4
		//   netstat: tcp  0      0       0.0.0.0:22 ...   -> column 3
		//
		// They are told apart by column 1: ss puts a state word there
		// (LISTEN/UNCONN), netstat puts the receive queue, a number.
		local := f[4]
		if _, numeric := strconv.Atoi(f[1]); numeric == nil {
			local = f[3]
		}

		// The address column differs by family too: ss gives "0.0.0.0:22",
		// "[::]:443" or "*:68"; netstat gives ":::443". Splitting on the LAST
		// colon is what handles IPv6, whose address is made of them.
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, portStr := local[:i], local[i+1:]
		port, perr := strconv.Atoi(portStr)
		if perr != nil || port <= 0 || port > 65535 {
			continue
		}

		key := proto + local
		if seen[key] {
			continue
		}
		seen[key] = true

		ports = append(ports, models.ListeningPort{
			Proto:   proto,
			Address: addr,
			Port:    port,
			Process: processName(line),
			Exposed: isExposed(addr),
		})
		if len(ports) >= listeningPortsCap {
			break
		}
	}
	return ports
}

// isExposed reports whether a bound address is reachable from off the host.
//
// Loopback is the only binding that is definitively not: everything else --
// a wildcard, or one specific interface address -- is reachable by something,
// and treating "bound to one NIC" as safe is how a database ends up served to a
// network somebody forgot was attached.
func isExposed(addr string) bool {
	a := strings.Trim(addr, "[]")
	switch {
	case a == "127.0.0.1" || a == "::1" || strings.HasPrefix(a, "127."):
		return false
	case a == "%lo" || strings.HasSuffix(a, "%lo"):
		return false
	}
	return true
}

// processName pulls the owning program out of the users:(("sshd",pid=...)) field
// ss appends, or netstat's trailing "1234/sshd". Absent without root, which is
// not an error.
func processName(line string) string {
	if i := strings.Index(line, `users:(("`); i >= 0 {
		rest := line[i+len(`users:(("`):]
		if j := strings.Index(rest, `"`); j > 0 {
			return rest[:j]
		}
	}
	// netstat: the last field is pid/name, or "-" when not permitted.
	f := strings.Fields(line)
	if len(f) > 0 {
		last := f[len(f)-1]
		if k := strings.Index(last, "/"); k > 0 && k < len(last)-1 {
			return last[k+1:]
		}
	}
	return ""
}
