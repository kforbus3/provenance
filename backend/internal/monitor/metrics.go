package monitor

import (
	"strconv"
	"strings"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

// metricsScript gathers disk, memory, load, and network facts in one shot. Each
// section is delimited so the output can be parsed deterministically. All
// commands are read-only and best-effort (missing tools just yield empty
// sections). cpuCount (from inventory) is applied to load in Go.
const metricsScript = `echo "::LOADAVG::"; cat /proc/loadavg 2>/dev/null
echo "::MEM::"; awk '/^MemTotal:|^MemAvailable:/{print $1, $2}' /proc/meminfo 2>/dev/null
echo "::DF::"; df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null
echo "::IP::"; ip -o -4 addr show scope global 2>/dev/null
echo "::ROUTE::"; ip route show default 2>/dev/null
echo "::SRC::"; ip route get 1.1.1.1 2>/dev/null | head -1
echo "::END::"`

// collectMetrics runs the metrics script over the open connection and parses it.
// Returns nil if the command fails entirely.
func collectMetrics(conn *sshgw.Conn, cpuCount int) *models.HostMetrics {
	out, err := runCmd(conn, metricsScript)
	if err != nil {
		return nil
	}
	return parseMetrics(out, cpuCount)
}

// parseMetrics is pure: it turns the delimited script output into HostMetrics.
func parseMetrics(out string, cpuCount int) *models.HostMetrics {
	sections := splitSections(out)
	m := &models.HostMetrics{}

	parseLoadAvg(sections["LOADAVG"], cpuCount, m)
	parseMem(sections["MEM"], m)
	m.Disk = parseDF(sections["DF"])
	if p := minDiskFreePct(m.Disk); p != nil {
		m.MinDiskFreePct = p
	}
	if net := parseNetwork(sections["IP"], sections["ROUTE"], sections["SRC"]); net != nil {
		m.Network = net
		m.PrimaryIP = net.PrimaryIP
	}
	return m
}

// splitSections groups lines under their "::NAME::" markers.
func splitSections(out string) map[string]string {
	sections := map[string]string{}
	var cur string
	var b strings.Builder
	flush := func() {
		if cur != "" {
			sections[cur] = strings.TrimRight(b.String(), "\n")
		}
		b.Reset()
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "::") && strings.HasSuffix(line, "::") && len(line) > 4 {
			flush()
			cur = strings.TrimSuffix(strings.TrimPrefix(line, "::"), "::")
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	flush()
	return sections
}

func parseLoadAvg(s string, cpuCount int, m *models.HostMetrics) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) < 3 {
		return
	}
	if v, err := strconv.ParseFloat(f[0], 64); err == nil {
		m.Load1 = &v
		if cpuCount > 0 {
			pc := v / float64(cpuCount)
			m.LoadPerCore = &pc
		}
	}
	if v, err := strconv.ParseFloat(f[1], 64); err == nil {
		m.Load5 = &v
	}
	if v, err := strconv.ParseFloat(f[2], 64); err == nil {
		m.Load15 = &v
	}
}

func parseMem(s string, m *models.HostMetrics) {
	var totalKB, availKB int64
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availKB = v
		}
	}
	if totalKB <= 0 {
		return
	}
	m.MemTotalMB = totalKB / 1024
	m.MemAvailableMB = availKB / 1024
	used := float64(totalKB-availKB) / float64(totalKB) * 100
	m.MemUsedPct = &used
}

// parseDF parses `df -P -B1` output (bytes). Columns: FS, size, used, avail,
// capacity%, mount (mount may contain spaces -> join the remainder).
func parseDF(s string) []models.DiskFS {
	var out []models.DiskFS
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if i == 0 && (f[0] == "Filesystem" || strings.EqualFold(f[1], "1B-blocks")) {
			continue // header
		}
		size, err1 := strconv.ParseInt(f[1], 10, 64)
		used, err2 := strconv.ParseInt(f[2], 10, 64)
		avail, err3 := strconv.ParseInt(f[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || size <= 0 {
			continue
		}
		out = append(out, models.DiskFS{
			Mount:      strings.Join(f[5:], " "),
			SizeBytes:  size,
			UsedBytes:  used,
			AvailBytes: avail,
			UsePct:     round1(float64(used) / float64(size) * 100),
		})
	}
	return out
}

func minDiskFreePct(disk []models.DiskFS) *float64 {
	first := true
	var min float64
	for _, d := range disk {
		if d.SizeBytes <= 0 {
			continue
		}
		free := float64(d.AvailBytes) / float64(d.SizeBytes) * 100
		if first || free < min {
			min, first = free, false
		}
	}
	if first {
		return nil
	}
	r := round1(min)
	return &r
}

// parseNetwork parses `ip -o -4 addr`, the default route, and the primary src IP.
func parseNetwork(ipOut, routeOut, srcOut string) *models.HostNetwork {
	byIface := map[string]*models.NetInterface{}
	var order []string
	for _, line := range strings.Split(ipOut, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		iface := strings.TrimSuffix(f[1], ":")
		var cidr string
		for i, tok := range f {
			if tok == "inet" && i+1 < len(f) {
				cidr = f[i+1]
				break
			}
		}
		if iface == "" || cidr == "" {
			continue
		}
		ni, ok := byIface[iface]
		if !ok {
			ni = &models.NetInterface{Name: iface}
			byIface[iface] = ni
			order = append(order, iface)
		}
		ni.Addrs = append(ni.Addrs, cidr)
	}

	net := &models.HostNetwork{}
	for _, name := range order {
		net.Interfaces = append(net.Interfaces, *byIface[name])
	}
	// default route: "default via <gw> dev <iface> ..."
	if rf := strings.Fields(strings.TrimSpace(routeOut)); len(rf) >= 5 && rf[0] == "default" {
		net.DefaultGateway = fieldAfter(rf, "via")
		net.DefaultIface = fieldAfter(rf, "dev")
	}
	// primary IP: "... src <ip> ..."
	if sf := strings.Fields(strings.TrimSpace(srcOut)); len(sf) > 0 {
		net.PrimaryIP = fieldAfter(sf, "src")
	}
	if len(net.Interfaces) == 0 && net.PrimaryIP == "" && net.DefaultGateway == "" {
		return nil
	}
	return net
}

func fieldAfter(fields []string, key string) string {
	for i, f := range fields {
		if f == key && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}
