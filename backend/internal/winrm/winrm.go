// Package winrm collects host facts from a Windows host over WinRM (PowerShell
// remoting). Windows exposes no SSH for Fleet's usual fact collection, so RDP hosts
// are queried over WinRM instead, authenticated with the host's vaulted credential
// and tunneled through the jump host (the same path as the RDP session).
package winrm

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"
)

// Facts are the host facts collected from a Windows host.
type Facts struct {
	OS            string
	OSVersion     string // version + build, e.g. "10.0.20348 (Build 20348)"
	Architecture  string
	CPUCount      int
	MemoryMB      int64
	MemFreeMB     int64
	UptimeSeconds int64
	Disks         []Disk
	Interfaces    []Iface
	Gateway       string

	// Pending Windows Update counts. nil when the search wasn't run this call
	// (it's throttled) or the WUA query failed — distinct from a real zero.
	UpdatesAvailable *int
	SecurityUpdates  *int
}

// Disk is one fixed logical drive's capacity/free space (bytes).
type Disk struct {
	Mount     string
	SizeBytes int64
	FreeBytes int64
}

// Iface is a network interface and its IP addresses.
type Iface struct {
	Name  string
	Addrs []string
}

// DialFunc opens a raw TCP connection to addr (e.g. through a jump host).
type DialFunc func(network, addr string) (net.Conn, error)

// factsScript emits KEY=VALUE lines for the facts we surface. Kept free of backticks
// (Go raw string) and newlines so it encodes cleanly as a -EncodedCommand. DISK and
// NIC lines are repeated once per drive / interface.
const factsScript = `$o=Get-CimInstance Win32_OperatingSystem;$s=Get-CimInstance Win32_ComputerSystem;` +
	`$p=(Get-CimInstance Win32_Processor|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;` +
	`Write-Output "OS=$($o.Caption)";Write-Output "VER=$($o.Version)";Write-Output "BUILD=$($o.BuildNumber)";` +
	`Write-Output "ARCH=$($o.OSArchitecture)";Write-Output "CPU=$p";` +
	`Write-Output "MEMMB=$([math]::Round($s.TotalPhysicalMemory/1MB))";` +
	`Write-Output "MEMFREEMB=$([math]::Round($o.FreePhysicalMemory/1KB))";` +
	`Write-Output "UPTIME=$([int]((Get-Date)-$o.LastBootUpTime).TotalSeconds)";` +
	`foreach($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"){Write-Output "DISK=$($d.DeviceID)|$($d.Size)|$($d.FreeSpace)"};` +
	`foreach($n in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"){Write-Output "NIC=$($n.Description)|$($n.IPAddress -join ',')";if($n.DefaultIPGateway){Write-Output "GW=$($n.DefaultIPGateway -join ',')"}}`

// updatesScript is appended to factsScript when the pending-updates search is due.
// It queries the Windows Update Agent OFFLINE (against the local cache, no round-trip
// to Microsoft — the cheap, scalable equivalent of reading cached apt/dnf metadata) and
// counts pending updates plus the security subset (matched by the locale-independent
// Security Updates category GUID). Wrapped in try/catch so a WUA failure never breaks
// the rest of the fact collection.
const updatesScript = `;try{$us=New-Object -ComObject Microsoft.Update.Session;$se=$us.CreateUpdateSearcher();$se.Online=$false;` +
	`$rs=$se.Search("IsInstalled=0 and IsHidden=0");$sg='0FA1201D-4330-4FA8-8AE9-B877473B6441';$sc=0;` +
	`foreach($u in $rs.Updates){foreach($c in $u.Categories){if($c.CategoryID -eq $sg){$sc++;break}}};` +
	`Write-Output "UPDATES=$($rs.Updates.Count)";Write-Output "SECUPDATES=$sc"}catch{}`

// Collect runs the facts query over WinRM, trying each port in order (5986 HTTPS
// first, then 5985 HTTP), authenticating with NTLM over the given dialer (through the
// jump host). Returns the first success. Server TLS is not verified (WinRM listeners
// use self-signed certs by default) — the connection is already inside the jump-host
// tunnel.
func Collect(ctx context.Context, dial DialFunc, host, user, pass string, ports []int, includeUpdates bool) (*Facts, error) {
	script := factsScript
	if includeUpdates {
		script += updatesScript
	}
	cmd := "powershell.exe -NonInteractive -NoProfile -EncodedCommand " + encodePS(script)
	var lastErr error
	for _, port := range ports {
		ep := &winrm.Endpoint{Host: host, Port: port, HTTPS: port == 5986, Insecure: true, Timeout: 20 * time.Second}
		params := winrm.NewParameters("PT20S", "en-US", 153600)
		params.TransportDecorator = func() winrm.Transporter {
			return winrm.NewClientNTLMWithDial(func(network, addr string) (net.Conn, error) { return dial(network, addr) })
		}
		c, err := winrm.NewClientWithParameters(ep, user, pass, params)
		if err != nil {
			lastErr = err
			continue
		}
		stdout, _, code, err := c.RunWithContextWithString(ctx, cmd, "")
		if err != nil {
			lastErr = err
			continue
		}
		if code != 0 {
			lastErr = fmt.Errorf("winrm command exited %d", code)
			continue
		}
		return parseFacts(stdout), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no winrm ports configured")
	}
	return nil, lastErr
}

// RunScript executes a PowerShell script on a Windows host over WinRM and returns its
// stdout, stderr, and exit code. Unlike Collect (idempotent facts), this may run
// arbitrary/mutating code, so it must execute at most once: it first probes the ports
// (5986 HTTPS, then 5985 HTTP) for the first reachable one and runs the script ONLY on
// that port — never falling back after a connection is established, which could double
// -execute the script. The script is passed via -EncodedCommand so no quoting is needed
// and multi-line scripts work unchanged. Server TLS is not verified (self-signed WinRM
// certs); the connection is already inside the jump-host tunnel.
func RunScript(ctx context.Context, dial DialFunc, host, user, pass string, ports []int, script string, timeout time.Duration) (stdout, stderr string, code int, err error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	// Find the first reachable WinRM port without running anything, so a port
	// fallback can never re-run the script.
	port := 0
	var probeErr error
	for _, p := range ports {
		conn, e := dial("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if e == nil {
			_ = conn.Close()
			port = p
			break
		}
		probeErr = e
	}
	if port == 0 {
		if probeErr == nil {
			probeErr = fmt.Errorf("no winrm ports configured")
		}
		return "", "", -1, fmt.Errorf("no reachable WinRM port: %w", probeErr)
	}

	ep := &winrm.Endpoint{Host: host, Port: port, HTTPS: port == 5986, Insecure: true, Timeout: timeout}
	params := winrm.NewParameters(fmt.Sprintf("PT%dS", int(timeout.Seconds())), "en-US", 153600)
	params.TransportDecorator = func() winrm.Transporter {
		return winrm.NewClientNTLMWithDial(func(network, addr string) (net.Conn, error) { return dial(network, addr) })
	}
	c, err := winrm.NewClientWithParameters(ep, user, pass, params)
	if err != nil {
		return "", "", -1, err
	}
	cmd := "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encodePS(script)
	stdout, stderr, code, err = c.RunWithContextWithString(ctx, cmd, "")
	if err != nil {
		return stdout, stderr, -1, err
	}
	return stdout, stderr, code, nil
}

// UpdateInfo is one missing (not-installed) Windows update with the metadata needed
// to turn it into vulnerability findings: the KB, MSRC severity, whether it's in the
// Security Updates category, and the CVE IDs it remediates.
type UpdateInfo struct {
	KB       string
	Title    string
	Severity string // MsrcSeverity: Critical|Important|Moderate|Low (or "")
	Security bool
	CVEs     []string
}

// updatesDetailScript enumerates missing updates via the Windows Update Agent (OFFLINE
// search against the local cache, like the facts count) and emits one line per update:
//
//	U|<kb(s)>|<msrcSeverity>|<security 0/1>|<cve;cve;...>|<title>
//
// The title is last so it may contain the delimiter. String concatenation (not -f) is
// used so a title with { } braces can't break a format string.
const updatesDetailScript = `$s=New-Object -ComObject Microsoft.Update.Session;$se=$s.CreateUpdateSearcher();$se.Online=$false;` +
	`$r=$se.Search("IsInstalled=0 and IsHidden=0");$sg='0FA1201D-4330-4FA8-8AE9-B877473B6441';` +
	`foreach($u in $r.Updates){$kb=(@($u.KBArticleIDs)|ForEach-Object{"KB"+$_}) -join ';';$sev=[string]$u.MsrcSeverity;` +
	`$sec=0;foreach($c in $u.Categories){if($c.CategoryID -eq $sg){$sec=1;break}};$cves=(@($u.CveIDs)) -join ';';` +
	`Write-Output ("U|"+$kb+"|"+$sev+"|"+$sec+"|"+$cves+"|"+$u.Title)}`

// CollectUpdates returns the host's missing updates with their CVE/severity metadata,
// over WinRM (through the jump-host dialer). Used by the vulnerability scanner: on
// Windows, "vulnerabilities" are the CVEs remediated by not-yet-installed security
// updates, sourced directly from Microsoft's update metadata.
func CollectUpdates(ctx context.Context, dial DialFunc, host, user, pass string, ports []int, timeout time.Duration) ([]UpdateInfo, error) {
	stdout, stderr, code, err := RunScript(ctx, dial, host, user, pass, ports, updatesDetailScript, timeout)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("update search exited %d: %s", code, strings.TrimSpace(stderr))
	}
	var out []UpdateInfo
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "U|") {
			continue
		}
		p := strings.SplitN(line, "|", 6)
		if len(p) < 6 {
			continue
		}
		u := UpdateInfo{KB: strings.TrimSpace(p[1]), Severity: strings.TrimSpace(p[2]), Security: p[3] == "1", Title: strings.TrimSpace(p[5])}
		for _, c := range strings.Split(p[4], ";") {
			if c = strings.TrimSpace(c); c != "" {
				u.CVEs = append(u.CVEs, c)
			}
		}
		out = append(out, u)
	}
	return out, nil
}

func parseFacts(out string) *Facts {
	f := &Facts{}
	var ver, build string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "OS":
			f.OS = v
		case "VER":
			ver = v
		case "BUILD":
			build = v
		case "ARCH":
			f.Architecture = v
		case "CPU":
			f.CPUCount, _ = strconv.Atoi(v)
		case "MEMMB":
			f.MemoryMB, _ = strconv.ParseInt(v, 10, 64)
		case "MEMFREEMB":
			f.MemFreeMB, _ = strconv.ParseInt(v, 10, 64)
		case "UPTIME":
			f.UptimeSeconds, _ = strconv.ParseInt(v, 10, 64)
		case "DISK":
			// "<mount>|<sizeBytes>|<freeBytes>"
			if p := strings.Split(v, "|"); len(p) == 3 {
				sz, _ := strconv.ParseInt(p[1], 10, 64)
				fr, _ := strconv.ParseInt(p[2], 10, 64)
				if sz > 0 {
					f.Disks = append(f.Disks, Disk{Mount: p[0], SizeBytes: sz, FreeBytes: fr})
				}
			}
		case "NIC":
			// "<name>|<ip1>,<ip2>,..."
			name, addrCSV, _ := strings.Cut(v, "|")
			var addrs []string
			for _, a := range strings.Split(addrCSV, ",") {
				if a = strings.TrimSpace(a); a != "" {
					addrs = append(addrs, a)
				}
			}
			if name != "" || len(addrs) > 0 {
				f.Interfaces = append(f.Interfaces, Iface{Name: strings.TrimSpace(name), Addrs: addrs})
			}
		case "GW":
			if f.Gateway == "" {
				f.Gateway = strings.TrimSpace(strings.Split(v, ",")[0])
			}
		case "UPDATES":
			if n, err := strconv.Atoi(v); err == nil {
				f.UpdatesAvailable = &n
			}
		case "SECUPDATES":
			if n, err := strconv.Atoi(v); err == nil {
				f.SecurityUpdates = &n
			}
		}
	}
	f.OSVersion = strings.TrimSpace(ver)
	if build != "" {
		f.OSVersion = strings.TrimSpace(ver + " (Build " + build + ")")
	}
	return f
}

// encodePS UTF-16LE-encodes a PowerShell script and base64s it for -EncodedCommand,
// which sidesteps all command-line quoting.
func encodePS(script string) string {
	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(u16)*2)
	var b [2]byte
	for _, r := range u16 {
		binary.LittleEndian.PutUint16(b[:], r)
		buf = append(buf, b[0], b[1])
	}
	return base64.StdEncoding.EncodeToString(buf)
}
