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

// Collect runs the facts query over WinRM, trying each port in order (5986 HTTPS
// first, then 5985 HTTP), authenticating with NTLM over the given dialer (through the
// jump host). Returns the first success. Server TLS is not verified (WinRM listeners
// use self-signed certs by default) — the connection is already inside the jump-host
// tunnel.
func Collect(ctx context.Context, dial DialFunc, host, user, pass string, ports []int) (*Facts, error) {
	cmd := "powershell.exe -NonInteractive -NoProfile -EncodedCommand " + encodePS(factsScript)
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
