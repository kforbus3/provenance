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
	UptimeSeconds int64
}

// DialFunc opens a raw TCP connection to addr (e.g. through a jump host).
type DialFunc func(network, addr string) (net.Conn, error)

// factsScript emits KEY=VALUE lines for the facts we surface. Kept to one line so it
// encodes cleanly as a -EncodedCommand.
const factsScript = `$o=Get-CimInstance Win32_OperatingSystem;$s=Get-CimInstance Win32_ComputerSystem;` +
	`$p=(Get-CimInstance Win32_Processor|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;` +
	`Write-Output "OS=$($o.Caption)";Write-Output "VER=$($o.Version)";Write-Output "BUILD=$($o.BuildNumber)";` +
	`Write-Output "ARCH=$($o.OSArchitecture)";Write-Output "CPU=$p";` +
	`Write-Output "MEMMB=$([math]::Round($s.TotalPhysicalMemory/1MB))";` +
	`Write-Output "UPTIME=$([int]((Get-Date)-$o.LastBootUpTime).TotalSeconds)"`

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
		case "UPTIME":
			f.UptimeSeconds, _ = strconv.ParseInt(v, 10, 64)
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
