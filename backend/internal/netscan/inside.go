package netscan

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/monitor"
)

// The inside view: what the host itself says it has bound.
//
// The host monitor collects the same `ss` list on its own schedule, but the network
// scan needs it NOW -- the diff between "listening" and "reachable" is only
// meaningful when both are measured at the same time -- and it needs two things the
// monitor does not collect: the package that owns each listening binary, and the
// packages of the libraries that process has loaded. Those are what let a grype
// finding in libssl3 be marked as exposed through nginx on 443, rather than read as
// one more CVE in an installed library.

// listenerInnerScript runs as root when the scan principal may sudo without a
// password, and as itself otherwise (process ownership is then partial, which is
// reported, not fatal). Bounded everywhere: this runs on every scanned host.
const listenerInnerScript = `LC_ALL=C
export LC_ALL
if command -v ss >/dev/null 2>&1; then
  ss -lntupH 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntup 2>/dev/null | tail -n +3
fi
echo '#--'
pids=$(ss -lntupH 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un | head -64)
files=""
for p in $pids; do
  exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
  printf '#proc\t%s\t%s\n' "$p" "$exe"
  exe=${exe% (deleted)}
  files="$files
$exe"
  for l in $(awk '$6 ~ /\.so/ {print $6}' "/proc/$p/maps" 2>/dev/null | sort -u | head -150); do
    printf '#lib\t%s\t%s\n' "$p" "$l"
    files="$files
$l"
  done
done
printf '%s\n' "$files" | sed '/^$/d' | sort -u | head -400 | while IFS= read -r f; do
  pkg=""
  if command -v dpkg-query >/dev/null 2>&1; then
    # Merged /usr: dpkg may know the file by either spelling.
    pkg=$( (dpkg-query -S "$f" 2>/dev/null || dpkg-query -S "${f#/usr}" 2>/dev/null || dpkg-query -S "/usr$f" 2>/dev/null) | head -1 | cut -d: -f1)
  elif command -v rpm >/dev/null 2>&1; then
    pkg=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -1)
    case "$pkg" in *"not owned"*|"") pkg="" ;; esac
  fi
  [ -n "$pkg" ] && printf '#own\t%s\t%s\n' "$f" "$pkg"
done
`

// listenerScript wraps the inner script so it runs under sudo where that is allowed
// without a prompt. Passed as base64 so no quoting survives into a second shell.
func listenerScript() string {
	b := base64.StdEncoding.EncodeToString([]byte(listenerInnerScript))
	return `if sudo -n true 2>/dev/null; then echo ` + b + ` | base64 -d | sudo -n sh; ` +
		`else echo ` + b + ` | base64 -d | sh; fi`
}

// parseListeners reads listenerScript's output into listeners with their owners.
func parseListeners(out string) []models.NetListener {
	head, tail, _ := strings.Cut(out, "#--")
	exeOf := map[int]string{}
	libsOf := map[int][]string{}
	owner := map[string]string{}
	for _, line := range strings.Split(tail, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		switch {
		case len(f) == 3 && f[0] == "#proc":
			if pid, err := strconv.Atoi(f[1]); err == nil {
				exeOf[pid] = strings.TrimSuffix(f[2], " (deleted)")
			}
		case len(f) == 3 && f[0] == "#lib":
			if pid, err := strconv.Atoi(f[1]); err == nil {
				libsOf[pid] = append(libsOf[pid], f[2])
			}
		case len(f) == 3 && f[0] == "#own":
			owner[f[1]] = f[2]
		}
	}

	out2 := []models.NetListener{}
	for _, line := range strings.Split(head, "\n") {
		ports := monitor.ParseListeningPorts(line)
		if len(ports) != 1 {
			continue
		}
		p := ports[0]
		l := models.NetListener{
			Proto: p.Proto, Address: p.Address, Port: p.Port, Process: p.Process, Exposed: p.Exposed,
			PID: pidOf(line),
		}
		if l.PID > 0 {
			l.Exe = exeOf[l.PID]
			l.Package = owner[l.Exe]
			seen := map[string]bool{}
			for _, lib := range libsOf[l.PID] {
				if pkg := owner[lib]; pkg != "" && pkg != l.Package && !seen[pkg] {
					seen[pkg] = true
					l.LibPackages = append(l.LibPackages, pkg)
				}
			}
			sort.Strings(l.LibPackages)
		}
		out2 = append(out2, l)
	}
	return out2
}

// pidOf pulls the first pid out of ss's users:(("name",pid=123,fd=3)) field.
func pidOf(line string) int {
	i := strings.Index(line, "pid=")
	if i < 0 {
		return 0
	}
	rest := line[i+4:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	n, _ := strconv.Atoi(rest[:j])
	return n
}

// windowsListenerScript lists listening TCP sockets and UDP endpoints with the
// owning process. Tab-separated; one socket per line.
const windowsListenerScript = `$ErrorActionPreference = 'SilentlyContinue'
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_ }
Get-NetTCPConnection -State Listen | ForEach-Object {
  $p = $procs[[int]$_.OwningProcess]
  "tcp` + "`t" + `$($_.LocalAddress)` + "`t" + `$($_.LocalPort)` + "`t" + `$($_.OwningProcess)` + "`t" + `$($p.ProcessName)` + "`t" + `$($p.Path)"
}
Get-NetUDPEndpoint | ForEach-Object {
  $p = $procs[[int]$_.OwningProcess]
  "udp` + "`t" + `$($_.LocalAddress)` + "`t" + `$($_.LocalPort)` + "`t" + `$($_.OwningProcess)` + "`t" + `$($p.ProcessName)` + "`t" + `$($p.Path)"
}
`

func parseWindowsListeners(out string) []models.NetListener {
	seen := map[string]bool{}
	res := []models.NetListener{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 3 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(f[2]))
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		addr := strings.TrimSpace(f[1])
		key := f[0] + "|" + addr + "|" + f[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		l := models.NetListener{Proto: f[0], Address: addr, Port: port, Exposed: !isLoopback(addr)}
		if len(f) > 3 {
			l.PID, _ = strconv.Atoi(strings.TrimSpace(f[3]))
		}
		if len(f) > 4 {
			l.Process = strings.TrimSpace(f[4])
		}
		if len(f) > 5 {
			l.Exe = strings.TrimSpace(f[5])
		}
		res = append(res, l)
		if len(res) >= 400 {
			break
		}
	}
	return res
}

func isLoopback(addr string) bool {
	a := strings.Trim(addr, "[]")
	return a == "::1" || strings.HasPrefix(a, "127.")
}
