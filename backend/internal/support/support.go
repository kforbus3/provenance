// Package support collects a host "support bundle": a single gzipped tar of
// diagnostic command outputs (disk, load, memory, network, processes, services,
// pending updates) and recent system logs, gathered over the backend's SSH
// gateway as the privileged `fleet` account (the same path as scans). The
// bundle streams straight back to the operator's browser; nothing is stored.
package support

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/identity"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

// Service collects support bundles from managed hosts.
type Service struct {
	cfg    *config.Config
	log    *slog.Logger
	gw     *sshgw.Gateway
	issuer *identity.Issuer
}

func New(cfg *config.Config, log *slog.Logger, gw *sshgw.Gateway, issuer *identity.Issuer) *Service {
	return &Service{cfg: cfg, log: log, gw: gw, issuer: issuer}
}

// dial opens a privileged connection to the host (WireGuard overlay first, then
// management address/hostname), exactly as the scan path does.
func (s *Service) dial(ctx context.Context, h *models.Host) (*sshgw.Conn, error) {
	signer, err := s.issuer.SystemSigner(ctx, s.issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("system signer: %w", err)
	}
	var lastErr error
	for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
		conn, derr := s.gw.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address")
	}
	return nil, lastErr
}

// Collect runs the collection script on the host and streams the resulting
// gzipped tar to w. It is bounded by ctx (kill the remote command on timeout).
func (s *Service) Collect(ctx context.Context, h *models.Host, w io.Writer) error {
	conn, err := s.dial(ctx, h)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	sess, err := conn.Client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdout = w // the script writes ONLY the tar.gz to stdout
	var stderr bytes.Buffer
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run("sudo sh -c " + shellQuote(collectScript)) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("collect: %v: %s", err, trunc(stderr.String()))
		}
		return nil
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func trunc(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// collectScript gathers diagnostics into a temp dir and emits a gzipped tar on
// stdout. Each command's output goes to its own file (so stdout stays pure
// binary); logs are tail-bounded to keep the bundle small. Run under sudo so
// privileged logs (auth, journal) are readable.
const collectScript = `set +e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
D=$(mktemp -d /tmp/fleet-support.XXXXXX) || exit 1
SH() { f="$D/$1"; shift; printf '$ %s\n\n' "$*" > "$f"; sh -c "$*" >> "$f" 2>&1; }

SH 00-summary.txt 'echo "hostname: $(hostname)"; echo "collected: $(date -u) UTC"; echo "kernel: $(uname -a)"; (. /etc/os-release 2>/dev/null; echo "os: $PRETTY_NAME")'
SH 10-uptime.txt 'uptime; echo; echo "loadavg: $(cat /proc/loadavg)"'
SH 11-cpu.txt 'lscpu 2>/dev/null || cat /proc/cpuinfo'
SH 12-memory.txt 'free -h; echo; head -20 /proc/meminfo'
SH 13-top.txt 'top -bn1 2>/dev/null | head -45'
SH 14-vmstat.txt 'vmstat 1 3 2>/dev/null'
SH 20-disk-df.txt 'df -h; echo "== inodes =="; df -hi'
SH 21-lsblk.txt 'lsblk 2>/dev/null'
SH 22-mounts.txt 'mount'
SH 23-disk-usage.txt 'du -xhd1 / 2>/dev/null | sort -rh | head -25'
SH 30-net-addr.txt 'ip -o addr 2>/dev/null || ifconfig -a'
SH 31-net-route.txt 'ip route 2>/dev/null; echo; ip -6 route 2>/dev/null'
SH 32-net-listen.txt 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null'
SH 33-net-link.txt 'ip -s link 2>/dev/null | head -80'
SH 34-dns-hosts.txt 'echo "== resolv.conf =="; cat /etc/resolv.conf 2>/dev/null; echo; echo "== hosts =="; cat /etc/hosts 2>/dev/null'
SH 40-ps-by-cpu.txt 'ps aux --sort=-%cpu 2>/dev/null | head -40'
SH 41-ps-by-mem.txt 'ps aux --sort=-%mem 2>/dev/null | head -40'
SH 50-systemd-failed.txt 'systemctl --failed --no-pager 2>/dev/null'
SH 51-systemd-status.txt 'systemctl status --no-pager 2>/dev/null | head -80'
SH 52-running-services.txt 'systemctl list-units --type=service --state=running --no-pager 2>/dev/null'
SH 60-pending-updates.txt 'apt list --upgradable 2>/dev/null || dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null'
SH 61-logins.txt 'last -n 30 2>/dev/null; echo; echo "== who =="; w 2>/dev/null'
SH 70-wireguard.txt 'wg show 2>/dev/null'
SH 71-firewall.txt 'nft list ruleset 2>/dev/null | head -120 || iptables -S 2>/dev/null'

mkdir -p "$D/logs"
for f in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log; do
  [ -f "$f" ] && tail -c 3000000 "$f" > "$D/logs/$(basename "$f")" 2>/dev/null
done
journalctl -n 5000 --no-pager > "$D/logs/journal.log" 2>/dev/null
dmesg -T 2>/dev/null | tail -n 2000 > "$D/logs/dmesg.log" 2>/dev/null

tar czf "$D.tgz" -C "$D" . 2>/dev/null
cat "$D.tgz"
rm -rf "$D" "$D.tgz"
`
