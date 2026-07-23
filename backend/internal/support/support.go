// Package support collects a host "support bundle": a single gzipped tar of
// diagnostic command outputs (system, CPU/memory/pressure, disk + filesystems +
// SMART + RAID + I/O, network + DNS + time sync, processes, services + timers +
// cron + boot analysis, updates + package health, security posture, hardware +
// containers) and recent system/error/boot logs, gathered over the backend's SSH
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
// stdout. Each command's output goes to its own numbered file (so stdout stays
// pure binary); logs are tail-bounded to keep the bundle small. Everything is
// best-effort — a missing tool just records "command not found" in its file
// rather than failing the bundle. Run under sudo so privileged config and logs
// (sshd -T, auth log, journal, dmidecode) are readable. The set is intended to
// cover what a support agent typically requests up front when troubleshooting:
// system/CPU/memory/pressure, disk + filesystems + SMART + RAID + I/O, network +
// DNS + time sync, processes, services + timers + cron + boot analysis, updates +
// package-manager health, security posture (SELinux/AppArmor, sshd config,
// sudo/privileges, accounts), hardware/virtualization/sensors, containers, and
// the recent system + error + boot logs.
const collectScript = `set +e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
D=$(mktemp -d /tmp/fleet-support.XXXXXX) || exit 1
SH() { f="$D/$1"; shift; printf '$ %s\n\n' "$*" > "$f"; sh -c "$*" >> "$f" 2>&1; }

SH 00-summary.txt 'echo "hostname: $(hostname)"; echo "collected: $(date -u) UTC"; echo "kernel: $(uname -a)"; (. /etc/os-release 2>/dev/null; echo "os: $PRETTY_NAME"); echo "virt: $(systemd-detect-virt 2>/dev/null)"; echo "uptime:$(uptime 2>/dev/null)"'
SH 10-uptime.txt 'uptime; echo; echo "loadavg: $(cat /proc/loadavg)"; echo; echo "== last boot =="; who -b 2>/dev/null; echo "== recent reboots =="; last reboot 2>/dev/null | head -15'
SH 11-cpu.txt 'lscpu 2>/dev/null || cat /proc/cpuinfo'
SH 12-memory.txt 'free -h; echo; head -25 /proc/meminfo; echo; echo "== swap =="; swapon --show 2>/dev/null; cat /proc/swaps 2>/dev/null'
SH 13-top.txt 'top -bn1 2>/dev/null | head -50'
SH 14-vmstat.txt 'vmstat 1 3 2>/dev/null'
SH 15-pressure.txt 'echo "== /proc/pressure (PSI: cpu/memory/io stall) =="; for r in cpu memory io; do echo "-- $r --"; cat /proc/pressure/$r 2>/dev/null; done'
SH 16-limits.txt 'echo "== ulimit -a =="; ulimit -a; echo; echo "== open file handles (file-nr: allocated / free / max) =="; cat /proc/sys/fs/file-nr 2>/dev/null'
SH 20-disk-df.txt 'df -h; echo "== inodes =="; df -hi'
SH 21-lsblk.txt 'lsblk 2>/dev/null'
SH 22-mounts.txt 'mount'
SH 23-disk-usage.txt 'du -xhd1 / 2>/dev/null | sort -rh | head -25'
SH 24-blk-fs.txt 'echo "== lsblk -f =="; lsblk -f 2>/dev/null; echo; echo "== blkid =="; blkid 2>/dev/null; echo; echo "== /etc/fstab =="; cat /etc/fstab 2>/dev/null'
SH 25-smart.txt 'echo "== smartctl --scan =="; smartctl --scan 2>/dev/null; for d in /dev/sd? /dev/nvme?n1; do [ -e "$d" ] || continue; echo; echo "== $d =="; smartctl -H -A "$d" 2>/dev/null | head -45; done'
SH 26-raid.txt 'echo "== /proc/mdstat =="; cat /proc/mdstat 2>/dev/null; echo; echo "== mdadm --detail --scan =="; mdadm --detail --scan 2>/dev/null; echo; echo "== zpool status =="; zpool status 2>/dev/null'
SH 27-io.txt 'iostat -xz 1 2 2>/dev/null; echo; echo "== /proc/diskstats =="; cat /proc/diskstats 2>/dev/null'
SH 30-net-addr.txt 'ip -o addr 2>/dev/null || ifconfig -a'
SH 31-net-route.txt 'ip route 2>/dev/null; echo; ip -6 route 2>/dev/null'
SH 32-net-listen.txt 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null'
SH 33-net-link.txt 'ip -s link 2>/dev/null | head -80'
SH 34-dns-hosts.txt 'echo "== resolv.conf =="; cat /etc/resolv.conf 2>/dev/null; echo; echo "== hosts =="; cat /etc/hosts 2>/dev/null; echo; echo "== nsswitch =="; cat /etc/nsswitch.conf 2>/dev/null'
SH 35-net-errors.txt 'echo "== interface counters/errors =="; netstat -i 2>/dev/null || ip -s -s link 2>/dev/null | head -80; echo; echo "== socket summary =="; ss -s 2>/dev/null'
SH 36-time-sync.txt 'echo "== timedatectl =="; timedatectl 2>/dev/null; echo; echo "== chrony =="; chronyc tracking 2>/dev/null; chronyc sources 2>/dev/null; echo; echo "== ntpd =="; ntpq -pn 2>/dev/null'
SH 40-ps-by-cpu.txt 'ps aux --sort=-%cpu 2>/dev/null | head -40'
SH 41-ps-by-mem.txt 'ps aux --sort=-%mem 2>/dev/null | head -40'
SH 50-systemd-failed.txt 'systemctl --failed --no-pager 2>/dev/null'
SH 51-systemd-status.txt 'systemctl status --no-pager 2>/dev/null | head -80'
SH 52-running-services.txt 'systemctl list-units --type=service --state=running --no-pager 2>/dev/null'
SH 53-systemd-timers.txt 'systemctl list-timers --all --no-pager 2>/dev/null'
SH 54-cron.txt 'echo "== root crontab =="; crontab -l 2>/dev/null; echo; echo "== /etc/crontab =="; cat /etc/crontab 2>/dev/null; echo; echo "== cron dirs =="; ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null'
SH 55-boot-analysis.txt 'systemd-analyze 2>/dev/null; echo; echo "== blame (slowest units) =="; systemd-analyze blame 2>/dev/null | head -20'
SH 60-pending-updates.txt 'apt list --upgradable 2>/dev/null || dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null'
SH 61-logins.txt 'echo "== last -n 30 =="; last -n 30 2>/dev/null; echo; echo "== who =="; w 2>/dev/null'
SH 62-pkg-health.txt 'echo "== held packages =="; apt-mark showhold 2>/dev/null; echo; echo "== apt check =="; apt-get -s check 2>/dev/null | tail -5; echo; echo "== configured repositories =="; grep -rhE "^deb |^https?:" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null | head -40; dnf repolist 2>/dev/null; yum repolist 2>/dev/null'
SH 70-wireguard.txt 'wg show 2>/dev/null'
SH 71-firewall.txt 'nft list ruleset 2>/dev/null | head -140 || iptables -S 2>/dev/null'
SH 72-selinux-apparmor.txt 'echo "== SELinux =="; getenforce 2>/dev/null; sestatus 2>/dev/null; echo; echo "== AppArmor =="; aa-status 2>/dev/null | head -30'
SH 73-sshd-config.txt 'sshd -T 2>/dev/null | sort'
SH 74-privileges.txt 'echo "== sudo/wheel groups =="; getent group sudo 2>/dev/null; getent group wheel 2>/dev/null; echo; echo "== sudoers.d =="; ls -la /etc/sudoers.d 2>/dev/null; echo; echo "== NOPASSWD rules =="; grep -rhE "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null'
SH 75-accounts.txt 'echo "== accounts that can log in =="; grep -vE "nologin|/false|/sync|/halt|/shutdown" /etc/passwd 2>/dev/null | head -60; echo; echo "== recent lastlog =="; lastlog 2>/dev/null | grep -v Never | head -30'
SH 80-modules.txt 'echo "kernel release: $(uname -r)"; echo; echo "== lsmod =="; lsmod 2>/dev/null | head -60'
SH 81-hardware.txt 'echo "== virtualization =="; systemd-detect-virt 2>/dev/null; echo; echo "== dmidecode (system/bios) =="; dmidecode -t system -t bios 2>/dev/null; echo; echo "== sensors =="; sensors 2>/dev/null; echo; echo "== lspci =="; lspci 2>/dev/null | head -40'
SH 82-containers.txt 'if command -v docker >/dev/null 2>&1; then echo "== docker ps -a =="; docker ps -a 2>/dev/null; echo; echo "== docker system df =="; docker system df 2>/dev/null; echo; echo "== docker images =="; docker images 2>/dev/null | head -30; fi; if command -v podman >/dev/null 2>&1; then echo "== podman ps -a =="; podman ps -a 2>/dev/null; fi'

mkdir -p "$D/logs"
for f in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log /var/log/dpkg.log; do
  [ -f "$f" ] && tail -c 3000000 "$f" > "$D/logs/$(basename "$f")" 2>/dev/null
done
journalctl -n 5000 --no-pager > "$D/logs/journal.log" 2>/dev/null
journalctl -p err -b --no-pager 2>/dev/null | tail -n 2000 > "$D/logs/journal-errors.log" 2>/dev/null
journalctl --list-boots --no-pager 2>/dev/null | tail -n 20 > "$D/logs/journal-boots.log" 2>/dev/null
dmesg -T 2>/dev/null | tail -n 2000 > "$D/logs/dmesg.log" 2>/dev/null

tar czf "$D.tgz" -C "$D" . 2>/dev/null
cat "$D.tgz"
rm -rf "$D" "$D.tgz"
`
