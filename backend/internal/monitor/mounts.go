package monitor

import (
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
)

// networkMountsCap bounds what is stored per host. A host with more than this many
// network mounts is an automounter, and a longer list helps nobody.
const networkMountsCap = 50

// mountsScript reports network mounts and whether the host is virtualised.
//
// /proc/self/mounts rather than `mount` or `findmnt`: it is the kernel's own table,
// present on every Linux, needs no root and no package. systemd-detect-virt is
// asked for separately and allowed to be missing -- its absence is not an error,
// it is an older or non-systemd host.
//
// The marker line keeps the two answers apart without a second round trip, because
// this runs in the monitor sweep against every host.
const mountsScript = `
cat /proc/self/mounts 2>/dev/null || cat /proc/mounts 2>/dev/null
echo '---virt---'
systemd-detect-virt 2>/dev/null || true
`

// networkFSTypes are the filesystems that mean "this data lives on another machine".
//
// Deliberately a list rather than a "not local" rule: the point is to name a server
// that another host could be, and a fuse mount or an overlay has no server to name.
var networkFSTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"glusterfs": true, "ceph": true, "beegfs": true, "lustre": true, "afs": true,
}

// collectNetworkMounts records what the host mounts from elsewhere, and what it
// reports running on.
//
// Best-effort and never fatal, like every other collector here: a host that will
// not answer keeps what was collected last, because "we could not ask" and "nothing
// is mounted" must not look the same -- the second would quietly withdraw the
// evidence behind a storage dependency.
func collectNetworkMounts(conn *sshgw.Conn, inv *models.HostInventory) {
	out, err := runCmd(conn, mountsScript)
	if err != nil {
		return
	}
	mounts, virt := parseMounts(out)
	now := time.Now()
	inv.NetworkMounts = mounts
	inv.MountsCheckedAt = &now
	inv.Virtualisation = virt
}

// parseMounts reads the /proc mount table and the virtualisation marker.
//
// Split out from the collection so it can be tested against real mount tables from
// every filesystem that spells its source differently, without a host.
func parseMounts(out string) ([]models.NetworkMount, string) {
	table, virt, _ := strings.Cut(out, "---virt---")
	mounts := []models.NetworkMount{}
	seen := map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		source, target, fstype := f[0], f[1], f[2]
		if !networkFSTypes[strings.ToLower(fstype)] {
			continue
		}
		server := mountServer(source)
		if server == "" {
			continue
		}
		key := source + " " + target
		if seen[key] {
			continue
		}
		seen[key] = true
		mounts = append(mounts, models.NetworkMount{
			// The kernel escapes spaces in paths as \040. Left as the kernel wrote
			// it in Source, which is what a person would grep for, and decoded in
			// Target, which is a path the UI prints.
			Source: source,
			Server: server,
			Target: unescapeMountPath(target),
			FSType: strings.ToLower(fstype),
		})
		if len(mounts) >= networkMountsCap {
			break
		}
	}
	v := strings.TrimSpace(virt)
	if v == "none" {
		v = ""
	}
	return mounts, v
}

// mountServer pulls the server out of a mount source.
//
// Every network filesystem spells it differently, and guessing wrong does not fail
// visibly -- it invents a dependency on a host that happens to share the name of a
// path component:
//
//	nfs/nfs4   nas:/tank/media        or  [fd00::1]:/export
//	cifs/smb   //nas/share            or  \\nas\share
//	ceph       mon1,mon2:/            or  1.2.3.4:6789:/
//	glusterfs  nas:/volume
func mountServer(source string) string {
	s := strings.TrimSpace(source)
	// SMB, in either slash direction.
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, `\\`) {
		s = strings.ReplaceAll(s[2:], `\`, "/")
		host, _, _ := strings.Cut(s, "/")
		return strings.ToLower(host)
	}
	// A bracketed IPv6 literal: "[fd00::1]:/export".
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 1 {
			return strings.ToLower(s[1:end])
		}
		return ""
	}
	// Everything else is host[:port]:/path. Take the first field, and for ceph's
	// comma-separated monitor list the first monitor.
	host, rest, ok := strings.Cut(s, ":")
	if !ok || host == "" || rest == "" {
		return "" // no server named: a local or bind mount that slipped the fstype filter
	}
	if first, _, found := strings.Cut(host, ","); found {
		host = first
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// unescapeMountPath decodes the octal escapes the kernel writes for characters that
// would otherwise break the field separation.
func unescapeMountPath(p string) string {
	for from, to := range map[string]string{`\040`: " ", `\011`: "\t", `\012`: "\n", `\134`: `\`} {
		p = strings.ReplaceAll(p, from, to)
	}
	return p
}
