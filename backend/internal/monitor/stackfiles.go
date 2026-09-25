package monitor

import (
	"context"
	"strconv"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// maxStackFileBytes bounds what one compose file read may return. Real ones are a
// few kilobytes; this only stops a wrong path from streaming something enormous.
const maxStackFileBytes = 1 << 20

// checkStackFiles reads each managed stack's compose file on this host and records
// its hash, so drift can see a change made on the host at the same revision.
//
// Only the hash is stored. The file is read with sudo because stacks live in
// directories the login user may not own (/root/aptlywebui), and a compose file can
// carry credentials -- which is exactly why its contents stay here, in memory, for
// as long as it takes to hash them.
//
// Runs on the container cadence rather than every probe: a compose file changes when
// somebody edits it, not every thirty seconds.
func (m *Monitor) checkStackFiles(ctx context.Context, conn *sshgw.Conn, h *models.Host) {
	if m.store == nil {
		return
	}
	hid := h.ID
	stacks, err := m.store.ListStacks(ctx, &hid)
	if err != nil {
		m.log.Warn("monitor: listing stacks", "host", h.Hostname, "err", err)
		return
	}
	for _, st := range stacks {
		sha, readErr := readStackFile(conn, st.Path)
		if err := m.store.RecordStackHostFile(ctx, st.ID, sha, readErr); err != nil {
			m.log.Warn("monitor: recording stack file", "host", h.Hostname, "stack", st.Name, "err", err)
		}
	}
}

// readStackFile returns the ComposeHash of dir/docker-compose.yml on the host, or the
// reason it could not be read.
func readStackFile(conn *sshgw.Conn, dir string) (sha, readErr string) {
	path := strings.TrimRight(dir, "/") + "/docker-compose.yml"
	// Directly first: most stacks are readable by the login user, and not every
	// host gives it passwordless sudo. sudo only for the ones that need it.
	read := "head -c " + strconv.Itoa(maxStackFileBytes) + " -- " + shQuote(path)
	out, err := runCmd(conn, read+" 2>/dev/null || sudo -n "+read)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		return "", trunc("could not read "+path+": "+msg, 240)
	}
	return store.ComposeHash(out), ""
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
