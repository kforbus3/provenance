package monitor

import (
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/sshgw"
)

// containersCap bounds what is stored per host. A host running more than this
// many containers has a story a longer list will not tell.
const containersCap = 200

// Why a host has no container list. Stored rather than inferred, because the
// interesting cases are indistinguishable from "none" once the list is empty.
const (
	ContainersOK          = "ok"          // asked, answered
	ContainersNoDocker    = "no_docker"   // no container runtime installed
	ContainersNoAccess    = "no_access"   // installed, but the monitor account cannot reach the socket
	ContainersUnreachable = "unreachable" // could not ask at all
)

// containersScript lists running containers, and says why if it cannot.
//
// Three outcomes, kept distinct on purpose. An empty list is a real answer only
// when we were able to ask: Docker's socket is root-owned, this runs WITHOUT
// sudo (as every monitor probe does -- a password prompt in a sweep is not
// acceptable), and on a host where the monitor account is not in the docker
// group `docker ps` fails with a permission error. Reporting that as "no
// containers" would turn an unanswered question into a clean bill of health on
// precisely the hosts that carry the most software.
//
// The digest is what makes the list worth collecting: a tag moves, and "running
// nginx:1.25" says nothing about which nginx:1.25. Vulnerability scanning and
// update detection both key on the digest, so it is collected even though it
// makes the format string longer.
//
// podman is checked too, and is socket-free for a non-root user, so it often
// answers where docker does not.
const containersScript = `
_rt=""
if command -v docker >/dev/null 2>&1; then _rt=docker
elif command -v podman >/dev/null 2>&1; then _rt=podman
fi
if [ -z "$_rt" ]; then echo "::NORUNTIME::"; exit 0; fi
if ! $_rt ps --format '{{.ID}}' >/dev/null 2>&1; then echo "::NOACCESS::"; exit 0; fi
echo "::OK::"
$_rt ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null
echo "::IMAGES::"
$_rt ps --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u | while read -r _i; do
  [ -n "$_i" ] || continue
  _d=$($_rt image inspect --format '{{index .RepoDigests 0}}' "$_i" 2>/dev/null)
  echo "$_i	$_d"
done
`

// collectContainers records what the host is running.
//
// Best-effort and never fatal, like every other probe here: a host that will not
// answer keeps what was collected last rather than having it blanked, because
// "we could not ask" and "nothing is running" are different and must not look
// the same.
func collectContainers(conn *sshgw.Conn, inv *models.HostInventory) {
	out, err := runCmd(conn, containersScript)
	now := time.Now()
	if err != nil {
		inv.ContainersStatus = ContainersUnreachable
		inv.ContainersCheckedAt = &now
		return
	}
	containers, status := parseContainers(out)
	inv.Containers = containers
	inv.ContainersStatus = status
	inv.ContainersCheckedAt = &now
}

// parseContainers turns the script's output into a list and a reason.
func parseContainers(out string) ([]models.Container, string) {
	switch {
	case strings.Contains(out, "::NORUNTIME::"):
		return nil, ContainersNoDocker
	case strings.Contains(out, "::NOACCESS::"):
		return nil, ContainersNoAccess
	case !strings.Contains(out, "::OK::"):
		// No marker at all means the script did not run to completion -- an
		// unreachable host, a shell that died. Not an empty host.
		return nil, ContainersUnreachable
	}

	body, images, _ := strings.Cut(out, "::IMAGES::")
	// image reference -> repo digest, so a moving tag can still be pinned.
	digests := map[string]string{}
	for _, line := range strings.Split(images, "\n") {
		ref, d, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || ref == "" || d == "" {
			continue
		}
		// `image inspect` returns repo@sha256:..., and only the digest is useful.
		if _, sha, found := strings.Cut(d, "@"); found {
			digests[ref] = sha
		}
	}

	var out2 []models.Container
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "::") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		c := models.Container{
			ID:     shortID(f[0]),
			Name:   f[1],
			Image:  f[2],
			State:  f[3],
			Digest: digests[f[2]],
		}
		if len(f) > 4 {
			c.Status = f[4]
		}
		if len(f) > 5 {
			c.Ports = f[5]
		}
		c.Repository, c.Tag = splitImageRef(c.Image)
		out2 = append(out2, c)
		if len(out2) >= containersCap {
			break
		}
	}
	return out2, ContainersOK
}

// shortID trims a full container id to the 12 characters everything displays,
// so the stored value matches what an operator sees in their own `docker ps`.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// splitImageRef separates an image reference into repository and tag.
//
// The colon is not enough on its own: a registry may carry a port, as in
// registry.example.com:5000/app, and splitting on the first colon there gives a
// "tag" of 5000/app. Only a colon AFTER the last slash introduces a tag.
func splitImageRef(ref string) (repo, tag string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		ref = ref[:i] // a digest-pinned reference carries no tag
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	// No tag written means latest, which is what the daemon resolved.
	return ref, "latest"
}
