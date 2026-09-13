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
// containersScript lists running containers, and says why if it cannot.
//
// The "why" is the part worth the extra lines. "no_access" on its own tells an
// operator that something is wrong and nothing about what to do, and the two
// causes need opposite actions: a socket they are not in the group for is a
// one-line fix, and a daemon that is not running is a different problem
// entirely. Six hosts on a nineteen-host fleet said no_access with no way to
// tell which, so the probe now reports what it actually found — the socket, its
// group, and the daemon's stderr — rather than leaving that to be worked out
// host by host over SSH.
// ContainersScript is the collection script, exported so work that has just
// CHANGED a host's containers can re-read them immediately instead of waiting
// for the next sweep.
//
// One script and one parser, deliberately. A second implementation drifts from
// this one, and the two would disagree about what a host is running -- which is
// the question this whole feature turns on.
const ContainersScript = containersScript

const containersScript = `
_detail=""
_sock=/var/run/docker.sock
[ -S "$_sock" ] || _sock=/run/docker.sock
_rt=""
if command -v docker >/dev/null 2>&1; then _rt=docker
elif command -v podman >/dev/null 2>&1; then _rt=podman
fi

if [ -z "$_rt" ]; then
  # No CLI. That is not the same as no containers: the daemon may be running and
  # only the client missing, which is a different (and much smaller) fix.
  if [ -S "$_sock" ]; then
    _detail="a container socket exists at $_sock but no docker or podman command is installed for this account"
  elif pgrep -x dockerd >/dev/null 2>&1 || pgrep -x containerd >/dev/null 2>&1; then
    _detail="a container daemon is running but no docker or podman command is installed for this account"
  else
    _detail="no container runtime is installed"
  fi
  echo "::NORUNTIME::$_detail"
  exit 0
fi

# Unprivileged first. The docker socket is root-owned, so on most hosts this only
# works for an account in its group -- which is a root-equivalent membership that
# nobody should have to grant just to be able to SEE what is running.
_pre=""
if ! $_rt ps --format '{{.ID}}' >/dev/null 2>&1; then
  # Then non-interactive sudo, if this account has it. -n so a host that would
  # PROMPT fails immediately instead of hanging a sweep on a password nobody is
  # there to type. Read-only either way: ps and image inspect.
  if command -v sudo >/dev/null 2>&1 && sudo -n $_rt ps --format '{{.ID}}' >/dev/null 2>&1; then
    _pre="sudo -n"
  else
    _err=$($_rt ps --format '{{.ID}}' 2>&1 >/dev/null)
    if [ -S "$_sock" ]; then
      _grp=$(stat -c '%G' "$_sock" 2>/dev/null || echo "?")
      _detail="$(id -un) cannot use $_sock and has no passwordless sudo here. Either add this account to group $_grp (usermod -aG $_grp $(id -un)) or give it NOPASSWD sudo for docker. Error: $_err"
    else
      _detail="no socket at $_sock — the daemon may not be running, or may be rootless or remote (DOCKER_HOST=${DOCKER_HOST:-unset}): $_err"
    fi
    echo "::NOACCESS::$_detail"
    exit 0
  fi
fi
echo "::OK::"
$_pre $_rt ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null
echo "::IMAGES::"
$_pre $_rt ps --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u | while read -r _i; do
  [ -n "$_i" ] || continue
  _d=$($_pre $_rt image inspect --format '{{index .RepoDigests 0}}' "$_i" 2>/dev/null)
  # printf, not echo. Whether echo expands \t depends on the shell: dash does,
  # bash does not. On a bash host this line emitted a literal backslash-t, the
  # parser found no tab, and EVERY digest was dropped -- which silently turned off
  # rebuild detection, container vulnerability scanning (which is keyed by digest),
  # and update checking, since an image with no digest is treated as built locally
  # and never asked about.
  printf '%s\t%s\n' "$_i" "$_d"
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
	containers, status, detail := parseContainers(out)
	inv.Containers = containers
	inv.ContainersStatus = status
	inv.ContainersDetail = detail
	inv.ContainersCheckedAt = &now
}

// parseContainers turns the script's output into a list, a reason, and the
// detail behind that reason.
// ParseContainers reads what ContainersScript produced. See ContainersScript.
func ParseContainers(out string) ([]models.Container, string, string) {
	return parseContainers(out)
}

func parseContainers(out string) ([]models.Container, string, string) {
	switch {
	case strings.Contains(out, "::NORUNTIME::"):
		return nil, ContainersNoDocker, markerDetail(out, "::NORUNTIME::")
	case strings.Contains(out, "::NOACCESS::"):
		return nil, ContainersNoAccess, markerDetail(out, "::NOACCESS::")
	case !strings.Contains(out, "::OK::"):
		// No marker at all means the script did not run to completion -- an
		// unreachable host, a shell that died. Not an empty host.
		return nil, ContainersUnreachable, ""
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
		if len(f) > 8 {
			c.ComposeProject, c.ComposeService, c.ComposeDir = f[6], f[7], f[8]
		}
		c.Repository, c.Tag = splitImageRef(c.Image)
		out2 = append(out2, c)
		if len(out2) >= containersCap {
			break
		}
	}
	return out2, ContainersOK, ""
}

// markerDetail returns the rest of the line a marker appears on.
func markerDetail(out, marker string) string {
	i := strings.Index(out, marker)
	if i < 0 {
		return ""
	}
	rest := out[i+len(marker):]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[:j]
	}
	if d := strings.TrimSpace(rest); len(d) > 400 {
		return d[:400]
	} else {
		return d
	}
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
