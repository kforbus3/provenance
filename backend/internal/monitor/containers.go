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
$_pre $_rt ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.Label "com.docker.compose.project.config_files"}}' 2>/dev/null
echo "::IMAGES::"
$_pre $_rt ps --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u | while read -r _i; do
  [ -n "$_i" ] || continue
  # EVERY digest, not the first. RepoDigests is a list, and an image answers to
  # more than one whenever a registry republishes a multi-arch index over unchanged
  # layers: the same bytes gain a second index digest, and a host that pulled the tag
  # before and after holds both. Docker does not order them by recency, so [0] is
  # arbitrary -- and picking the stale one makes an up-to-date host look behind
  # forever, offering an update that has already been applied and failing every
  # rollout sent to fix it.
  _d=$($_pre $_rt image inspect --format '{{range .RepoDigests}}{{.}},{{end}}' "$_i" 2>/dev/null)
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
	digests := map[string][]string{}
	for _, line := range strings.Split(images, "\n") {
		ref, list, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || ref == "" || list == "" {
			continue
		}
		// A comma-separated list, terminated by a trailing comma from the template
		// that produced it. `image inspect` returns repo@sha256:..., and only the
		// digest part is useful.
		for _, d := range strings.Split(list, ",") {
			if _, sha, found := strings.Cut(strings.TrimSpace(d), "@"); found && sha != "" {
				digests[ref] = append(digests[ref], sha)
			}
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
		all := digests[f[2]]
		c := models.Container{
			ID:      shortID(f[0]),
			Name:    f[1],
			Image:   f[2],
			State:   f[3],
			Digests: all,
		}
		// Digest stays the single value everything already reads and displays. It is
		// the FIRST of the list, which is what this recorded before -- what changed is
		// that the others are no longer thrown away, so a comparison can ask whether
		// the image answers to a digest rather than whether one arbitrary entry does.
		if len(all) > 0 {
			c.Digest = all[0]
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
		// The project's own file list, comma-separated by compose. Order is kept:
		// compose merges overlays left to right, and the order decides which
		// definition of a service wins.
		if len(f) > 9 {
			for _, path := range strings.Split(f[9], ",") {
				if path = strings.TrimSpace(path); path != "" {
					c.ComposeFiles = append(c.ComposeFiles, path)
				}
			}
		}
		c.Repository, c.Tag = splitImageRef(c.Image)
		out2 = append(out2, c)
		if len(out2) >= containersCap {
			break
		}
	}
	// An answered check with nothing running is an EMPTY list, never nil. Both
	// writers read nil as "not collected" and keep the previous list -- which is
	// right for a host that could not be asked, and wrong for one that said
	// "nothing". The difference was invisible until a host's last container
	// stopped: coder's crash-looping docker-frontend-1 was stopped on 2026-09-25,
	// and Provenance went on reporting it "restarting in a loop" every sweep,
	// because the empty answer kept the list that still had it.
	if out2 == nil {
		out2 = []models.Container{}
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
	// An image with no repository tags at all. `docker ps` reports those by ID --
	// "sha256:60b1fa07833c…" -- and splitting on the colon produced a repository
	// called "sha256" with a 64-character hex "tag", which then went to the
	// registry to be asked whether a newer sha256:60b1fa07833c… was available.
	//
	// It reached production: a row reading `sha256 | 60b1fa0783…` sat at the top of
	// the Updates page, above the real images, permanently unanswerable. This
	// happens to any image whose tag has been removed or replaced -- an ordinary
	// consequence of rebuilding a local image under the same name.
	//
	// Reported as having neither repository nor tag, which is the truth of it. The
	// container still appears in inventory under its image ID; it is registry
	// checks and rollouts that have nothing to work with, and both select on a
	// non-empty repository and tag.
	if isImageID(ref) {
		return "", ""
	}
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

// isImageID reports whether a reference is a bare image ID rather than a name:
// "sha256:" and 64 hex characters, or the digest alone.
func isImageID(ref string) bool {
	hex := strings.TrimPrefix(ref, "sha256:")
	if len(hex) != 64 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
