package stacks

import (
	"strings"
	"testing"
)

// A VPN-routed torrent client with no route out, still reporting "Up 35 hours".
//
// A rollout recreated gluetun to apply a pin. metube, pinchflat and qbittorrent
// share its network namespace via `network_mode: "service:gluetun"` — so when
// gluetun was replaced they were left attached to a container that no longer
// existed:
//
//	qbittorrent NetworkMode: container:48b14a31…   (the old gluetun)
//	wget: bad address 'ifconfig.me'
//	curl http://host:8080 → 000
//
// The compose file said so three times: "if gluetun is ever replaced, recreate
// this too - otherwise it is". Nothing read those comments.

const vpnCompose = `services:
  gluetun:
    image: qmcgaw/gluetun:v3.41.3
    ports:
      - "8080:8080"   # qBittorrent UI (qbit is behind gluetun)
  metube:
    image: ghcr.io/alexta69/metube:2026.07.24
    network_mode: "service:gluetun"
  pinchflat:
    image: ghcr.io/kieraneglin/pinchflat:latest
    network_mode: "service:gluetun"   # <-- forces ALL pinchflat traffic through VPN
  sabnzbd:
    image: lscr.io/linuxserver/sabnzbd:latest
#    network_mode: "service:gluetun"
  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    network_mode: "service:gluetun"   # <-- forces ALL qbit traffic through VPN
  bazarr:
    image: lscr.io/linuxserver/bazarr:latest
`

func TestServicesSharingANetworkNamespaceAreFound(t *testing.T) {
	got := networkDependents(vpnCompose, "gluetun")
	want := map[string]bool{"metube": true, "pinchflat": true, "qbittorrent": true}

	if len(got) != len(want) {
		t.Fatalf("found %v, want metube, pinchflat and qbittorrent", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("%s does not share gluetun's namespace", g)
		}
	}
	// sabnzbd's line is commented out: it has its own network and must not be
	// dragged into every gluetun deploy.
	for _, g := range got {
		if g == "sabnzbd" {
			t.Error("a commented-out network_mode was treated as live")
		}
	}
}

func TestAServiceIsNotItsOwnDependent(t *testing.T) {
	for _, g := range networkDependents(vpnCompose, "gluetun") {
		if g == "gluetun" {
			t.Error("gluetun listed as depending on itself")
		}
	}
}

func TestAServiceNobodySharesHasNoDependents(t *testing.T) {
	if got := networkDependents(vpnCompose, "bazarr"); len(got) != 0 {
		t.Errorf("bazarr has no dependents, got %v", got)
	}
}

func TestANarrowedDeployBringsTheDependentsWithIt(t *testing.T) {
	// The fix, at the level that matters: what the host is actually told to do.
	got := RenderScript("/home/keith/media-stack", vpnCompose, 4, true, "gluetun")
	for _, svc := range []string{"gluetun", "metube", "pinchflat", "qbittorrent"} {
		if !strings.Contains(got, "up -d --no-deps 'gluetun'") {
			t.Fatalf("the service itself is not brought up:\n%s", got)
		}
		if !strings.Contains(got, "'"+svc+"'") {
			t.Errorf("%s is not brought up with gluetun, so it would be left on a "+
				"network namespace that no longer exists:\n%s", svc, got)
		}
	}
	// Still narrowed: bazarr and sabnzbd have their own networks and are not
	// restarted for somebody else's deploy.
	for _, svc := range []string{"bazarr", "sabnzbd"} {
		if strings.Contains(got, "'"+svc+"'") {
			t.Errorf("%s was dragged into a deploy that had nothing to do with it", svc)
		}
	}
}

func TestDeployingADependentDoesNotDragInTheWholeChain(t *testing.T) {
	// Updating qbittorrent alone touches qbittorrent. It shares gluetun's
	// namespace, but recreating qbittorrent does not disturb gluetun, so there is
	// nothing to bring along.
	got := RenderScript("/opt/x", vpnCompose, 1, true, "qbittorrent")
	if strings.Contains(got, "'gluetun'") {
		t.Errorf("deploying a dependent restarted the service it depends on:\n%s", got)
	}
}
