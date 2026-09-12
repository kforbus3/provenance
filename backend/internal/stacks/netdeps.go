package stacks

import "strings"

// Services that share another service's network namespace.
//
// `network_mode: "service:gluetun"` means a container has no network stack of its
// own — it lives inside gluetun's. Recreating gluetun destroys that namespace,
// and every container attached to it is left pointing at a container that no
// longer exists. They keep RUNNING, and report as healthy, with no network at
// all:
//
//	qbittorrent NetworkMode: container:48b14a31…   (the old gluetun)
//	wget: bad address 'ifconfig.me'
//	curl http://host:8080 → 000
//
// That happened. A rollout recreated gluetun to apply a pin and stranded metube,
// pinchflat and qbittorrent — a VPN-routed torrent client with no route out,
// still showing "Up 35 hours". The compose file said so three times in comments:
// "if gluetun is ever replaced, recreate this too".
//
// So a deploy narrowed to one service has to bring its dependents with it. This
// is the one case where touching only what was asked for is the wrong answer:
// the blast radius is already larger than the service, whether or not we act on
// it.
//
// Only network_mode is followed. depends_on is start ORDER, and a container whose
// dependency restarts is not broken by it — restarting those too would undo the
// narrowing for no reason.
func networkDependents(compose, service string) []string {
	if service == "" {
		return nil
	}
	want := "service:" + service
	var out []string
	current := ""
	for _, raw := range strings.Split(compose, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		indent := len(line) - len(trimmed)

		// A service key: two spaces in, ending in a colon, directly under
		// `services:`. Deeper keys are that service's own settings.
		if indent == 2 && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			current = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if current == "" || current == service {
			continue
		}
		rest, ok := strings.CutPrefix(trimmed, "network_mode:")
		if !ok {
			continue
		}
		v := strings.TrimSpace(rest)
		if i := strings.IndexByte(v, '#'); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"'`)
		if v == want {
			out = append(out, current)
		}
	}
	return out
}
