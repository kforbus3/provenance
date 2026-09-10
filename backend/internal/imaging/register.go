package imaging

import (
	"context"
	"fmt"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Registering an already-enrolled host as an updatable A/B machine.
//
// Rollouts select FROM imaging_machines and join to hosts, so a host with no
// imaging row is invisible to them — including to "the whole fleet". That is
// right for an ordinary server, and wrong for an A/B machine this deployment
// did not image: one restored from backup, imaged by a previous server, or
// whose imaging row was deleted. Such a machine has ab-update, an A/B layout and
// a valid certificate, and was excluded on bookkeeping rather than on anything
// technical.
//
// The row is built from what the machine says about ITSELF, read over SSH with
// the same logic ab-agent uses — not from what the server assumes. That matters
// most for the id: the agent identifies by the id in /boot/ab-deploy.json and
// falls back to its first real MAC, so reading it the same way means a later
// check-in updates this row instead of creating a second one for the same
// machine under a different name.
//
// Nothing is invented. If the machine is not an A/B system this refuses, rather
// than registering a host that will fail every rollout it is offered.

// probeScript reports what a machine would report about itself. Keyed output
// rather than JSON: these images ship neither jq nor python3, which is the same
// reason the agent's own wire format is key=value.
const probeScript = `
set -u
have=0; [ -x /usr/local/sbin/ab-update ] && have=1
echo "ab_update=$have"
slot="$(sed -n 's/.*rauc\.slot=\([AB]\).*/\1/p' /proc/cmdline 2>/dev/null)"
echo "slot=$slot"
id=""
[ -r /boot/ab-deploy.json ] && id="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /boot/ab-deploy.json)"
if [ -z "$id" ]; then
  for f in /sys/class/net/*/address; do
    case "$f" in */lo/*) continue;; esac
    a="$(cat "$f" 2>/dev/null)"
    case "$a" in ""|00:00:00:00:00:00) continue;; esac
    id="$a"; break
  done
fi
echo "id=$id"
ver=""
[ -n "$slot" ] && [ -r "/boot/$slot/ab-version" ] && ver="$(cat "/boot/$slot/ab-version")"
[ -z "$ver" ] && [ -r /usr/lib/flipside/version ] && ver="$(cat /usr/lib/flipside/version)"
[ -z "$ver" ] && ver="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}" )"
echo "version=$ver"
echo "arch=$(uname -m)"
echo "hostname=$(hostname 2>/dev/null)"
echo "agent=$([ -x /usr/local/sbin/ab-agent ] && echo yes || echo no)"
`

// RegisterHost reads an enrolled host's A/B state over SSH and records it as a
// machine, so rollouts can reach it.
func (s *Service) RegisterHost(ctx context.Context, host *models.Host) (*models.ImagingMachine, error) {
	ctx, cancel := context.WithTimeout(ctx, nudgeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	out, err := run(conn, probeScript)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("reading A/B state from %s: %w", host.Hostname, err)
	}

	m, err := machineFromProbe(out, host)
	if err != nil {
		return nil, err
	}

	saved, err := s.store.ReportMachine(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("recording %s: %w", host.Hostname, err)
	}
	if err := s.store.LinkMachine(ctx, saved.ID, &host.ID); err != nil {
		return nil, fmt.Errorf("registered %s but could not pair it with the host: %w",
			host.Hostname, err)
	}
	// Whether the check-in agent is installed decides what happens next, so it is
	// worth recording: with it, this record keeps itself current from the
	// machine's own heartbeats. Without it, what was read here is all this
	// server will ever know until someone registers it again.
	s.store.RecordImagingEvent(ctx, saved.ID, "registered", map[string]any{
		"host": host.Hostname, "slot": saved.Slot, "version": saved.Version,
		"selfReporting": strings.Contains(out, "agent=yes"),
	})
	return saved, nil
}

// machineFromProbe turns what a machine said about itself into a record, or
// explains why it cannot be one.
//
// Split out from the SSH round-trip because every judgement worth checking is
// here and none of it needs a network: which fields are required, what counts as
// an A/B machine, and what the record is called. The connection is the part with
// no decisions in it.
func machineFromProbe(out string, host *models.Host) (*models.ImagingMachine, error) {
	f := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			f[k] = strings.TrimSpace(v)
		}
	}

	// Refuse rather than register something that cannot take an update. A record
	// that exists and always fails is worse than none: it makes the machine a
	// permanent member of every fleet-wide rollout, and a permanent failure in
	// each one.
	if f["ab_update"] != "1" {
		return nil, fmt.Errorf("%s has no /usr/local/sbin/ab-update, so it is not an "+
			"A/B machine and cannot take a RAUC bundle. Nothing was registered",
			host.Hostname)
	}
	// The id has to be the one the agent would report. Anything else creates a
	// second record for the same machine the moment it checks in, and then two
	// rows disagree about which slot it is running.
	if f["id"] == "" {
		return nil, fmt.Errorf("could not read a machine identity from %s — no "+
			"/boot/ab-deploy.json and no usable MAC address. Registering it under an "+
			"invented id would create a second record as soon as its agent checked in",
			host.Hostname)
	}

	return &models.ImagingMachine{
		ID:       f["id"],
		Hostname: f["hostname"],
		Address:  host.Address,
		Slot:     f["slot"],
		Version:  f["version"],
		Arch:     f["arch"],
		// Read off the machine rather than reported by it. The distinction is
		// already modelled and already shown, and it is the honest one here:
		// nothing has heard from this machine, we went and looked.
		ReportSource: "observed",
		ReportedBy:   "registration",
	}, nil
}
