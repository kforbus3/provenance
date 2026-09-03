package imaging

import (
	"strings"
	"time"
)

// How long a machine may go unheard-from before its row stops meaning "this is
// true now". Expressed in multiples of the agent's own interval rather than as
// flat minutes, so changing the interval does not silently make every machine
// look broken -- or hide one that is.
const (
	MissedBeatsOnline = 3
	StaleFor          = 24 * time.Hour
)

// Presence answers whether what this row says is still current -- which is a
// different question from whether the machine is healthy. A machine can be
// perfectly fine and simply live somewhere nothing can hear it.
//
// `unknown` is its own answer and not folded into offline: a machine that has
// never run an agent has not gone quiet, it was never speaking, and reporting
// those as offline fills the page with alarms about machines that are fine.
func Presence(lastSeen *time.Time, interval time.Duration, now time.Time) string {
	if lastSeen == nil || lastSeen.IsZero() {
		return "unknown"
	}
	age := now.Sub(*lastSeen)
	if age <= interval*MissedBeatsOnline {
		return "online"
	}
	if age <= StaleFor {
		return "stale"
	}
	return "offline"
}

// NormaliseHostname strips the domain and case.
//
// A machine reports whatever `hostname` says, which is short on some systems and
// fully qualified on others, and a host record is whatever an operator typed.
func NormaliseHostname(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// MatchByHostname pairs machines with hosts by name, for machines that have not
// been linked to one explicitly.
//
// A name is a guess and is treated as one. An explicit link survives a rename or
// a re-image; a name stops being true the moment somebody changes it. And a name
// that two machines answer to is worse than useless: picking one at random sends
// half the updates to the wrong machine, silently, so an ambiguous name matches
// nothing at all.
func MatchByHostname(names []string) map[string]bool {
	seen := map[string]int{}
	for _, n := range names {
		if k := NormaliseHostname(n); k != "" {
			seen[k]++
		}
	}
	unique := map[string]bool{}
	for k, n := range seen {
		unique[k] = n == 1
	}
	return unique
}
