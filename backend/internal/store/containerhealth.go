package store

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// UnhealthyContainer is a container the fleet reports as not doing its job.
type UnhealthyContainer struct {
	HostID   uuid.UUID `json:"hostId"`
	Hostname string    `json:"hostname"`
	Name     string    `json:"name"`
	Image    string    `json:"image,omitempty"`
	// State is docker's own word: restarting, exited, dead, paused.
	State string `json:"state"`
	// Status is the human line docker prints, which carries the detail the state
	// does not: "Restarting (0) 40 seconds ago", "Up 2 days (unhealthy)".
	Status string `json:"status,omitempty"`
	// Project and Dir locate it, so a person can act on it without hunting.
	Project string `json:"composeProject,omitempty"`
	Dir     string `json:"composeDir,omitempty"`
	// StackID is set when Provenance manages the compose project this container
	// belongs to, so the UI can link to the stack that owns it.
	StackID *uuid.UUID `json:"stackId,omitempty"`
	// CollectedAt is when this host's container list was read. A crash loop
	// reported from a three-day-old inventory is not news, and a page that does
	// not say so invites somebody to go and fix a container that has been fine
	// since Tuesday.
	CollectedAt *time.Time `json:"collectedAt,omitempty"`
	// Why is the reason this container is listed, in a few words.
	Why string `json:"why"`
}

// UnhealthyContainers lists containers across the fleet that are not running
// properly.
//
// This exists because two containers were crash-looping in production -- one for
// long enough that nobody remembered starting it -- and nothing anywhere said so.
// Every part of the machinery was working: the collector recorded the state, the
// API served it, and the host detail panel drew an orange chip. The chip was
// inside a 220-pixel scrolling list on one host's expanded panel, so seeing it
// required opening the host you already suspected. Fleet-wide there was no
// question that could be asked at all.
//
// The judgement about which states count is deliberate and made in code rather
// than by the caller, because the alternative -- list everything that is not
// "running" -- is the version that gets ignored. A compose project routinely
// contains one-shot containers that have exited 0 and should have; reporting
// those as problems teaches people that this list is noise, and then the crash
// loop underneath them is invisible again for a different reason.
func (s *Store) UnhealthyContainers(ctx context.Context) ([]UnhealthyContainer, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hi.host_id, h.hostname,
		       COALESCE(c->>'name',''), COALESCE(c->>'image',''),
		       lower(COALESCE(c->>'state','')), COALESCE(c->>'status',''),
		       COALESCE(c->>'composeProject',''), COALESCE(c->>'composeDir',''),
		       st.id, hi.collected_at
		FROM host_inventory hi
		JOIN hosts h ON h.id = hi.host_id
		CROSS JOIN LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		LEFT JOIN container_stacks st
		       ON st.host_id = hi.host_id AND st.path = COALESCE(c->>'composeDir','')
		WHERE lower(COALESCE(c->>'state','')) <> 'running'
		   OR lower(COALESCE(c->>'status','')) LIKE '%(unhealthy)%'
		ORDER BY h.hostname, 3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UnhealthyContainer{}
	for rows.Next() {
		var u UnhealthyContainer
		if err := rows.Scan(&u.HostID, &u.Hostname, &u.Name, &u.Image,
			&u.State, &u.Status, &u.Project, &u.Dir, &u.StackID, &u.CollectedAt); err != nil {
			return nil, err
		}
		why, report := whyUnhealthy(u.State, u.Status)
		if !report {
			continue
		}
		u.Why = why
		out = append(out, u)
	}
	return out, rows.Err()
}

// whyUnhealthy decides whether a container's state is worth reporting, and says
// why in the words an operator needs.
func whyUnhealthy(state, status string) (why string, report bool) {
	low := strings.ToLower(status)
	switch state {
	case "restarting":
		// The crash loop. The exit code in the status is the code it exited with
		// LAST time, and zero does not make it benign: a container that exits
		// cleanly and is restarted forever by its restart policy never does its
		// job, and one was doing exactly that in production.
		return "restarting in a loop — it is not staying up", true
	case "dead":
		return "dead — the runtime could not remove it", true
	case "exited":
		// A one-shot container that finished is not a fault, and listing every one
		// of them is how a page like this stops being read.
		if code, ok := exitCode(low); ok && code == 0 {
			return "", false
		}
		return "exited with a failure and has not come back", true
	case "paused":
		return "paused", true
	case "created", "removing":
		// Genuinely transient, and "created" is also the state of a container that
		// never started -- but a single collection cannot tell those apart, and
		// guessing produces a warning that clears itself.
		return "", false
	}
	// Running, but failing its own healthcheck. Docker keeps the state "running"
	// and puts this only in the status line, so a check on state alone misses the
	// container that is up and not working -- which is the failure a healthcheck
	// exists to find.
	if strings.Contains(low, "(unhealthy)") {
		return "running, but failing its healthcheck", true
	}
	return "", false
}

// exitCode reads the code out of docker's "exited (1) 5 minutes ago".
func exitCode(status string) (int, bool) {
	open := strings.IndexByte(status, '(')
	if open < 0 {
		return 0, false
	}
	close := strings.IndexByte(status[open:], ')')
	if close < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(status[open+1 : open+close]))
	if err != nil {
		return 0, false
	}
	return n, true
}
