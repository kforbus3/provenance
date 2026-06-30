package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/fleet-terminal/backend/internal/httpx"
)

// healthComponent is one checked subsystem.
type healthComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | error
	Detail string `json:"detail"`
}

// handleHealth aggregates a live status report of Fleet's subsystems for the
// admin System Health page. Each check is bounded so one slow dependency can't
// stall the whole report.
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var comps []healthComponent
	add := func(name, status, detail string) {
		comps = append(comps, healthComponent{Name: name, Status: status, Detail: detail})
	}

	// Database
	if err := s.DB.Ping(ctx); err != nil {
		add("Database", "error", "ping failed: "+err.Error())
	} else {
		add("Database", "ok", "connected")
	}

	// Certificate authority
	if id := s.CA.ActiveID(); id != "" {
		add("Certificate authority", "ok", "active CA loaded ("+shortID(id)+")")
	} else {
		add("Certificate authority", "error", "no active CA key loaded")
	}

	// Jump host reachability (TCP)
	jh := s.Cfg.JumpHost
	if jh == "" {
		add("Jump host", "warn", "no jump host configured")
	} else if c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", jh); err != nil {
		add("Jump host", "error", fmt.Sprintf("cannot reach %s: %v", jh, err))
	} else {
		_ = c.Close()
		add("Jump host", "ok", "reachable at "+jh)
	}

	// Ansible runner sidecar
	if s.Cfg.AnsibleRunnerURL == "" {
		add("Ansible runner", "warn", "not configured")
	} else if s.playbookSvc.Healthy(ctx) {
		add("Ansible runner", "ok", "reachable")
	} else {
		add("Ansible runner", "warn", "not reachable (playbook validate/run unavailable)")
	}

	// Backups
	policy := s.backups.LoadPolicy(ctx)
	backups, _ := s.backups.List(ctx)
	switch {
	case len(backups) > 0:
		age := time.Since(backups[0].CreatedAt).Round(time.Hour)
		st := "ok"
		// Warn if scheduled backups are on but the latest is much older than the interval.
		if policy.Enabled && age > 2*time.Duration(policy.IntervalHours)*time.Hour {
			st = "warn"
		}
		add("Backups", st, fmt.Sprintf("%d stored; latest %s ago%s", len(backups), age,
			map[bool]string{true: " (scheduled on)", false: " (manual only)"}[policy.Enabled]))
	case policy.Enabled:
		add("Backups", "warn", "scheduled but none produced yet")
	default:
		add("Backups", "warn", "no backups yet — enable scheduled backups in Settings")
	}

	// Background jobs (monitor, renewal, reaper, retention, KRL, etc.)
	for _, j := range s.Jobs.Snapshot() {
		st, detail := "ok", "no runs yet"
		if j.LastRunAt != nil {
			detail = fmt.Sprintf("last run %s ago, %d total", time.Since(*j.LastRunAt).Round(time.Second), j.Runs)
		}
		if !j.OK {
			st, detail = "error", "last error: "+j.LastError
		}
		add("Job: "+j.Name, st, detail)
	}

	overall := "ok"
	for _, c := range comps {
		if c.Status == "error" {
			overall = "error"
			break
		}
		if c.Status == "warn" {
			overall = "warn"
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"overall":    overall,
		"components": comps,
		"checkedAt":  time.Now(),
		"version":    s.Version,
	})
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
