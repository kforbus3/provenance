package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Recurrence describes when a schedule fires. Times are in the server's local
// timezone.
type Recurrence struct {
	Type         string `json:"type"`         // interval | daily | weekly
	EveryMinutes int    `json:"everyMinutes"` // interval
	TimeOfDay    string `json:"timeOfDay"`    // "HH:MM" for daily/weekly
	Weekday      int    `json:"weekday"`      // 0=Sunday … 6=Saturday, for weekly
}

// Schedule is a recurring scan or playbook run. It is disabled until an operator
// turns it on; the engine reuses the normal run paths so results land in the
// usual scan/playbook history.
type Schedule struct {
	ID         uuid.UUID       `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"` // scan | playbook
	Enabled    bool            `json:"enabled"`
	TargetKind string          `json:"targetKind"` // host | group
	TargetID   *uuid.UUID      `json:"targetId,omitempty"`
	TargetName string          `json:"targetName,omitempty"`
	Recurrence Recurrence      `json:"recurrence"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Requester  string          `json:"requester,omitempty"`
	LastRunAt  *time.Time      `json:"lastRunAt,omitempty"`
	LastStatus string          `json:"lastStatus,omitempty"`
	NextRunAt  *time.Time      `json:"nextRunAt,omitempty"`
	// Running is computed (not stored): true while the scan/playbook records from
	// the most recent fire are still pending or running.
	Running bool `json:"running"`
	// LastOutcome is computed too: what the last firing PRODUCED -- completed,
	// failed, running, or empty when it produced nothing (a vulndb refresh, or a
	// firing with no hosts).
	//
	// LastStatus says what FIRING did and never changes afterwards, so every schedule
	// reads "started" forever: one that failed six nights running looks exactly like
	// one that worked, on the page an operator opens to find out which. This is the
	// answer to "did it work", derived from the runs themselves.
	LastOutcome string `json:"lastOutcome,omitempty"`
	// LastRunTotal and LastRunOK count the records the last firing launched and
	// how many completed -- "16 of 17", which a verdict alone cannot say.
	LastRunTotal int `json:"lastRunTotal"`
	LastRunOK    int `json:"lastRunOk"`
	// TargetMissing is computed: the host or group this schedule targets has been
	// deleted. Deleting it disables the schedule; this says why.
	TargetMissing bool      `json:"targetMissing"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// ScanSchedulePayload is the Payload for a scan schedule.
type ScanSchedulePayload struct {
	Profile              string   `json:"profile"`
	SkipExpensiveFsRules bool     `json:"skipExpensiveFsRules"`
	SkipRules            []string `json:"skipRules"`
}

// PlaybookSchedulePayload is the Payload for a playbook schedule.
type PlaybookSchedulePayload struct {
	PlaybookID uuid.UUID `json:"playbookId"`
	CheckMode  bool      `json:"checkMode"`
	// OrderByTopology runs the schedule's hosts in dependency order -- dependents
	// first, the things carrying them last -- as a sequence of runs rather than
	// one. Off by default: it changes a single run into several, and a fleet that
	// has recorded no topology would get the same behaviour with more rows.
	OrderByTopology bool `json:"orderByTopology"`
}

// ScriptSchedulePayload is the Payload for a PowerShell script schedule.
type ScriptSchedulePayload struct {
	ScriptID uuid.UUID `json:"scriptId"`
}
