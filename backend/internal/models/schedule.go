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
	Running   bool      `json:"running"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
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
}
