package models

import (
	"time"

	"github.com/google/uuid"
)

// Playbook is a single Ansible YAML document authored/edited in the UI. The
// current content lives here; each saved edit snapshots the prior content into
// a PlaybookVersion.
type Playbook struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Content     string     `json:"content,omitempty"`
	Version     int        `json:"version"`
	CreatedBy   *uuid.UUID `json:"createdBy,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updatedBy,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// PlaybookVersion is an immutable snapshot of a playbook's content at a revision.
type PlaybookVersion struct {
	ID         uuid.UUID `json:"id"`
	PlaybookID uuid.UUID `json:"playbookId"`
	Version    int       `json:"version"`
	Content    string    `json:"content,omitempty"`
	Author     string    `json:"author,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// PlaybookRun is one execution of a playbook against a target (a single host or
// a Fleet group). Execution wiring lands in Phase 2; the record exists now so
// the model and the startup reconciler are in place.
type PlaybookRun struct {
	ID              uuid.UUID  `json:"id"`
	PlaybookID      uuid.UUID  `json:"playbookId"`
	PlaybookVersion int        `json:"playbookVersion"`
	Requester       string     `json:"requester,omitempty"`
	TargetKind      string     `json:"targetKind"` // host|group
	TargetID        *uuid.UUID `json:"targetId,omitempty"`
	TargetName      string     `json:"targetName,omitempty"`
	HostCount       int        `json:"hostCount"`
	CheckMode       bool       `json:"checkMode"`
	Scheduled       bool       `json:"scheduled"`
	Status          string     `json:"status"` // pending|running|completed|failed
	ExitCode        *int       `json:"exitCode,omitempty"`
	Output          string     `json:"output,omitempty"`
	Error           string     `json:"error,omitempty"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}
