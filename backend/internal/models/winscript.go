package models

import (
	"time"

	"github.com/google/uuid"
)

// WinScript is a single PowerShell script authored/edited in the UI — the Windows
// counterpart to a Playbook. The current content lives here; each saved edit
// snapshots the prior content into a WinScriptVersion.
type WinScript struct {
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

// WinScriptVersion is an immutable snapshot of a script's content at a revision.
type WinScriptVersion struct {
	ID        uuid.UUID `json:"id"`
	ScriptID  uuid.UUID `json:"scriptId"`
	Version   int       `json:"version"`
	Content   string    `json:"content,omitempty"`
	Author    string    `json:"author,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// WinScriptRun is one execution of a PowerShell script against a target (one or
// more Windows hosts, or a Fleet group). Output holds the combined per-host log.
type WinScriptRun struct {
	ID            uuid.UUID  `json:"id"`
	ScriptID      uuid.UUID  `json:"scriptId"`
	ScriptVersion int        `json:"scriptVersion"`
	Requester     string     `json:"requester,omitempty"`
	TargetKind    string     `json:"targetKind"` // host|group
	TargetID      *uuid.UUID `json:"targetId,omitempty"`
	TargetName    string     `json:"targetName,omitempty"`
	HostCount     int        `json:"hostCount"`
	Scheduled     bool       `json:"scheduled"`
	Status        string     `json:"status"` // pending|running|completed|failed
	ExitCode      *int       `json:"exitCode,omitempty"`
	Output        string     `json:"output,omitempty"`
	Error         string     `json:"error,omitempty"`
	StartedAt     *time.Time `json:"startedAt,omitempty"`
	FinishedAt    *time.Time `json:"finishedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}
