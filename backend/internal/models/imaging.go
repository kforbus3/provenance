package models

import (
	"time"

	"github.com/google/uuid"
)

// Data types for the imaging control plane. The *behaviour* -- the rollout
// engine's rules about canary, soak, batching and the failure budget -- lives in
// internal/imaging and works on its own types, so it stays testable without a
// database. These are what is stored and what crosses the API.

// ImagingMachine is one machine as the imaging system knows it.
//
// Deliberately not a column on Host: a machine exists before it is a host. It is
// imaged on the provisioning switch and only later enrolled, and that window is
// exactly where "imaged perfectly and never came back" lives -- the failure the
// imager's own reports cannot cover, because the last of them is sent before the
// reboot.
type ImagingMachine struct {
	ID     string     `json:"id"` // what the imager saw; usually a MAC
	HostID *uuid.UUID `json:"hostId,omitempty"`

	Hostname     string `json:"hostname"`
	Address      string `json:"address,omitempty"`
	Slot         string `json:"slot,omitempty"`
	Version      string `json:"version"`
	Image        string `json:"image,omitempty"`
	Arch         string `json:"arch,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`
	BootID       string `json:"bootId,omitempty"`
	Health       string `json:"health,omitempty"`

	UpdateState   string `json:"updateState"`
	UpdateError   string `json:"updateError,omitempty"`
	UpdateRollout string `json:"updateRollout,omitempty"`

	// Who last said this, and how they knew. A machine's own check-in and
	// something reporting what it observed over SSH are different kinds of
	// claim; flattening them would lose which to trust and who to ask.
	ReportedBy   string `json:"reportedBy,omitempty"`
	ReportSource string `json:"reportSource"` // agent | observed

	Label string `json:"label,omitempty"`
	Held  bool   `json:"held"`

	FirstSeen time.Time  `json:"firstSeen"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
	ImagedAt  *time.Time `json:"imagedAt,omitempty"`
	BootedAt  *time.Time `json:"bootedAt,omitempty"`

	// Filled in by the API layer from the host record and the clock, so a caller
	// does not have to join three things to answer "what is this and can we
	// reach it".
	Presence    string   `json:"presence"`
	HostName    string   `json:"hostName,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reachable   bool     `json:"reachable"`
}

// ImagingRollout is a staged rollout of one bundle to a set of machines.
//
// Targets are host groups -- this product's own, not a second set of groups
// naming the same machines. Keeping two in step is work nobody would have done.
type ImagingRollout struct {
	ID          uuid.UUID `json:"id"`
	Bundle      string    `json:"bundle"`
	Version     string    `json:"version"`
	BundleURL   string    `json:"bundleUrl,omitempty"`
	Description string    `json:"description,omitempty"`

	State      string `json:"state"` // running|paused|halted|completed|cancelled
	HaltReason string `json:"haltReason,omitempty"`

	TargetGroups []uuid.UUID `json:"targetGroups"`
	TargetHosts  []uuid.UUID `json:"targetHosts"`
	TargetAll    bool        `json:"targetAll"`

	Canary      int `json:"canary"`
	BatchSize   int `json:"batchSize"`
	SoakSeconds int `json:"soakSeconds"`
	MaxFailures int `json:"maxFailures"`

	WindowStart *string `json:"windowStart,omitempty"`
	WindowEnd   *string `json:"windowEnd,omitempty"`
	WindowDays  []int32 `json:"windowDays,omitempty"`

	// When the canary phase finished. The soak is measured from here, not from
	// whichever machine verified most recently -- the latter re-arms the soak as
	// each batch lands, so every batch soaks too.
	CanaryDoneAt *time.Time `json:"canaryDoneAt,omitempty"`
	// Failures counted before the last resume, so resuming forgives what an
	// operator has already looked at instead of re-halting immediately.
	FailureBaseline int `json:"-"`

	CreatedAt     time.Time `json:"createdAt"`
	CreatedByName string    `json:"createdBy,omitempty"`

	// Filled in by the API layer.
	Total    int                        `json:"total"`
	Done     int                        `json:"done"`
	Counts   map[string]int             `json:"counts,omitempty"`
	Machines map[string]RolloutProgress `json:"machines,omitempty"`
}

// RolloutProgress is one machine's place in one rollout.
type RolloutProgress struct {
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	Attempts  int       `json:"attempts"`
	ChangedAt time.Time `json:"changedAt"`
}
