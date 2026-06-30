// Package models defines the core domain types shared across the application.
// Field tags map to JSON for API responses; the store layer scans DB rows into
// these structs.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User is an application account.
type User struct {
	ID            uuid.UUID  `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email,omitempty"`
	DisplayName   string     `json:"displayName"`
	IsSuperAdmin  bool       `json:"isSuperAdmin"`
	IsDisabled    bool       `json:"isDisabled"`
	EmailVerified bool       `json:"emailVerified"`
	MustChangePw  bool       `json:"mustChangePassword"`
	RequireMFA    bool       `json:"requireMfa"`
	FailedLogins  int        `json:"-"`
	LockedUntil   *time.Time `json:"lockedUntil,omitempty"`
	LastLoginAt   *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`

	// Populated by aggregate queries.
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Role is a named collection of permissions.
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"isBuiltin"`
	CreatedAt   time.Time `json:"createdAt"`
	Permissions []string  `json:"permissions,omitempty"`
}

// Permission is a single capability key.
type Permission struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}

// Group authorizes users to hosts via shared membership.
type Group struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Host is a managed Linux system.
type Host struct {
	ID          uuid.UUID `json:"id"`
	Hostname    string    `json:"hostname"`
	Description string    `json:"description"`
	Environment string    `json:"environment"`
	Owner       string    `json:"owner"`
	Address     string    `json:"address,omitempty"`
	WGAddress   string    `json:"wgAddress,omitempty"`
	SSHPort     int       `json:"sshPort"`
	SSHUser     string    `json:"sshUser"`
	Tags        []string  `json:"tags"`
	Enrolled    bool      `json:"enrolled"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`

	Groups    []string       `json:"groups,omitempty"`
	Inventory *HostInventory `json:"inventory,omitempty"`
	Status    *HostStatus    `json:"status,omitempty"`
	Metrics   *HostMetrics   `json:"metrics,omitempty"`
}

// DiskFS is one mounted filesystem's usage.
type DiskFS struct {
	Mount      string  `json:"mount"`
	SizeBytes  int64   `json:"sizeBytes"`
	UsedBytes  int64   `json:"usedBytes"`
	AvailBytes int64   `json:"availBytes"`
	UsePct     float64 `json:"usePct"`
}

// NetInterface is a network interface with its addresses (CIDR form).
type NetInterface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// HostNetwork holds a host's network facts.
type HostNetwork struct {
	Interfaces     []NetInterface `json:"interfaces,omitempty"`
	PrimaryIP      string         `json:"primaryIp,omitempty"`
	DefaultGateway string         `json:"defaultGateway,omitempty"`
	DefaultIface   string         `json:"defaultIface,omitempty"`
}

// HostMetrics is periodically-collected resource usage (disk, memory, load,
// network), refreshed by the monitor on every probe.
type HostMetrics struct {
	Disk           []DiskFS     `json:"disk,omitempty"`
	MinDiskFreePct *float64     `json:"minDiskFreePct,omitempty"`
	MemTotalMB     int64        `json:"memTotalMb"`
	MemAvailableMB int64        `json:"memAvailableMb"`
	MemUsedPct     *float64     `json:"memUsedPct,omitempty"`
	Load1          *float64     `json:"load1,omitempty"`
	Load5          *float64     `json:"load5,omitempty"`
	Load15         *float64     `json:"load15,omitempty"`
	LoadPerCore    *float64     `json:"loadPerCore,omitempty"`
	Network        *HostNetwork `json:"network,omitempty"`
	PrimaryIP      string       `json:"primaryIp,omitempty"`
	CollectedAt    *time.Time   `json:"collectedAt,omitempty"`
}

// HostInventory holds collected facts about a host.
type HostInventory struct {
	OSName        string     `json:"osName"`
	OSVersion     string     `json:"osVersion"`
	KernelVersion string     `json:"kernelVersion"`
	Architecture  string     `json:"architecture"`
	SSHVersion    string     `json:"sshVersion"`
	CPUCount      int        `json:"cpuCount"`
	MemoryMB      int64      `json:"memoryMb"`
	CollectedAt   *time.Time `json:"collectedAt,omitempty"`

	// Pending package updates (nil = not yet checked). SecurityUpdates is the
	// subset flagged as security fixes where the package manager reports it.
	UpdatesAvailable *int       `json:"updatesAvailable,omitempty"`
	SecurityUpdates  *int       `json:"securityUpdates,omitempty"`
	UpdatesCheckedAt *time.Time `json:"updatesCheckedAt,omitempty"`
}

// HostStatus is the live health of a host.
type HostStatus struct {
	Status        string     `json:"status"` // online|offline|unknown
	SSHOK         bool       `json:"sshOk"`
	WGOK          bool       `json:"wgOk"`
	LatencyMS     *int       `json:"latencyMs,omitempty"`
	UptimeSeconds *int64     `json:"uptimeSeconds,omitempty"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	LastFailureAt *time.Time `json:"lastFailureAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	CheckedAt     *time.Time `json:"checkedAt,omitempty"`
}

// Session is a browser login session that owns an ephemeral SSH identity.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"userId"`
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"userAgent,omitempty"`
	MFAPassed  bool       `json:"mfaPassed"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt time.Time  `json:"lastSeenAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// CACert describes a stored CA keypair (private material is never serialized).
type CACert struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"` // user|host
	Algo        string     `json:"algo"`
	PublicKey   string     `json:"publicKey"`
	Fingerprint string     `json:"fingerprint"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"createdAt"`
	RetiredAt   *time.Time `json:"retiredAt,omitempty"`
}

// SSHCertificate is issued-certificate metadata (no private key persisted).
type SSHCertificate struct {
	ID           uuid.UUID  `json:"id"`
	Serial       uint64     `json:"serial"`
	Kind         string     `json:"kind"`
	CAKeyID      uuid.UUID  `json:"caKeyId"`
	UserID       *uuid.UUID `json:"userId,omitempty"`
	SessionID    *uuid.UUID `json:"sessionId,omitempty"`
	HostID       *uuid.UUID `json:"hostId,omitempty"`
	KeyID        string     `json:"keyId"`
	Principals   []string   `json:"principals"`
	PublicKey    string     `json:"publicKey"`
	AuditID      uuid.UUID  `json:"auditId"`
	IssuedAt     time.Time  `json:"issuedAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	RevokeReason string     `json:"revokeReason,omitempty"`
}

// SSHSession records a single terminal session.
type SSHSession struct {
	ID         uuid.UUID  `json:"id"`
	SessionID  *uuid.UUID `json:"sessionId,omitempty"`
	UserID     *uuid.UUID `json:"userId,omitempty"`
	HostID     *uuid.UUID `json:"hostId,omitempty"`
	Username   string     `json:"username"`
	Hostname   string     `json:"hostname"`
	CertSerial *uint64    `json:"certSerial,omitempty"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
	ExitCode   *int       `json:"exitCode,omitempty"`
	BytesIn    int64      `json:"bytesIn"`
	BytesOut   int64      `json:"bytesOut"`
	ClientIP   string     `json:"clientIp,omitempty"`

	// HasRecording is populated by the list endpoint (not stored).
	HasRecording bool `json:"hasRecording"`
}

// Recording is replay metadata for an SSH session.
type Recording struct {
	ID           uuid.UUID `json:"id"`
	SSHSessionID uuid.UUID `json:"sshSessionId"`
	Format       string    `json:"format"`
	Path         string    `json:"-"`
	SizeBytes    int64     `json:"sizeBytes"`
	DurationMS   int64     `json:"durationMs"`
	SHA256       string    `json:"sha256"`
	CreatedAt    time.Time `json:"createdAt"`
}

// ApprovalRequest is a just-in-time access request.
type ApprovalRequest struct {
	ID            uuid.UUID  `json:"id"`
	RequesterID   uuid.UUID  `json:"requesterId"`
	Requester     string     `json:"requester,omitempty"`
	TargetKind    string     `json:"targetKind"` // host|group
	HostID        *uuid.UUID `json:"hostId,omitempty"`
	GroupID       *uuid.UUID `json:"groupId,omitempty"`
	TargetName    string     `json:"targetName,omitempty"`
	Reason        string     `json:"reason"`
	TicketRef     string     `json:"ticketRef,omitempty"`
	RequestedSecs int64      `json:"requestedSecs"`
	Status        string     `json:"status"`
	DecidedBy     *uuid.UUID `json:"decidedBy,omitempty"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
	DecisionNote  string     `json:"decisionNote,omitempty"`
	GrantedSecs   *int64     `json:"grantedSecs,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

// TemporaryPermission is a time-boxed grant created from an approval.
type TemporaryPermission struct {
	ID        uuid.UUID  `json:"id"`
	RequestID *uuid.UUID `json:"requestId,omitempty"`
	UserID    uuid.UUID  `json:"userId"`
	HostID    *uuid.UUID `json:"hostId,omitempty"`
	GroupID   *uuid.UUID `json:"groupId,omitempty"`
	GrantedAt time.Time  `json:"grantedAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

// EnrollmentJob tracks an automated host onboarding run.
type EnrollmentJob struct {
	ID         uuid.UUID         `json:"id"`
	HostID     *uuid.UUID        `json:"hostId,omitempty"`
	Target     string            `json:"target"`
	OSHint     string            `json:"osHint,omitempty"`
	Status     string            `json:"status"`
	Steps      []EnrollmentStep  `json:"steps"`
	Error      string            `json:"error,omitempty"`
	CreatedBy  *uuid.UUID        `json:"createdBy,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	StartedAt  *time.Time        `json:"startedAt,omitempty"`
	FinishedAt *time.Time        `json:"finishedAt,omitempty"`
}

// EnrollmentStep is one recorded step in an enrollment job.
type EnrollmentStep struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // ok|failed|skipped
	Detail    string    `json:"detail,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AuditEvent is one entry in the tamper-evident audit chain.
type AuditEvent struct {
	Seq        int64          `json:"seq"`
	ID         uuid.UUID      `json:"id"`
	ActorID    *uuid.UUID     `json:"actorId,omitempty"`
	ActorName  string         `json:"actorName,omitempty"`
	Action     string         `json:"action"`
	TargetKind string         `json:"targetKind,omitempty"`
	TargetID   string         `json:"targetId,omitempty"`
	IP         string         `json:"ip,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	PrevHash   string         `json:"prevHash"`
	Hash       string         `json:"hash"`
	CreatedAt  time.Time      `json:"createdAt"`
}

// AuthEvent is a login/security event.
type AuthEvent struct {
	ID        int64          `json:"id"`
	UserID    *uuid.UUID     `json:"userId,omitempty"`
	Username  string         `json:"username,omitempty"`
	Event     string         `json:"event"`
	IP        string         `json:"ip,omitempty"`
	UserAgent string         `json:"userAgent,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
}

// HostScan is one OpenSCAP security/compliance scan run against a host. The
// full HTML report lives on disk (ReportPath); the summary fields are parsed
// from the results for listing without opening the report.
type HostScan struct {
	ID           uuid.UUID  `json:"id"`
	HostID       uuid.UUID  `json:"hostId"`
	Hostname     string     `json:"hostname,omitempty"`
	RequestedBy  *uuid.UUID `json:"requestedBy,omitempty"`
	Requester    string     `json:"requester,omitempty"`
	Profile      string     `json:"profile,omitempty"`
	ProfileTitle string     `json:"profileTitle,omitempty"`
	Benchmark    string     `json:"benchmark,omitempty"`
	Status       string     `json:"status"` // pending|running|completed|failed
	Score        *float64   `json:"score,omitempty"`
	PassCount    int        `json:"passCount"`
	FailCount    int        `json:"failCount"`
	OtherCount   int        `json:"otherCount"`
	TotalRules   int        `json:"totalRules"`
	Error        string     `json:"error,omitempty"`
	SkipRules    []string   `json:"skipRules,omitempty"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// ScanProfile is a SCAP profile available in a host's datastream.
type ScanProfile struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// AssistantHostRow is a compact host record returned to the AI assistant's
// query tool (one row per host, joined from status/metrics/inventory).
type AssistantHostRow struct {
	Hostname       string     `json:"hostname"`
	Environment    string     `json:"environment,omitempty"`
	Status         string     `json:"status"`
	PrimaryIP      string     `json:"primaryIp,omitempty"`
	OSName         string     `json:"os,omitempty"`
	OSVersion      string     `json:"osVersion,omitempty"`
	Kernel         string     `json:"kernel,omitempty"`
	Architecture   string     `json:"arch,omitempty"`
	CPUCount       int        `json:"cpuCount,omitempty"`
	MemoryTotalMB  int64      `json:"memoryMb,omitempty"`
	SSHVersion     string     `json:"sshVersion,omitempty"`
	UptimeSeconds  *int64     `json:"uptimeSeconds,omitempty"`
	MinDiskFreePct *float64   `json:"diskFreePct,omitempty"`
	MemUsedPct     *float64   `json:"memUsedPct,omitempty"`
	LoadPerCore    *float64   `json:"loadPerCore,omitempty"`
	LatencyMS      *int       `json:"latencyMs,omitempty"`
	WGOK           *bool      `json:"wireguardOk,omitempty"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
	UpdatesAvailable *int     `json:"updatesAvailable,omitempty"`
	SecurityUpdates  *int     `json:"securityUpdates,omitempty"`
	Groups         []string   `json:"groups,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
	Owner          string     `json:"owner,omitempty"`
	Enrolled       bool       `json:"enrolled"`
}

// AssistantScanRow is a recent security scan surfaced to the AI assistant.
type AssistantScanRow struct {
	Hostname   string     `json:"hostname"`
	Profile    string     `json:"profile,omitempty"`
	Status     string     `json:"status"`
	Score      *float64   `json:"score,omitempty"`
	PassCount  int        `json:"passCount"`
	FailCount  int        `json:"failCount"`
	Requester  string     `json:"requester,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// AssistantPlaybookRunRow is a recent playbook run surfaced to the AI assistant.
type AssistantPlaybookRunRow struct {
	Playbook   string     `json:"playbook"`
	TargetKind string     `json:"targetKind"`
	TargetName string     `json:"targetName,omitempty"`
	HostCount  int        `json:"hostCount"`
	CheckMode  bool       `json:"checkMode"`
	Status     string     `json:"status"`
	Requester  string     `json:"requester,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// ScanFinding is one rule outcome from a scan (used to list failures the user
// can choose to remediate).
type ScanFinding struct {
	RuleID          string `json:"ruleId"`
	Title           string `json:"title"`
	Severity        string `json:"severity,omitempty"`
	Result          string `json:"result"`
	AccessImpacting bool   `json:"accessImpacting"`
}

// HostRemediation is one remediation run: the selected rules and its outcome.
type HostRemediation struct {
	ID         uuid.UUID  `json:"id"`
	ScanID     uuid.UUID  `json:"scanId"`
	HostID     uuid.UUID  `json:"hostId"`
	Requester  string     `json:"requester,omitempty"`
	RuleIDs    []string   `json:"ruleIds"`
	Status     string     `json:"status"` // pending|running|completed|failed
	ExitCode   *int       `json:"exitCode,omitempty"`
	Output     string     `json:"output,omitempty"`
	RescanID   *uuid.UUID `json:"rescanId,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}
