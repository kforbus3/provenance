// Package models defines the core domain types shared across the application.
// Field tags map to JSON for API responses; the store layer scans DB rows into
// these structs.
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AssistantAction is one proposal in the assistant's propose→confirm→execute
// lifecycle. The assistant stages it; the user confirms; execution re-authorizes
// against the live principal. Also serves as the history of assistant actions.
type AssistantAction struct {
	ID         uuid.UUID       `json:"id"`
	UserID     uuid.UUID       `json:"userId"`
	Kind       string          `json:"kind"`
	Params     json.RawMessage `json:"params"`
	Preview    string          `json:"preview"`
	Risk       string          `json:"risk"` // safe | guarded | destructive
	Permission string          `json:"permission"`
	Status     string          `json:"status"` // proposed | pending_approval | executed | failed | cancelled | denied | expired
	Outcome    string          `json:"outcome,omitempty"`
	CreatedAt  time.Time       `json:"createdAt"`
	ExpiresAt  time.Time       `json:"expiresAt"`
	ExecutedAt *time.Time      `json:"executedAt,omitempty"`
	// Approval decision (set for guarded actions that went through pending_approval).
	Requester    string     `json:"requester,omitempty"` // proposer username, filled by joins where useful
	DecidedBy    *uuid.UUID `json:"decidedBy,omitempty"`
	DecidedAt    *time.Time `json:"decidedAt,omitempty"`
	DecisionNote string     `json:"decisionNote,omitempty"`
}

// VaultSecret is a stored credential's metadata. The secret material itself lives
// only in vault_secret_versions, encrypted; it is never carried on this struct.
type VaultSecret struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Folder       string    `json:"folder"`
	Type         string    `json:"type"` // password | ssh_key | api_key | generic
	Username     string    `json:"username"`
	Target       string    `json:"target"`
	Description  string    `json:"description"`
	AccessPolicy string    `json:"accessPolicy"` // open | checkout | approval
	Version      int       `json:"version"`
	CreatedBy    string    `json:"createdBy,omitempty"` // resolved username
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	// Access is the requesting caller's effective access (view|use|manage), set on
	// list/get for the UI. Empty means access is via the Credential.Manage role.
	Access string `json:"access,omitempty"`
}

// VaultCheckout is a time-boxed check-out of a credential (optionally approved by a
// second person) that grants the requester reveal/inject access while active.
type VaultCheckout struct {
	ID          uuid.UUID  `json:"id"`
	SecretID    uuid.UUID  `json:"secretId"`
	SecretName  string     `json:"secretName,omitempty"` // resolved
	UserID      uuid.UUID  `json:"userId"`
	Username    string     `json:"username,omitempty"` // resolved requester
	Reason      string     `json:"reason,omitempty"`
	Status      string     `json:"status"` // pending | active | denied | expired | checked_in
	RequestedAt time.Time  `json:"requestedAt"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	DecidedBy   *uuid.UUID `json:"decidedBy,omitempty"`
	DecidedAt   *time.Time `json:"decidedAt,omitempty"`
	CheckedInAt *time.Time `json:"checkedInAt,omitempty"`
}

// VaultGrant delegates access to one secret to a user or group.
type VaultGrant struct {
	ID          uuid.UUID `json:"id"`
	SecretID    uuid.UUID `json:"secretId"`
	SubjectKind string    `json:"subjectKind"` // user | group
	SubjectID   uuid.UUID `json:"subjectId"`
	SubjectName string    `json:"subjectName,omitempty"` // resolved for the UI
	Access      string    `json:"access"`                // view | use | manage
	CreatedAt   time.Time `json:"createdAt"`
}

// Tenant is one isolated customer (or the provider itself) in multi-tenant mode.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Kind      string    `json:"kind"`   // provider | customer
	Status    string    `json:"status"` // active | suspended
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	UserCount int       `json:"userCount"`
	HostCount int       `json:"hostCount"`
}

// User is an application account.
type User struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenantId,omitempty"`
	Username      string     `json:"username"`
	Email         string     `json:"email,omitempty"`
	DisplayName   string     `json:"displayName"`
	IsSuperAdmin  bool       `json:"isSuperAdmin"`
	IsDisabled    bool       `json:"isDisabled"`
	EmailVerified bool       `json:"emailVerified"`
	MustChangePw  bool       `json:"mustChangePassword"`
	RequireMFA    bool       `json:"requireMfa"`
	AuthSource    string     `json:"authSource,omitempty"` // local | oidc | ldap | saml
	FailedLogins  int        `json:"-"`
	LockedUntil   *time.Time `json:"lockedUntil,omitempty"`
	LastLoginAt   *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`

	// Populated by aggregate queries.
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// ServiceAccount is a non-human identity that authenticates via API tokens. It is
// a users row flagged is_service_account, carrying roles + group host-access like
// any user but with no password and no interactive login.
type ServiceAccount struct {
	ID          uuid.UUID  `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	IsDisabled  bool       `json:"isDisabled"`
	CreatedAt   time.Time  `json:"createdAt"`
	Roles       []string   `json:"roles"`
	Groups      []string   `json:"groups"`
	TokenCount  int        `json:"tokenCount"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
}

// APIToken is a hashed bearer credential belonging to a service account. The
// plaintext is returned only once, at creation, in the separate Secret field.
type APIToken struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	Secret     string     `json:"secret,omitempty"` // full token, set only on creation
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
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"createdAt"`
	Rule        *GroupRule `json:"rule,omitempty"` // non-nil = dynamic (rule-managed) membership
}

// GroupRule defines dynamic group membership over stable host attributes. Live
// metrics are deliberately excluded — membership (and thus access) must not flap
// with disk/load. A host matches when every non-empty condition holds.
type GroupRule struct {
	Environment      string   `json:"environment,omitempty"`
	TagsAll          []string `json:"tagsAll,omitempty"` // host must carry ALL of these tags
	TagsAny          []string `json:"tagsAny,omitempty"` // host must carry AT LEAST ONE
	OSContains       string   `json:"osContains,omitempty"`
	HostnameContains string   `json:"hostnameContains,omitempty"`
}

// Empty reports whether the rule has no conditions (matches nothing — a safe
// default rather than "all hosts").
func (r *GroupRule) Empty() bool {
	return r == nil || (r.Environment == "" && len(r.TagsAll) == 0 && len(r.TagsAny) == 0 &&
		r.OSContains == "" && r.HostnameContains == "")
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
	// Overlay is the per-host reachability transport chosen at enrollment: "" (use the
	// deployment default FLEET_OVERLAY), "wireguard" or "openvpn". The
	// assigned overlay address lives in WGAddress regardless of transport.
	Overlay  string   `json:"overlay,omitempty"`
	SSHPort  int      `json:"sshPort"`
	SSHUser  string   `json:"sshUser"`
	Tags     []string `json:"tags"`
	Enrolled bool     `json:"enrolled"`
	// AuthMethod is how the host authenticates: fleet_cert (default, ephemeral
	// certificates) | vault_password | vault_ssh_key (a vaulted credential injected
	// at connect time). CredentialID references the vault secret when vaulted.
	AuthMethod   string     `json:"authMethod"`
	CredentialID *uuid.UUID `json:"credentialId,omitempty"`
	// Protocol is how Fleet reaches the host: ssh (default; terminal/SFTP) or rdp
	// (Windows desktop brokered through guacd, on RDPPort).
	Protocol   string     `json:"protocol"`
	RDPPort    int        `json:"rdpPort"`
	RDPOptions RDPOptions `json:"rdpOptions"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	// MaintenanceUntil, when set to a future time, marks the host "in maintenance":
	// offline/recovered alerts and dashboard attention items are suppressed.
	MaintenanceUntil *time.Time `json:"maintenanceUntil,omitempty"`

	Groups    []string       `json:"groups,omitempty"`
	Inventory *HostInventory `json:"inventory,omitempty"`
	Status    *HostStatus    `json:"status,omitempty"`
	Metrics   *HostMetrics   `json:"metrics,omitempty"`
}

// InMaintenance reports whether the host is currently within a maintenance window,
// during which offline/recovered alerts and dashboard attention items are suppressed.
func (h *Host) InMaintenance() bool {
	return h.MaintenanceUntil != nil && h.MaintenanceUntil.After(time.Now())
}

// RDPOptions are per-host display/security and clipboard settings applied when
// brokering an RDP session to guacd. Zero values mean "guacd default", preserving
// the original behaviour. Clipboard copy/paste are off unless explicitly enabled —
// they are data-exfiltration surfaces, so a host owner opts in per direction.
type RDPOptions struct {
	Security      string `json:"security,omitempty"`      // any (default) | nla | tls | rdp | vmconnect
	ColorDepth    int    `json:"colorDepth,omitempty"`    // 0 (default) | 8 | 16 | 24 | 32
	Width         int    `json:"width,omitempty"`         // 0 = use the browser's size
	Height        int    `json:"height,omitempty"`        // 0 = use the browser's size
	DPI           int    `json:"dpi,omitempty"`           // 0 = guacd default (96)
	DisableAudio  bool   `json:"disableAudio,omitempty"`  // mute the remote audio channel
	EnableTheming bool   `json:"enableTheming,omitempty"` // wallpaper + theming + font smoothing
	Domain        string `json:"domain,omitempty"`        // Windows/AD domain to authenticate against

	ClipboardCopy  bool `json:"clipboardCopy,omitempty"`  // allow remote -> local clipboard
	ClipboardPaste bool `json:"clipboardPaste,omitempty"` // allow local -> remote clipboard

	// Drive redirection (file transfer) exposes a virtual drive in the RDP session.
	// Off unless EnableDrive; each transfer direction is separately gated.
	EnableDrive   bool `json:"enableDrive,omitempty"`
	DriveUpload   bool `json:"driveUpload,omitempty"`   // allow browser -> drive
	DriveDownload bool `json:"driveDownload,omitempty"` // allow drive -> browser
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
	// UpdatePackages is the actual pending-update package list (bounded), so the UI and
	// the assistant can answer "which packages need updating on host X", not just how
	// many. Nil = not yet collected; empty = collected and up to date.
	UpdatePackages []PendingUpdate `json:"updatePackages,omitempty"`
}

// PendingUpdate is one upgradable package on a host.
type PendingUpdate struct {
	Package    string `json:"package"`
	NewVersion string `json:"newVersion,omitempty"`
	Security   bool   `json:"security,omitempty"`
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

// RDPRecording is replay metadata for an RDP (Windows desktop) session. The
// recording itself is a Guacamole-protocol stream written by guacd to a shared
// volume; Path (hidden from JSON) points at that file.
type RDPRecording struct {
	ID         uuid.UUID  `json:"id"`
	HostID     *uuid.UUID `json:"hostId,omitempty"`
	UserID     *uuid.UUID `json:"userId,omitempty"`
	Hostname   string     `json:"hostname"`
	FleetUser  string     `json:"fleetUser"`
	RDPUser    string     `json:"rdpUser"`
	Format     string     `json:"format"`
	Path       string     `json:"-"`
	SizeBytes  int64      `json:"sizeBytes"`
	DurationMS int64      `json:"durationMs"`
	Status     string     `json:"status"`
	ClientIP   string     `json:"clientIp"`
	StartedAt  time.Time  `json:"startedAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
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
	DecidedByName string     `json:"decidedByName,omitempty"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
	DecisionNote  string     `json:"decisionNote,omitempty"`
	GrantedSecs   *int64     `json:"grantedSecs,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

// ExpiredGrant describes a temporary permission that the reaper just expired,
// with enough context to notify the user whose access ended.
type ExpiredGrant struct {
	RequestID  *uuid.UUID
	UserID     uuid.UUID
	Username   string
	UserEmail  string
	TargetKind string // host|group
	TargetName string
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
	ID         uuid.UUID        `json:"id"`
	HostID     *uuid.UUID       `json:"hostId,omitempty"`
	Target     string           `json:"target"`
	OSHint     string           `json:"osHint,omitempty"`
	Status     string           `json:"status"`
	Steps      []EnrollmentStep `json:"steps"`
	Error      string           `json:"error,omitempty"`
	CreatedBy  *uuid.UUID       `json:"createdBy,omitempty"`
	CreatedAt  time.Time        `json:"createdAt"`
	StartedAt  *time.Time       `json:"startedAt,omitempty"`
	FinishedAt *time.Time       `json:"finishedAt,omitempty"`
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
	Seq        int64      `json:"seq"`
	ID         uuid.UUID  `json:"id"`
	ActorID    *uuid.UUID `json:"actorId,omitempty"`
	ActorName  string     `json:"actorName,omitempty"`
	Action     string     `json:"action"`
	TargetKind string     `json:"targetKind,omitempty"`
	TargetID   string     `json:"targetId,omitempty"`
	// TargetName is a display-only, human-readable name for the target (e.g. the
	// username or hostname behind TargetID). It is resolved at read time for the
	// UI and never persisted or part of the hash chain.
	TargetName string         `json:"targetName,omitempty"`
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
	Scheduled    bool       `json:"scheduled"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// ScanProfile is a SCAP profile available in a host's datastream.
type ScanProfile struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// ReviewScope selects which grants an access review snapshots.
type ReviewScope struct {
	Type    string      `json:"type"` // all | group | user
	GroupID *uuid.UUID  `json:"groupId,omitempty"`
	UserIDs []uuid.UUID `json:"userIds,omitempty"`
}

// AccessReview is an access-certification campaign: a point-in-time snapshot of
// access grants to be kept or revoked by a reviewer.
type AccessReview struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Scope       ReviewScope `json:"scope"`
	Status      string      `json:"status"`
	CreatedBy   string      `json:"createdBy,omitempty"`
	CreatedAt   time.Time   `json:"createdAt"`
	DueAt       *time.Time  `json:"dueAt,omitempty"`
	CompletedAt *time.Time  `json:"completedAt,omitempty"`
	Total       int         `json:"total"`
	Pending     int         `json:"pending"`
	Kept        int         `json:"kept"`
	Revoked     int         `json:"revoked"`
}

// AccessReviewItem is one grant under review: a user's access to a group or host.
type AccessReviewItem struct {
	ID           uuid.UUID  `json:"id"`
	SubjectUser  string     `json:"subjectUser"`
	SubjectIsSvc bool       `json:"subjectIsServiceAccount"`
	GrantKind    string     `json:"grantKind"`    // group_membership | direct_host
	ResourceKind string     `json:"resourceKind"` // group | host
	ResourceName string     `json:"resourceName"`
	Decision     string     `json:"decision"` // pending | keep | revoke
	Note         string     `json:"note,omitempty"`
	DecidedBy    string     `json:"decidedBy,omitempty"`
	DecidedAt    *time.Time `json:"decidedAt,omitempty"`
}

// VulnScan is one vulnerability scan of a host (package CVE matching via Grype),
// with a per-severity finding breakdown.
type VulnScan struct {
	ID         uuid.UUID  `json:"id"`
	HostID     uuid.UUID  `json:"hostId"`
	Hostname   string     `json:"hostname,omitempty"`
	Requester  string     `json:"requester"`
	Scheduled  bool       `json:"scheduled"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	DBBuiltAt  *time.Time `json:"dbBuiltAt,omitempty"`
	Total      int        `json:"total"`
	Critical   int        `json:"critical"`
	High       int        `json:"high"`
	Medium     int        `json:"medium"`
	Low        int        `json:"low"`
	Negligible int        `json:"negligible"`
	Unknown    int        `json:"unknown"`
	Fixable    int        `json:"fixable"`
	MaxCVSS    float64    `json:"maxCvss"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// VulnFinding is one CVE affecting one installed package.
// WindowsSoftware is one installed application on a Windows host, from the registry
// Uninstall keys (collected over WinRM). Powers the software inventory and the
// third-party CVE matching.
type WindowsSoftware struct {
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Publisher   string    `json:"publisher,omitempty"`
	CollectedAt time.Time `json:"collectedAt"`
}

// MSRCEntry is one KB→CVE mapping from Microsoft's Security Update Guide (CVRF):
// installing KB remediates CVE, which carries this severity/CVSS. Used to enrich
// Windows vulnerability findings.
type MSRCEntry struct {
	KB       string  `json:"kb"`
	CVE      string  `json:"cve"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
	Vector   string  `json:"vector,omitempty"`
	Title    string  `json:"title,omitempty"`
	Release  string  `json:"release,omitempty"`
}

type VulnFinding struct {
	CVE              string  `json:"cve"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion,omitempty"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvssScore"`
	CVSSVector       string  `json:"cvssVector,omitempty"`
	DataSource       string  `json:"dataSource,omitempty"`
	Description      string  `json:"description,omitempty"`
}

// AssistantHostRow is a compact host record returned to the AI assistant's
// query tool (one row per host, joined from status/metrics/inventory).
type AssistantHostRow struct {
	Hostname         string     `json:"hostname"`
	Environment      string     `json:"environment,omitempty"`
	Status           string     `json:"status"`
	PrimaryIP        string     `json:"primaryIp,omitempty"`
	OSName           string     `json:"os,omitempty"`
	OSVersion        string     `json:"osVersion,omitempty"`
	Kernel           string     `json:"kernel,omitempty"`
	Architecture     string     `json:"arch,omitempty"`
	CPUCount         int        `json:"cpuCount,omitempty"`
	MemoryTotalMB    int64      `json:"memoryMb,omitempty"`
	SSHVersion       string     `json:"sshVersion,omitempty"`
	UptimeSeconds    *int64     `json:"uptimeSeconds,omitempty"`
	MinDiskFreePct   *float64   `json:"diskFreePct,omitempty"`
	MemUsedPct       *float64   `json:"memUsedPct,omitempty"`
	LoadPerCore      *float64   `json:"loadPerCore,omitempty"`
	LatencyMS        *int       `json:"latencyMs,omitempty"`
	WGOK             *bool      `json:"wireguardOk,omitempty"`
	LastSeen         *time.Time `json:"lastSeen,omitempty"`
	UpdatesAvailable *int       `json:"updatesAvailable,omitempty"`
	SecurityUpdates  *int       `json:"securityUpdates,omitempty"`
	Groups           []string   `json:"groups,omitempty"`
	Tags             []string   `json:"tags,omitempty"`
	Owner            string     `json:"owner,omitempty"`
	Enrolled         bool       `json:"enrolled"`
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
	Scheduled  bool       `json:"scheduled"`
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
	Scheduled  bool       `json:"scheduled"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// AssistantSSHSessionRow is a past (or still-active) SSH session surfaced to
// the AI assistant's session_history tool.
type AssistantSSHSessionRow struct {
	Username  string     `json:"username,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	ClientIP  string     `json:"clientIp,omitempty"`
	Status    string     `json:"status"` // active|closed|error
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
}

// AssistantAuditRow is one audit event surfaced to the AI assistant.
type AssistantAuditRow struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor,omitempty"`
	Action     string    `json:"action"`
	TargetKind string    `json:"targetKind,omitempty"`
	TargetID   string    `json:"targetId,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Detail     string    `json:"detail,omitempty"` // compact JSON, truncated
}

// AssistantScheduleRow is a recurring scan/playbook schedule surfaced to the
// AI assistant.
type AssistantScheduleRow struct {
	Name       string     `json:"name"`
	Kind       string     `json:"kind"` // scan | playbook
	Enabled    bool       `json:"enabled"`
	Target     string     `json:"target,omitempty"` // "host web-01" / "group dba"
	Recurrence string     `json:"recurrence"`       // human summary
	LastRunAt  *time.Time `json:"lastRunAt,omitempty"`
	LastStatus string     `json:"lastStatus,omitempty"`
	NextRunAt  *time.Time `json:"nextRunAt,omitempty"`
	Running    bool       `json:"running"`
}

// AssistantTransferRow is one SFTP transfer surfaced to the AI assistant.
type AssistantTransferRow struct {
	Username  string    `json:"username,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Direction string    `json:"direction"` // upload | download
	Path      string    `json:"path"`
	SizeBytes int64     `json:"sizeBytes"`
	Status    string    `json:"status"`
	Time      time.Time `json:"time"`
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

// RemediationJob is a lightweight view of a remediation run for the background-
// job log: enough to see which host it targeted, who started it, and whether it
// is still running — without the (potentially large) output blob.
type RemediationJob struct {
	ID         uuid.UUID  `json:"id"`
	HostID     uuid.UUID  `json:"hostId"`
	Hostname   string     `json:"hostname"`
	Requester  string     `json:"requester,omitempty"`
	RuleCount  int        `json:"ruleCount"`
	Status     string     `json:"status"` // pending|running|completed|failed
	ExitCode   *int       `json:"exitCode,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}
