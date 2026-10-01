package prov

import "time"

// Host is a managed system in the fleet. Fields mirror the API's host object;
// optional sections (Inventory, Status, Metrics) are omitted here since the SDK
// focuses on inventory-as-code — use the raw endpoints if you need live metrics.
type Host struct {
	ID          string    `json:"id"`
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
	Groups      []string  `json:"groups,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// HostInput is the create/update payload for a host.
type HostInput struct {
	Hostname    string   `json:"hostname"`
	Description string   `json:"description,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Address     string   `json:"address,omitempty"`
	WGAddress   string   `json:"wgAddress,omitempty"`
	SSHPort     int      `json:"sshPort,omitempty"`
	SSHUser     string   `json:"sshUser,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// User is a Provenance user account.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"displayName"`
	IsSuperAdmin bool      `json:"isSuperAdmin"`
	IsDisabled   bool      `json:"isDisabled"`
	AuthSource   string    `json:"authSource,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	Groups       []string  `json:"groups,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}

// Role is a named set of permissions.
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"isBuiltin"`
	Permissions []string  `json:"permissions,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Permission is a single capability key.
type Permission struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}

// GroupRule defines dynamic group membership over stable host attributes. A host
// matches when every non-empty condition holds. Live metrics are intentionally
// excluded so membership (and access) does not flap.
type GroupRule struct {
	Environment      string   `json:"environment,omitempty"`
	TagsAll          []string `json:"tagsAll,omitempty"`
	TagsAny          []string `json:"tagsAny,omitempty"`
	OSContains       string   `json:"osContains,omitempty"`
	HostnameContains string   `json:"hostnameContains,omitempty"`
}

// Group authorizes users to hosts via shared membership. A non-nil Rule means
// membership is rule-managed (dynamic) rather than manual.
type Group struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Rule        *GroupRule `json:"rule,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	// HostCount is the number of host members. Only the group listing computes it;
	// nil means "not reported" rather than zero.
	HostCount *int `json:"hostCount,omitempty"`
}

// GroupHost is a host member of a group: identity fields only. Use ListHosts for
// full host records including connection details.
type GroupHost struct {
	ID          string   `json:"id"`
	Hostname    string   `json:"hostname"`
	Description string   `json:"description"`
	Environment string   `json:"environment"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
	Enrolled    bool     `json:"enrolled"`
}

// GroupInput is the create/update payload for a group.
type GroupInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Rule        *GroupRule `json:"rule,omitempty"`
}

// ServiceAccount is a non-interactive identity that authenticates with API tokens.
type ServiceAccount struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	IsDisabled  bool       `json:"isDisabled"`
	Roles       []string   `json:"roles"`
	Groups      []string   `json:"groups"`
	TokenCount  int        `json:"tokenCount"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// ServiceAccountInput is the create payload for a service account. RoleIDs and
// GroupIDs are the UUIDs of roles/groups to grant.
type ServiceAccountInput struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName,omitempty"`
	RoleIDs     []string `json:"roleIds,omitempty"`
	GroupIDs    []string `json:"groupIds,omitempty"`
}

// APIToken is a hashed bearer credential belonging to a service account. Secret
// holds the full token and is populated only by CreateToken (shown once).
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	Secret     string     `json:"secret,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// TokenInput is the create payload for an API token. ExpiresInDays of 0 means the
// token does not expire.
type TokenInput struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays,omitempty"`
}

// VulnScan is a vulnerability scan of one host, with severity rollups.
type VulnScan struct {
	ID         string  `json:"id"`
	HostID     string  `json:"hostId"`
	Hostname   string  `json:"hostname,omitempty"`
	Requester  string  `json:"requester"`
	Scheduled  bool    `json:"scheduled"`
	Status     string  `json:"status"` // pending|running|completed|failed
	Error      string  `json:"error,omitempty"`
	Total      int     `json:"total"`
	Critical   int     `json:"critical"`
	High       int     `json:"high"`
	Medium     int     `json:"medium"`
	Low        int     `json:"low"`
	Negligible int     `json:"negligible"`
	Unknown    int     `json:"unknown"`
	MaxCVSS    float64 `json:"maxCvss"`
	// Fixable is the actionable subset: CVEs with a fix available now. WontFix are
	// those the distribution assessed and will never fix. The Fixable* severity
	// counts break the actionable subset down — automation should gate on those
	// rather than on Critical/High, which count every CVE regardless of whether a
	// fix exists and stay high on a fully-patched host.
	Fixable         int        `json:"fixable"`
	WontFix         int        `json:"wontFix"`
	FixableCritical int        `json:"fixableCritical"`
	FixableHigh     int        `json:"fixableHigh"`
	FixableMedium   int        `json:"fixableMedium"`
	FixableMaxCVSS  float64    `json:"fixableMaxCvss"`
	StartedAt       *time.Time `json:"startedAt,omitempty"`
	FinishedAt      *time.Time `json:"finishedAt,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
}

// VulnFinding is one CVE affecting one installed package.
type VulnFinding struct {
	CVE     string `json:"cve"`
	Package string `json:"package"`
	// SourcePackage is the source package the CVE was matched against. Distro
	// trackers key on the source, so one source repeats its CVEs across every binary
	// it builds — group on this to count components rather than package rows.
	SourcePackage    string  `json:"sourcePackage,omitempty"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion,omitempty"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvssScore"`
	CVSSVector       string  `json:"cvssVector,omitempty"`
	DataSource       string  `json:"dataSource,omitempty"`
	Description      string  `json:"description,omitempty"`
}

// VulnScanDetail is a scan plus its findings, returned by GetVulnScan.
type VulnScanDetail struct {
	VulnScan
	Findings []VulnFinding `json:"findings"`
}

// Version describes the running deployment.
type Version struct {
	Version     string `json:"version"`
	Environment string `json:"environment"`
	AppName     string `json:"appName"`
}

// Identity is the account the current API token authenticates as, with its
// effective permissions.
type Identity struct {
	User         User     `json:"user"`
	Permissions  []string `json:"permissions"`
	IsSuperAdmin bool     `json:"isSuperAdmin"`
}

// NetScan is one address scanned from the network on one path.
type NetScan struct {
	ID               string       `json:"id"`
	RunID            string       `json:"runId"`
	HostID           string       `json:"hostId,omitempty"`
	Hostname         string       `json:"hostname,omitempty"`
	RangeID          string       `json:"rangeId,omitempty"`
	RangeName        string       `json:"rangeName,omitempty"`
	Target           string       `json:"target"`
	Path             string       `json:"path"`   // lan | overlay | range
	Status           string       `json:"status"` // pending|running|completed|unreachable|failed
	Error            string       `json:"error,omitempty"`
	Reason           string       `json:"reason,omitempty"`
	TemplatesVersion string       `json:"templatesVersion,omitempty"`
	OpenPorts        int          `json:"openPorts"`
	Total            int          `json:"total"`
	Critical         int          `json:"critical"`
	High             int          `json:"high"`
	Medium           int          `json:"medium"`
	Low              int          `json:"low"`
	Unexpected       int          `json:"unexpected"`
	ListenersKnown   bool         `json:"listenersKnown"`
	Warnings         []string     `json:"warnings,omitempty"`
	CreatedAt        time.Time    `json:"createdAt"`
	FinishedAt       *time.Time   `json:"finishedAt,omitempty"`
	Services         []NetService `json:"services,omitempty"`
	Findings         []NetFinding `json:"findings,omitempty"`
}

// NetService is what answered on one port.
type NetService struct {
	Port       int    `json:"port"`
	Proto      string `json:"proto"`
	Service    string `json:"service,omitempty"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	TLS        bool   `json:"tls"`
	Process    string `json:"process,omitempty"`
	Unexpected bool   `json:"unexpected"`
}

// NetFinding is a vulnerability or misconfiguration observed from the network.
type NetFinding struct {
	TemplateID    string   `json:"templateId"`
	Name          string   `json:"name"`
	Severity      string   `json:"severity"`
	Port          int      `json:"port"`
	Proto         string   `json:"proto"`
	CVEs          []string `json:"cves,omitempty"`
	CVSSScore     float64  `json:"cvssScore"`
	Description   string   `json:"description,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
	Corroboration string   `json:"corroboration,omitempty"` // confirmed | banner-only
}

// NetScanRange is an operator-defined network range scanned for unmanaged devices.
type NetScanRange struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	CIDR     string     `json:"cidr"`
	Note     string     `json:"note"`
	Enabled  bool       `json:"enabled"`
	LastScan *time.Time `json:"lastScan,omitempty"`
	LastLive int        `json:"lastLive"`
}

// NetScanRangeInput creates or updates a range. Enabled is required on update.
type NetScanRangeInput struct {
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Note    string `json:"note"`
	Enabled *bool  `json:"enabled"`
}
