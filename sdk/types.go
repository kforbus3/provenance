package fleet

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

// User is a Fleet user account.
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
	ID         string     `json:"id"`
	HostID     string     `json:"hostId"`
	Hostname   string     `json:"hostname,omitempty"`
	Requester  string     `json:"requester"`
	Scheduled  bool       `json:"scheduled"`
	Status     string     `json:"status"` // pending|running|completed|failed
	Error      string     `json:"error,omitempty"`
	Total      int        `json:"total"`
	Critical   int        `json:"critical"`
	High       int        `json:"high"`
	Medium     int        `json:"medium"`
	Low        int        `json:"low"`
	Negligible int        `json:"negligible"`
	Unknown    int        `json:"unknown"`
	MaxCVSS    float64    `json:"maxCvss"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// VulnFinding is one CVE affecting one installed package.
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
