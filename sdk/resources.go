package fleet

import (
	"context"
	"net/http"
	"net/url"
)

// ---- Deployment ------------------------------------------------------------

// Version returns the running deployment's version and environment. This
// endpoint is unauthenticated and is a convenient connectivity check.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v)
	return v, err
}

// Whoami returns the identity (and effective permissions) of the account the
// current API token authenticates as. Useful to verify a token and its scope.
func (c *Client) Whoami(ctx context.Context) (Identity, error) {
	var id Identity
	err := c.do(ctx, http.MethodGet, "/auth/me", nil, nil, &id)
	return id, err
}

// ---- Hosts -----------------------------------------------------------------

// ListHosts returns hosts visible to the token's identity.
func (c *Client) ListHosts(ctx context.Context, opts ListOptions) ([]Host, error) {
	var resp struct {
		Hosts []Host `json:"hosts"`
	}
	if err := c.do(ctx, http.MethodGet, "/hosts", opts.query(), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Hosts, nil
}

// GetHost returns a single host by id.
func (c *Client) GetHost(ctx context.Context, id string) (Host, error) {
	var h Host
	err := c.do(ctx, http.MethodGet, "/hosts/"+url.PathEscape(id), nil, nil, &h)
	return h, err
}

// CreateHost registers a new host (requires Host.Enroll).
func (c *Client) CreateHost(ctx context.Context, in HostInput) (Host, error) {
	var h Host
	err := c.do(ctx, http.MethodPost, "/hosts", nil, in, &h)
	return h, err
}

// UpdateHost updates an existing host (requires Host.Edit).
func (c *Client) UpdateHost(ctx context.Context, id string, in HostInput) (Host, error) {
	var h Host
	err := c.do(ctx, http.MethodPut, "/hosts/"+url.PathEscape(id), nil, in, &h)
	return h, err
}

// DeleteHost removes a host (requires Host.Delete).
func (c *Client) DeleteHost(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/hosts/"+url.PathEscape(id), nil, nil, nil)
}

// AddHostToGroup adds a host to a group (requires Host.Edit).
func (c *Client) AddHostToGroup(ctx context.Context, hostID, groupID string) error {
	return c.do(ctx, http.MethodPost, "/hosts/"+url.PathEscape(hostID)+"/groups/"+url.PathEscape(groupID), nil, nil, nil)
}

// RemoveHostFromGroup removes a host from a group (requires Host.Edit).
func (c *Client) RemoveHostFromGroup(ctx context.Context, hostID, groupID string) error {
	return c.do(ctx, http.MethodDelete, "/hosts/"+url.PathEscape(hostID)+"/groups/"+url.PathEscape(groupID), nil, nil, nil)
}

// ---- Users -----------------------------------------------------------------

// ListUsers returns all users (requires User.Edit).
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, http.MethodGet, "/users", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// GetUser returns a single user by id (requires User.Edit).
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil, nil, &u)
	return u, err
}

// ---- Roles & permissions ---------------------------------------------------

// ListRoles returns all roles (requires Role.Edit).
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	var resp struct {
		Roles []Role `json:"roles"`
	}
	if err := c.do(ctx, http.MethodGet, "/roles", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Roles, nil
}

// ListPermissions returns the catalog of permission keys (requires Role.Edit).
func (c *Client) ListPermissions(ctx context.Context) ([]Permission, error) {
	var resp struct {
		Permissions []Permission `json:"permissions"`
	}
	if err := c.do(ctx, http.MethodGet, "/permissions", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Permissions, nil
}

// ---- Groups ----------------------------------------------------------------

// ListGroups returns all groups (requires Group.Edit).
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var resp struct {
		Groups []Group `json:"groups"`
	}
	if err := c.do(ctx, http.MethodGet, "/groups", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Groups, nil
}

// CreateGroup creates a group. Supply Rule for dynamic (rule-managed) membership
// (requires Group.Create).
func (c *Client) CreateGroup(ctx context.Context, in GroupInput) (Group, error) {
	var g Group
	err := c.do(ctx, http.MethodPost, "/groups", nil, in, &g)
	return g, err
}

// UpdateGroup updates a group's name/description/rule (requires Group.Edit).
func (c *Client) UpdateGroup(ctx context.Context, id string, in GroupInput) (Group, error) {
	var g Group
	err := c.do(ctx, http.MethodPut, "/groups/"+url.PathEscape(id), nil, in, &g)
	return g, err
}

// DeleteGroup removes a group (requires Group.Delete).
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/groups/"+url.PathEscape(id), nil, nil, nil)
}

// ---- Service accounts & tokens ---------------------------------------------

// ListServiceAccounts returns all service accounts (requires ServiceAccount.Manage).
func (c *Client) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	var resp struct {
		ServiceAccounts []ServiceAccount `json:"serviceAccounts"`
	}
	if err := c.do(ctx, http.MethodGet, "/service-accounts", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.ServiceAccounts, nil
}

// CreateServiceAccount creates a service account (requires ServiceAccount.Manage).
func (c *Client) CreateServiceAccount(ctx context.Context, in ServiceAccountInput) (ServiceAccount, error) {
	var sa ServiceAccount
	err := c.do(ctx, http.MethodPost, "/service-accounts", nil, in, &sa)
	return sa, err
}

// DeleteServiceAccount removes a service account and its tokens (requires
// ServiceAccount.Manage).
func (c *Client) DeleteServiceAccount(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/service-accounts/"+url.PathEscape(id), nil, nil, nil)
}

// ListTokens returns the API tokens of a service account (secrets are never
// returned here; only CreateToken returns the plaintext).
func (c *Client) ListTokens(ctx context.Context, serviceAccountID string) ([]APIToken, error) {
	var resp struct {
		Tokens []APIToken `json:"tokens"`
	}
	if err := c.do(ctx, http.MethodGet, "/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

// CreateToken issues a new API token for a service account. The returned token's
// Secret is the full "flt_" bearer credential and is shown only this once.
func (c *Client) CreateToken(ctx context.Context, serviceAccountID string, in TokenInput) (APIToken, error) {
	var tok APIToken
	err := c.do(ctx, http.MethodPost, "/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens", nil, in, &tok)
	return tok, err
}

// RevokeToken revokes a service account's API token.
func (c *Client) RevokeToken(ctx context.Context, serviceAccountID, tokenID string) error {
	return c.do(ctx, http.MethodDelete, "/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens/"+url.PathEscape(tokenID), nil, nil, nil)
}

// ---- Vulnerability scans ----------------------------------------------------

// ScanHost triggers a vulnerability scan of a single host and returns the created
// scan id(s) (requires Host.Scan).
func (c *Client) ScanHost(ctx context.Context, hostID string) ([]string, error) {
	return c.triggerScan(ctx, map[string]string{"hostId": hostID})
}

// ScanGroup triggers vulnerability scans for every host in a group and returns
// the created scan ids (requires Host.Scan).
func (c *Client) ScanGroup(ctx context.Context, groupID string) ([]string, error) {
	return c.triggerScan(ctx, map[string]string{"groupId": groupID})
}

func (c *Client) triggerScan(ctx context.Context, body map[string]string) ([]string, error) {
	var resp struct {
		ScanIDs []string `json:"scanIds"`
	}
	if err := c.do(ctx, http.MethodPost, "/vuln-scans", nil, body, &resp); err != nil {
		return nil, err
	}
	return resp.ScanIDs, nil
}

// ListVulnScans returns vulnerability scans. If hostID is non-empty, only that
// host's scans are returned (requires Host.Scan).
func (c *Client) ListVulnScans(ctx context.Context, hostID string) ([]VulnScan, error) {
	q := url.Values{}
	if hostID != "" {
		q.Set("hostId", hostID)
	}
	var resp struct {
		Scans []VulnScan `json:"scans"`
	}
	if err := c.do(ctx, http.MethodGet, "/vuln-scans", q, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Scans, nil
}

// LatestVulnScans returns the most recent scan per host (requires Host.Scan).
func (c *Client) LatestVulnScans(ctx context.Context) ([]VulnScan, error) {
	var resp struct {
		Scans []VulnScan `json:"scans"`
	}
	if err := c.do(ctx, http.MethodGet, "/vuln-scans/latest", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Scans, nil
}

// GetVulnScan returns a scan with its CVE findings (requires Host.Scan).
func (c *Client) GetVulnScan(ctx context.Context, id string) (VulnScanDetail, error) {
	var d VulnScanDetail
	err := c.do(ctx, http.MethodGet, "/vuln-scans/"+url.PathEscape(id), nil, nil, &d)
	return d, err
}

// ---- Reports (CSV evidence) ------------------------------------------------

// ReportKind identifies a schedulable/exportable CSV report.
type ReportKind string

const (
	ReportAccess          ReportKind = "access"
	ReportAudit           ReportKind = "audit"
	ReportCertificates    ReportKind = "certificates"
	ReportScans           ReportKind = "scans"
	ReportVulnerabilities ReportKind = "vulnerabilities"
)

// Report downloads a CSV evidence report of the given kind over an optional date
// range. from/to are inclusive dates ("2006-01-02" or RFC3339); empty means
// unbounded. Requires Audit.View.
func (c *Client) Report(ctx context.Context, kind ReportKind, from, to string) ([]byte, error) {
	q := url.Values{}
	if from != "" {
		q.Set("from", from)
	}
	if to != "" {
		q.Set("to", to)
	}
	return c.doRaw(ctx, http.MethodGet, "/reports/"+string(kind)+".csv", q, "text/csv")
}
