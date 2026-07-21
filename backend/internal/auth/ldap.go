package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

const ldapSettingKey = "ldap"

// ldapConfig is the persisted LDAP/Active Directory configuration.
type ldapConfig struct {
	Enabled         bool              `json:"enabled"`
	URL             string            `json:"url"` // ldap://host:389 or ldaps://host:636
	StartTLS        bool              `json:"startTls"`
	BindDN          string            `json:"bindDn"`
	BindPassword    string            `json:"bindPassword,omitempty"` // write-only
	BindPasswordEnc string            `json:"bindPasswordEnc,omitempty"`
	BaseDN          string            `json:"baseDn"`
	UserFilter      string            `json:"userFilter"` // %s = username, e.g. (sAMAccountName=%s)
	UsernameAttr    string            `json:"usernameAttr"`
	EmailAttr       string            `json:"emailAttr"`
	DisplayNameAttr string            `json:"displayNameAttr"`
	GroupsAttr      string            `json:"groupsAttr"`
	DefaultRole     string            `json:"defaultRole"`
	AutoProvision   bool              `json:"autoProvision"`
	GroupRoleMap    map[string]string `json:"groupRoleMap"`
}

func (c ldapConfig) userFilter() string {
	if c.UserFilter != "" {
		return c.UserFilter
	}
	return "(uid=%s)"
}
func attrOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (s *Service) ldapConfig(ctx context.Context) ldapConfig {
	var c ldapConfig
	if raw, err := s.store.GetSetting(ctx, ldapSettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

func (s *Service) ldapEnabled(ctx context.Context) bool {
	c := s.ldapConfig(ctx)
	return c.Enabled && c.URL != "" && c.BaseDN != ""
}

// authenticateLDAP verifies credentials against the directory and find-or-
// provisions the matching Fleet account.
func (s *Service) authenticateLDAP(ctx context.Context, username, password string) (*models.User, error) {
	c := s.ldapConfig(ctx)
	if !c.Enabled || c.URL == "" || c.BaseDN == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := ldap.DialURL(c.URL)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	defer conn.Close()
	if c.StartTLS {
		if err := conn.StartTLS(&tls.Config{ServerName: ldapHost(c.URL), MinVersion: tls.VersionTLS12}); err != nil {
			return nil, ErrInvalidCredentials
		}
	}
	// Bind a service account (or anonymously) to find the user's DN.
	if c.BindDN != "" {
		if err := conn.Bind(c.BindDN, s.ldapBindPassword(c)); err != nil {
			return nil, ErrInvalidCredentials
		}
	}
	uAttr := attrOr(c.UsernameAttr, "uid")
	eAttr := attrOr(c.EmailAttr, "mail")
	dAttr := attrOr(c.DisplayNameAttr, "cn")
	gAttr := attrOr(c.GroupsAttr, "memberOf")
	res, err := conn.Search(ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		fmt.Sprintf(c.userFilter(), ldap.EscapeFilter(username)),
		[]string{uAttr, eAttr, dAttr, gAttr}, nil,
	))
	if err != nil || len(res.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	entry := res.Entries[0]

	// Verify the password by binding as the user.
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	uname := entry.GetAttributeValue(uAttr)
	if uname == "" {
		uname = username
	}
	email := entry.GetAttributeValue(eAttr)
	display := entry.GetAttributeValue(dAttr)
	groups := entry.GetAttributeValues(gAttr)

	user, err := s.store.GetUserByUsername(ctx, uname)
	if err != nil && email != "" {
		user, err = s.store.GetUserByEmail(ctx, email)
	}
	if err != nil {
		if !c.AutoProvision {
			return nil, ErrInvalidCredentials
		}
		user, err = s.store.CreateUser(ctx, store.CreateUserParams{
			Username: uname, Email: email, DisplayName: display, AuthSource: "ldap",
			PasswordHash: "ldap", // unusable local password
		})
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		role := c.DefaultRole
		if role == "" {
			role = "Read-Only"
		}
		_ = s.store.AssignRoleByName(ctx, user.ID, role)
	}
	if user.IsDisabled {
		return nil, ErrAccountDisabled
	}
	// Group → role mapping (additive). Match on each group's CN.
	if len(c.GroupRoleMap) > 0 {
		for _, g := range groups {
			if role, ok := c.GroupRoleMap[ldapCN(g)]; ok && role != "" {
				_ = s.store.AssignRoleByName(ctx, user.ID, role)
			}
		}
	}
	return user, nil
}

func (s *Service) ldapBindPassword(c ldapConfig) string {
	if c.BindPasswordEnc == "" {
		return ""
	}
	p, err := secretbox.Open(s.cfg.CAKeyPassphrase, c.BindPasswordEnc)
	if err != nil {
		return ""
	}
	return string(p)
}

// ldapCN extracts the CN from a group DN ("CN=admins,OU=...") for role mapping.
func ldapCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if kv := strings.SplitN(strings.TrimSpace(part), "=", 2); len(kv) == 2 && strings.EqualFold(kv[0], "cn") {
			return kv[1]
		}
	}
	return dn
}

func ldapHost(url string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(url, "ldaps://"), "ldap://")
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// --- admin config handlers ---

func (h *Handler) ldapConfigGet(w http.ResponseWriter, r *http.Request) {
	c := h.svc.ldapConfig(r.Context())
	secretSet := c.BindPasswordEnc != ""
	c.BindPassword, c.BindPasswordEnc = "", ""
	writeJSON(w, http.StatusOK, map[string]any{"config": c, "secretSet": secretSet})
}

func (h *Handler) ldapConfigPut(w http.ResponseWriter, r *http.Request) {
	var c ldapConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cur := h.svc.ldapConfig(r.Context())
	if c.BindPassword != "" {
		enc, err := secretbox.Seal(h.svc.cfg.CAKeyPassphrase, []byte(c.BindPassword))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not seal secret")
			return
		}
		c.BindPasswordEnc = enc
	} else {
		c.BindPasswordEnc = cur.BindPasswordEnc
	}
	c.BindPassword = ""
	if err := h.svc.store.SetSetting(r.Context(), ldapSettingKey, c); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if p := MustPrincipal(r); p != nil {
		_, _ = h.svc.store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "system.ldap_config", TargetKind: "system",
			Detail: map[string]any{"enabled": c.Enabled, "url": c.URL},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}
