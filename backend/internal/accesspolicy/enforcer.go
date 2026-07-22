package accesspolicy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// RequestIP is a best-effort client-IP extractor for audit records (the reverse proxy
// sets X-Forwarded-For; realIP middleware has already validated it upstream).
func RequestIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// Enforcer loads enabled policies, the subject's roles, and the configured timezone,
// then evaluates the pure engine. It is used at every interactive connect choke point
// after the RBAC/host-access check succeeds.
type Enforcer struct {
	st  *store.Store
	log *slog.Logger
}

func NewEnforcer(st *store.Store, log *slog.Logger) *Enforcer {
	return &Enforcer{st: st, log: log}
}

// Check evaluates ABAC for one connection attempt. Super admins are never denied. On a
// store error it FAILS OPEN (allows) and logs: ABAC restricts access on top of RBAC —
// it is not the primary authorization — so a policy-store hiccup must not sever all
// access. This mirrors the existing conditional-access (enforceSessionPolicy) behavior.
func (e *Enforcer) Check(ctx context.Context, userID uuid.UUID, isSuper bool, host HostAttrs) Decision {
	if isSuper {
		return Decision{}
	}
	pols, err := e.st.EnabledAccessPolicies(ctx)
	if err != nil {
		e.log.Warn("access-policy: could not load policies, allowing", "error", err)
		return Decision{}
	}
	if len(pols) == 0 {
		return Decision{}
	}
	roles, err := e.st.UserRoleNames(ctx, userID)
	if err != nil {
		e.log.Warn("access-policy: could not load user roles", "error", err, "user", userID)
	}
	loc := time.Local
	if name := e.st.DisplayTimezone(ctx); name != "" {
		if l, lerr := time.LoadLocation(name); lerr == nil {
			loc = l
		}
	}
	rules := compile(pols)
	return Evaluate(rules, Subject{Roles: roles, IsSuperAdmin: isSuper}, host, time.Now().In(loc))
}

// ConnCtx describes one connection attempt for policy evaluation and audit.
type ConnCtx struct {
	UserID      uuid.UUID
	Username    string
	IsSuper     bool
	HostID      uuid.UUID
	HostName    string
	Environment string
	Tags        []string
	Protocol    string
	Surface     string // "terminal" | "rdp" | "sftp" | "command"
	IP          string
}

// Authorize evaluates ABAC for a connection and, on a deny, writes an audit event.
// Returns the Decision; the caller refuses the connection when Denied is true. This is
// the method the connect surfaces call (one line each).
func (e *Enforcer) Authorize(ctx context.Context, c ConnCtx) Decision {
	dec := e.Check(ctx, c.UserID, c.IsSuper, HostAttrs{Environment: c.Environment, Tags: c.Tags, Protocol: c.Protocol})
	if dec.Denied {
		uid := c.UserID
		_, _ = e.st.AppendAudit(ctx, models.AuditEvent{
			ActorID: &uid, ActorName: c.Username, Action: "access.denied",
			TargetKind: "host", TargetID: c.HostID.String(), IP: c.IP,
			Detail: map[string]any{
				"host": c.HostName, "surface": c.Surface,
				"policy": dec.RuleName, "policyId": dec.RuleID, "reason": dec.Reason,
			},
		})
	}
	return dec
}

// compile converts stored policies (already priority-ordered by the query) into engine
// rules.
func compile(pols []store.AccessPolicy) []Rule {
	rules := make([]Rule, len(pols))
	for i, p := range pols {
		days := make([]int, len(p.ActiveDays))
		for j, d := range p.ActiveDays {
			days[j] = int(d)
		}
		rules[i] = Rule{
			ID:           p.ID.String(),
			Name:         p.Name,
			Priority:     p.Priority,
			Environments: p.Environments,
			Tags:         p.Tags,
			Protocols:    p.Protocols,
			ExemptRoles:  p.ExemptRoles,
			ActiveDays:   days,
			ActiveStart:  p.ActiveStart,
			ActiveEnd:    p.ActiveEnd,
			DenyMessage:  p.DenyMessage,
		}
	}
	return rules
}
