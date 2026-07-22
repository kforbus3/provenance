// Package accesspolicy implements attribute-based access control (ABAC): contextual
// rules that can DENY a host connection RBAC would otherwise permit, based on host
// attributes, the time of day, and the subject's roles. Policies only restrict access;
// they never grant it beyond RBAC. The engine (this file) is pure and side-effect free
// so it can be unit-tested exhaustively; the enforcer (enforcer.go) loads rules and the
// subject from the store and applies the decision at each connect choke point.
package accesspolicy

import (
	"strings"
	"time"
)

// Rule is a compiled access policy. Empty match slices are wildcards.
type Rule struct {
	ID           string
	Name         string
	Priority     int
	Environments []string
	Tags         []string
	Protocols    []string
	ExemptRoles  []string
	ActiveDays   []int // 0=Sunday..6=Saturday; empty = all days
	ActiveStart  int   // minutes since midnight
	ActiveEnd    int   // minutes since midnight; == ActiveStart means "no time restriction"
	DenyMessage  string
}

// Subject is the user attempting the connection.
type Subject struct {
	Roles        []string
	IsSuperAdmin bool
}

// HostAttrs are the host attributes a rule matches against.
type HostAttrs struct {
	Environment string
	Tags        []string
	Protocol    string
}

// Decision is the outcome of evaluating the policy set for one connection attempt.
type Decision struct {
	Denied   bool
	RuleID   string
	RuleName string
	Reason   string
}

// Evaluate returns the first matching deny rule's decision, or an allow decision if no
// rule matches. Rules must be pre-sorted by priority (ascending). Super administrators
// are never denied — this prevents an over-broad policy from locking out the operators
// who would need to fix it. `now` must already be in the timezone the windows are
// expressed in.
func Evaluate(rules []Rule, subject Subject, host HostAttrs, now time.Time) Decision {
	if subject.IsSuperAdmin {
		return Decision{}
	}
	for i := range rules {
		r := &rules[i]
		if r.matches(subject, host, now) {
			reason := r.DenyMessage
			if reason == "" {
				reason = "Access denied by policy: " + r.Name
			}
			return Decision{Denied: true, RuleID: r.ID, RuleName: r.Name, Reason: reason}
		}
	}
	return Decision{}
}

func (r *Rule) matches(subject Subject, host HostAttrs, now time.Time) bool {
	// Subject exemption: holding any exempt role skips the rule entirely.
	if anyOverlap(subject.Roles, r.ExemptRoles) {
		return false
	}
	if len(r.Environments) > 0 && !containsFold(r.Environments, host.Environment) {
		return false
	}
	if len(r.Protocols) > 0 && !containsFold(r.Protocols, host.Protocol) {
		return false
	}
	if len(r.Tags) > 0 && !anyOverlapFold(host.Tags, r.Tags) {
		return false
	}
	if !r.timeActive(now) {
		return false
	}
	return true
}

// timeActive reports whether now falls inside the rule's active window. An empty day
// list means every day; equal start/end means no time restriction (always active).
func (r *Rule) timeActive(now time.Time) bool {
	if len(r.ActiveDays) > 0 {
		wd := int(now.Weekday()) // 0=Sunday..6=Saturday
		found := false
		for _, d := range r.ActiveDays {
			if d == wd {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.ActiveStart == r.ActiveEnd {
		return true // no intra-day time restriction
	}
	mins := now.Hour()*60 + now.Minute()
	if r.ActiveStart < r.ActiveEnd {
		return mins >= r.ActiveStart && mins < r.ActiveEnd
	}
	// Wraps past midnight (e.g. 18:00–09:00): active in either tail.
	return mins >= r.ActiveStart || mins < r.ActiveEnd
}

func anyOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func anyOverlapFold(a, b []string) bool {
	for _, x := range a {
		if containsFold(b, x) {
			return true
		}
	}
	return false
}

func containsFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
