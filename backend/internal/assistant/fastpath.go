package assistant

import (
	"encoding/json"
	"regexp"
	"strings"
)

// The fast path deterministically routes a few unambiguous question shapes to the
// correct tool, instead of relying on the (often small, local) model to choose. It is
// deliberately HIGH-PRECISION: it only fires on clear phrasings, and anything it
// doesn't recognize falls through to the normal model-driven tool loop.

var (
	// "who ran/typed/executed/used <command>" or "did anyone/someone run/type <command>".
	whoRanRE = regexp.MustCompile(`(?i)\b(?:who(?:'s| has| have)?\s+(?:ran|run|typed|executed|used)|did\s+(?:anyone|someone|somebody)\s+(?:run|type|execute|use))\b\s+(.+)`)
	// A trailing "on <host>" / "for <host>" clause (host = a plausible hostname token).
	onHostRE = regexp.MustCompile(`(?i)\b(?:on|for)\s+([a-z0-9][a-z0-9._-]*)\s*$`)
	// The "the … command" wrapper people put around a bare command name.
	theWrapRE     = regexp.MustCompile(`(?i)^(?:the|a)\s+`)
	commandSuffix = regexp.MustCompile(`(?i)\s+(?:command|commands|cmd)\s*$`)
	trailingPunct = regexp.MustCompile(`[?.!\s]+$`)
	updateWordRE  = regexp.MustCompile(`(?i)updat|upgrad|patch`)
	// A reachability/downtime token: "offline", "outage(s)", "downtime",
	// "unreachable", or "<aux> [subject] down" (went/was/is/... [nas] down).
	downRE = regexp.MustCompile(`(?i)\b(?:offline|outages?|downtime|unreachable|(?:go(?:ne|es|ing)?|went|was|were|been|is|are)\s+(?:[a-z0-9._-]+\s+)?down)\b`)
	// A capacity/exhaustion phrase: running out / filling up / low on space, etc.
	capacityVerbRE = regexp.MustCompile(`(?i)\b(?:runn?ing?\s+out|ran\s+out|run\s+out|fill(?:ing)?\s+up|out\s+of\s+(?:disk|space|storage|memory|ram)|runn?ing?\s+low|low\s+on\s+(?:disk|space|storage|memory|ram)|used?\s+up|exhaust|runway|capacity)\b`)
	// "on <host>" / "for <host>" anywhere (not anchored to the end of the string).
	hostAnywhereRE = regexp.MustCompile(`(?i)\b(?:on|for)\s+([a-z0-9][a-z0-9._-]*)`)
	// An imperative that means "run a scan", so a vulnerability READ fast-path stands
	// down and lets the action/model path propose a scan instead.
	scanVerbRE = regexp.MustCompile(`(?i)\b(?:run|start|kick|initiate|perform|launch|trigger|do)\b[^.?!]*\bscan\b`)
)

// fastPathTool returns the tool + JSON args to run directly for an unambiguous
// question, or ok=false to defer to the model.
func fastPathTool(question string) (name string, args json.RawMessage, ok bool) {
	q := strings.TrimSpace(question)
	lq := strings.ToLower(q)

	// 1) "who ran <command>" -> search_commands (typed-command history).
	if m := whoRanRE.FindStringSubmatch(q); m != nil {
		cmd, host := parseCommandTail(m[1])
		if cmd != "" {
			a, _ := json.Marshal(searchCommandsArgs{Query: cmd, Hostname: host})
			return "search_commands", a, true
		}
	}

	// 2) pending-update questions -> host_updates (the focused package list).
	if updatesIntent(lq) {
		host := ""
		lqTrim := trailingPunct.ReplaceAllString(lq, "")
		if hm := onHostRE.FindStringSubmatch(lqTrim); hm != nil && !updateWordRE.MatchString(hm[1]) {
			host = hm[1]
		}
		a, _ := json.Marshal(hostUpdatesArgs{Hostname: host})
		return "host_updates", a, true
	}

	// 3) downtime / offline-history questions -> host_availability. This is the
	// misroute the model made worst (answering "did anything go offline?" from
	// typed-command search), so pin the clear phrasings deterministically.
	if availabilityIntent(lq) {
		host := ""
		lqTrim := trailingPunct.ReplaceAllString(lq, "")
		if hm := onHostRE.FindStringSubmatch(lqTrim); hm != nil {
			host = hm[1]
		}
		a, _ := json.Marshal(hostAvailabilityArgs{Hostname: host, Hours: hoursFromText(lq)})
		return "host_availability", a, true
	}

	// 4) capacity / runway questions -> capacity_outlook. Routes "will any host run
	// out of disk/memory" to a capacity-FILTERED insights view that answers plainly
	// when nothing is at risk, instead of dumping unrelated insight rows.
	if disk, mem, ok := capacityIntent(lq); ok {
		a, _ := json.Marshal(capacityArgs{Disk: disk, Memory: mem, Days: daysFromText(lq)})
		return "capacity_outlook", a, true
	}

	// 5) failed-login / brute-force / lockout questions -> security_events. (Kept
	// distinct from "security updates", which is a package-update question above.)
	if securityEventsIntent(lq) {
		a, _ := json.Marshal(securityEventsArgs{FailedOnly: true, Hours: 24})
		return "security_events", a, true
	}

	// 6) CVE / vulnerability READ questions -> vulnerabilities (not a "run a scan"
	// request, which the action path handles).
	if !scanVerbRE.MatchString(lq) && vulnReadIntent(lq) {
		host := ""
		if hm := hostAnywhereRE.FindStringSubmatch(lq); hm != nil {
			host = hm[1]
		}
		sev := ""
		if strings.Contains(lq, "critical") {
			sev = "critical"
		} else if strings.Contains(lq, "high") {
			sev = "high"
		}
		a, _ := json.Marshal(vulnArgs{Hostname: host, MinSeverity: sev})
		return "vulnerabilities", a, true
	}

	// 7) accounts / roles / MFA questions -> list_users (but not "who is connected").
	if withoutMFA, ok := usersIntent(lq); ok {
		a, _ := json.Marshal(listUsersArgs{WithoutMFA: withoutMFA})
		return "list_users", a, true
	}

	// 8) "which OS / kernel versions" inventory questions -> query_hosts (list all).
	if osInventoryIntent(lq) {
		a, _ := json.Marshal(queryHostsArgs{})
		return "query_hosts", a, true
	}

	// 9) disk-provenance follow-ups ("which filesystem is that / where did 31% come
	// from") -> host_detail, whose diskBreakdown names the driving mount. Only when a
	// host is identifiable.
	if diskProvenanceIntent(lq) {
		if hm := hostAnywhereRE.FindStringSubmatch(lq); hm != nil {
			a, _ := json.Marshal(hostDetailArgs{Hostname: hm[1]})
			return "host_detail", a, true
		}
	}

	// 10) aggregate / superlative host-metric questions ("how many hosts", "highest
	// CPU load", "longest uptime", "which hosts have high memory") -> query_hosts
	// (list all). These route fine on their own, but small models tend to hallucinate
	// the FINAL narration (parroting example phrases); routing here forces the grounded
	// narrate-from-data path instead. Kept last so specific intents win.
	if hostAggregateIntent(lq) {
		a, _ := json.Marshal(queryHostsArgs{})
		return "query_hosts", a, true
	}

	return "", nil, false
}

// hostAggregateIntent matches "how many hosts", superlative host-metric questions
// ("highest CPU load", "longest uptime"), and "high memory/cpu usage".
func hostAggregateIntent(lq string) bool {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") {
		return false
	}
	if strings.Contains(lq, "how many host") || strings.Contains(lq, "how many server") ||
		strings.Contains(lq, "number of host") || strings.Contains(lq, "host count") ||
		strings.Contains(lq, "total hosts") || strings.Contains(lq, "count of host") {
		return true
	}
	resource := func(s string) bool {
		for _, r := range []string{"host", "server", "cpu", "load", "memory", "ram", "disk", "uptime", "space", "machine"} {
			if strings.Contains(s, r) {
				return true
			}
		}
		return false
	}
	for _, sup := range []string{"highest", "lowest", "most", "least", "longest", "shortest",
		"top ", "maximum", "minimum", "biggest", "smallest", "greatest", "busiest"} {
		if strings.Contains(lq, sup) && resource(lq) {
			return true
		}
	}
	for _, hi := range []string{"high memory", "high cpu", "high load", "heavy load", "heavy memory",
		"high ram", "elevated memory", "elevated cpu", "high utilization", "high usage", "under heavy",
		"memory pressure", "cpu pressure"} {
		if strings.Contains(lq, hi) {
			return true
		}
	}
	return false
}

// securityEventsIntent matches failed-login / brute-force / lockout / MFA-failure
// questions (auth_events), deliberately NOT "security updates" (package updates).
func securityEventsIntent(lq string) bool {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") {
		return false
	}
	for _, t := range []string{
		"failed login", "failed logins", "login failure", "login failures",
		"brute forc", "brute-forc", "bruteforc", "login attempt", "lockout",
		"locked out", "account locked", "mfa failure", "authentication failure",
		"auth failure", "failed authentication", "failed sign", "failed to log",
	} {
		if strings.Contains(lq, t) {
			return true
		}
	}
	return false
}

// vulnReadIntent matches CVE/vulnerability questions.
func vulnReadIntent(lq string) bool {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") {
		return false
	}
	return strings.Contains(lq, "cve") || strings.Contains(lq, "vulnerabilit") || strings.Contains(lq, "vulnerable")
}

// usersIntent matches account/role/MFA questions and reports whether it asks
// specifically for accounts WITHOUT MFA. It stands down for "who is connected"
// style questions, which are about sessions, not the account list.
func usersIntent(lq string) (withoutMFA, ok bool) {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") {
		return false, false
	}
	// Session-style phrasings ("who logged into web-01", "who is connected") are
	// about sessions, not the account list. Note: bare "haven't logged in" (account
	// inactivity) is a users question, so only guard the host-directed forms.
	for _, t := range []string{"connected", "logged into", "logged in to", "session", "who is on", "currently on"} {
		if strings.Contains(lq, t) {
			return false, false
		}
	}
	mfa := strings.Contains(lq, "mfa") || strings.Contains(lq, "2fa") ||
		strings.Contains(lq, "two-factor") || strings.Contains(lq, "two factor") || strings.Contains(lq, "multi-factor")
	account := strings.Contains(lq, "administrator") || strings.Contains(lq, "admins") ||
		strings.Contains(lq, "user account") || strings.Contains(lq, "accounts") ||
		((strings.Contains(lq, "which") || strings.Contains(lq, "what") || strings.Contains(lq, "list") ||
			strings.Contains(lq, "show") || strings.Contains(lq, "how many")) && strings.Contains(lq, "user"))
	if !mfa && !account {
		return false, false
	}
	for _, t := range []string{"without mfa", "no mfa", "lack", "missing mfa", "don't have mfa", "do not have mfa",
		"without 2fa", "no 2fa", "not enrolled", "missing 2fa", "aren't enrolled", "no second factor"} {
		if strings.Contains(lq, t) {
			return true, true
		}
	}
	return false, true
}

// osInventoryIntent matches "which OS/kernel versions are deployed" fleet-wide
// inventory questions.
func osInventoryIntent(lq string) bool {
	for _, t := range []string{"os version", "os versions", "operating system", "which os", "what os",
		"os are", "distro", "distros", "distribution", "kernel version", "kernel versions", "which kernel"} {
		if strings.Contains(lq, t) {
			return true
		}
	}
	return false
}

// diskProvenanceIntent matches "which filesystem is that / where did the disk %
// come from" follow-ups about a host's headline disk-free number.
func diskProvenanceIntent(lq string) bool {
	if strings.Contains(lq, "which filesystem") || strings.Contains(lq, "which mount") || strings.Contains(lq, "what filesystem") {
		return true
	}
	if (strings.Contains(lq, "where") || strings.Contains(lq, "why")) &&
		(strings.Contains(lq, "come from") || strings.Contains(lq, "%") || strings.Contains(lq, "percent")) &&
		(strings.Contains(lq, "disk") || strings.Contains(lq, "free") || strings.Contains(lq, "space")) {
		return true
	}
	return false
}

// capacityIntent detects a "going to run out of disk/memory" question and which
// resource(s) it is about. ok=false means it is not a capacity question.
func capacityIntent(lq string) (disk, memory, ok bool) {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") || strings.Contains(lq, "how can") {
		return false, false, false
	}
	if !capacityVerbRE.MatchString(lq) {
		return false, false, false
	}
	memory = strings.Contains(lq, "memory") || strings.Contains(lq, "ram")
	disk = strings.Contains(lq, "disk") || strings.Contains(lq, "space") ||
		strings.Contains(lq, "storage") || strings.Contains(lq, "/")
	if !disk && !memory {
		disk = true // a bare "running out"/"capacity" defaults to disk
	}
	return disk, memory, true
}

// daysFromText maps a coarse horizon phrase to a day window for capacity answers.
func daysFromText(lq string) int {
	switch {
	case strings.Contains(lq, "today"), strings.Contains(lq, "tomorrow"), strings.Contains(lq, "24 h"), strings.Contains(lq, "24h"):
		return 1
	case strings.Contains(lq, "month"):
		return 30
	case strings.Contains(lq, "two week"), strings.Contains(lq, "2 week"), strings.Contains(lq, "14 day"):
		return 14
	case strings.Contains(lq, "week"): // "this week" / "next week" / "a week"
		return 7
	default:
		return 7
	}
}

// availabilityIntent reports whether a (lowercased) question is about PAST
// reachability (a host going offline / downtime over a time range), as opposed to
// the CURRENT offline set ("which hosts are offline right now" -> query_hosts).
func availabilityIntent(lq string) bool {
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") || strings.Contains(lq, "how can") {
		return false
	}
	if !downRE.MatchString(lq) {
		return false
	}
	// Require a past/history/time-range signal so "are any hosts offline" (present
	// state) still falls through to the model.
	for _, t := range []string{
		"today", "yesterday", "overnight", "last night", "this morning", "tonight",
		"this week", "past ", "recent", "history", "ever ", "gone ", "went ", "did ",
		"have any", "has any", "were ", "was ", "been ", "outage", "downtime",
	} {
		if strings.Contains(lq, t) {
			return true
		}
	}
	return false
}

// hoursFromText maps a coarse time phrase to a lookback window (hours).
func hoursFromText(lq string) int {
	switch {
	case strings.Contains(lq, "today"), strings.Contains(lq, "overnight"),
		strings.Contains(lq, "last night"), strings.Contains(lq, "this morning"),
		strings.Contains(lq, "tonight"), strings.Contains(lq, "24h"), strings.Contains(lq, "24 h"):
		return 24
	case strings.Contains(lq, "yesterday"):
		return 48
	case strings.Contains(lq, "month"):
		return 720
	case strings.Contains(lq, "week"):
		return 168
	default:
		return 168
	}
}

// updatesIntent reports whether a (lowercased) question is asking WHICH updates/packages
// are pending — not an action like "update the host" or a how-to ("how do I update").
func updatesIntent(lq string) bool {
	if !updateWordRE.MatchString(lq) {
		return false
	}
	// A "how do I / how to" phrasing is a docs question, not a fleet-state one.
	if strings.Contains(lq, "how do") || strings.Contains(lq, "how to") || strings.Contains(lq, "how can") {
		return false
	}
	for _, t := range []string{
		"pending", "available", "which package", "what package", "list package",
		"need updat", "need upgrad", "need patch", "needs updat", "needs upgrad",
		"are there", "any update", "what update", "what are the update", "security update",
		"updates on", "updates for", "updates available", "updates pending", "packages to",
	} {
		if strings.Contains(lq, t) {
			return true
		}
	}
	// Plain "...updates?" as a direct question.
	if strings.Contains(lq, "updates") && (strings.Contains(lq, "?") ||
		strings.HasPrefix(lq, "what") || strings.HasPrefix(lq, "which") || strings.HasPrefix(lq, "are ")) {
		return true
	}
	return false
}

// parseCommandTail turns the tail after "who ran …" into a bare command + optional
// host: it strips a trailing "on <host>" clause, surrounding quotes/backticks, a
// leading "the/a", a trailing "command", and trailing punctuation.
func parseCommandTail(tail string) (cmd, host string) {
	s := strings.TrimSpace(tail)
	s = trailingPunct.ReplaceAllString(s, "")
	if hm := onHostRE.FindStringSubmatch(s); hm != nil {
		host = hm[1]
		s = strings.TrimSpace(onHostRE.ReplaceAllString(s, ""))
	}
	s = strings.Trim(s, "`'\"")
	s = theWrapRE.ReplaceAllString(s, "")
	s = commandSuffix.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	return s, host
}
