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

	return "", nil, false
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
