package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A CLI run without the chain key permanently weakens the chain.
//
// AppendAudit falls back to keyless SHA-256 when no key is configured, and every row
// names its own algorithm — so a provctl run whose environment lacks
// PROV_AUDIT_HMAC_KEY appends a row the verifier re-derives keylessly. That row
// verifies, and marks the chain's tail as not tamper-evident from its sequence
// onwards, for ever.
//
// This is not hypothetical. On a production chain, sequence 3389 is exactly that: one
// keyless `recovery.create_admin` written by the CLI between two keyed rows from the
// backend, because that process had no key in its environment. The identical command
// run later WITH the key produced a keyed row. One missing variable.
//
// Asserted on the source: the behaviour needs a keyed database to exercise, and what
// matters is that no audit-appending or chain-verifying command can reach its work
// without passing the check first.
func TestEveryAuditTouchingCommandDemandsTheKey(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	// Commands that append an audit row or verify the chain.
	for _, cmd := range []string{"create-admin", "reset-mfa", "audit-scan"} {
		seg := caseSegment(body, cmd)
		if seg == "" {
			t.Fatalf("case %q not found — this test no longer guards what it claims", cmd)
		}
		if !strings.Contains(seg, "requireAuditKey(") {
			t.Errorf("provctl %s touches the audit chain without calling requireAuditKey. "+
				"Without the key it either appends a keyless row that permanently weakens "+
				"the chain, or reports every keyed row as broken.", cmd)
		}
	}

	// create-admin must check BEFORE creating the account, so a refusal leaves nothing
	// behind — an admin with no audit row is worse than no admin.
	seg := caseSegment(body, "create-admin")
	iCheck := strings.Index(seg, "requireAuditKey(")
	iCreate := strings.Index(seg, "st.CreateUser(")
	if iCheck < 0 || iCreate < 0 || iCheck > iCreate {
		t.Error("create-admin creates the account before checking for the key, so a refusal " +
			"would leave a super administrator behind with no audit record of it")
	}

	// And any NEW command that appends an audit row has to be considered. This fails
	// on an unguarded AppendAudit rather than letting one slip in silently.
	for _, m := range regexp.MustCompile(`(?m)^\tcase "([a-z-]+)":`).FindAllStringSubmatch(body, -1) {
		name := m[1]
		seg := caseSegment(body, name)
		if !strings.Contains(seg, "AppendAudit(") {
			continue
		}
		if !strings.Contains(seg, "requireAuditKey(") {
			t.Errorf("provctl %s appends an audit row without requireAuditKey", name)
		}
	}
}

// The refusal has to tell the operator how to fix it, or it just blocks the recovery
// path these commands exist for.
func TestTheRefusalSaysHowToSupplyTheKey(t *testing.T) {
	src, _ := os.ReadFile("main.go")
	seg := funcText(string(src), "func requireAuditKey")
	if seg == "" {
		t.Fatal("requireAuditKey not found")
	}
	for _, want := range []string{"PROV_AUDIT_HMAC_KEY", "docker inspect"} {
		if !strings.Contains(seg, want) {
			t.Errorf("the refusal message does not mention %q, so an operator locked out of "+
				"their own instance has nothing to act on", want)
		}
	}
	// An unkeyed chain must still be usable — that is a fresh install.
	if !strings.Contains(seg, "if !keyed") {
		t.Error("the check does not exempt an unkeyed chain, which would break first-run setup")
	}
}

func caseSegment(src, name string) string {
	i := strings.Index(src, "\tcase \""+name+"\":")
	if i < 0 {
		return ""
	}
	rest := src[i+1:]
	if end := regexp.MustCompile(`(?m)^\tcase "`).FindStringIndex(rest); end != nil {
		return rest[:end[0]]
	}
	return rest
}

func funcText(src, sig string) string {
	i := strings.Index(src, sig)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
