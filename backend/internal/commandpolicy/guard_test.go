package commandpolicy

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func rules(action, pattern string) []Rule {
	return Compile([]Spec{{ID: uuid.New(), Name: "test", Action: action, Pattern: pattern}})
}

func TestNilGuardPassthrough(t *testing.T) {
	var g *Guard
	fwd, note := g.Input([]byte("rm -rf /\r"))
	if string(fwd) != "rm -rf /\r" || note != "" {
		t.Fatalf("nil guard should pass through unchanged, got %q / %q", fwd, note)
	}
}

func TestFlagAllowsAndRecords(t *testing.T) {
	flagged := ""
	g := NewGuard(rules("flag", `sudo`), Callbacks{OnFlag: func(r Rule, cmd string) { flagged = cmd }})
	fwd, note := g.Input([]byte("sudo reboot\r"))
	if string(fwd) != "sudo reboot\r" {
		t.Errorf("flag should forward the whole line incl. newline, got %q", fwd)
	}
	if note != "" {
		t.Errorf("flag should not notice the user, got %q", note)
	}
	if flagged != "sudo reboot" {
		t.Errorf("OnFlag got %q", flagged)
	}
}

func TestBlockWithholdsNewline(t *testing.T) {
	blocked := ""
	g := NewGuard(rules("block", `rm\s+-rf\s+/`), Callbacks{OnBlock: func(r Rule, cmd string) { blocked = cmd }})
	fwd, note := g.Input([]byte("rm -rf /\r"))
	if strings.Contains(string(fwd), "\r") || strings.Contains(string(fwd), "\n") {
		t.Errorf("block must not forward the executing newline, got %q", fwd)
	}
	if !strings.Contains(string(fwd), string(killLine)) {
		t.Errorf("block should send a kill-line to clear the remote input, got %q", fwd)
	}
	if note == "" {
		t.Errorf("block should notice the user")
	}
	if blocked != "rm -rf /" {
		t.Errorf("OnBlock got %q", blocked)
	}
}

func TestApprovalGating(t *testing.T) {
	// No waiver → request + block.
	requested := false
	g := NewGuard(rules("approval", `shutdown`), Callbacks{
		HasWaiver:         func(uuid.UUID) bool { return false },
		OnApprovalRequest: func(Rule, string) { requested = true },
	})
	fwd, note := g.Input([]byte("shutdown now\r"))
	if strings.ContainsAny(string(fwd), "\r\n") || note == "" || !requested {
		t.Errorf("approval w/o waiver should block+request, got fwd=%q note=%q requested=%v", fwd, note, requested)
	}

	// Waiver held → allow.
	ran := false
	g2 := NewGuard(rules("approval", `shutdown`), Callbacks{
		HasWaiver:     func(uuid.UUID) bool { return true },
		OnApprovedRun: func(Rule, string) { ran = true },
	})
	fwd2, note2 := g2.Input([]byte("shutdown now\r"))
	if string(fwd2) != "shutdown now\r" || note2 != "" || !ran {
		t.Errorf("approval w/ waiver should allow, got fwd=%q note=%q ran=%v", fwd2, note2, ran)
	}
}

func TestBackspaceEditsMatchedLine(t *testing.T) {
	blocked := false
	g := NewGuard(rules("block", `^rm$`), Callbacks{OnBlock: func(Rule, string) { blocked = true }})
	// Type "rmx", backspace, so the effective line is "rm" and should block.
	g.Input([]byte("rmx"))
	_, _ = g.Input([]byte{0x7f}) // backspace
	g.Input([]byte("\r"))
	if !blocked {
		t.Errorf("backspace-edited line should have matched ^rm$ and blocked")
	}
}

func TestKeystrokesForwardedDuringTyping(t *testing.T) {
	g := NewGuard(rules("block", `secret`), Callbacks{})
	fwd, _ := g.Input([]byte("ls -la"))
	if string(fwd) != "ls -la" {
		t.Errorf("keystrokes should forward immediately, got %q", fwd)
	}
}
