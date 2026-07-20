// Package commandpolicy enforces command-control rules at the terminal relay. It
// buffers the interactive input stream into command lines and, when a line matches
// a configured rule, flags it (allow + audit), blocks it (refuse to run), or gates
// it on an approval waiver.
//
// IMPORTANT: this inspects the interactive input stream, so it is a deterrent and a
// complete audit trail — not a cryptographic guarantee. A determined insider can
// obfuscate (paste-splitting, base64, launching a sub-shell/editor). It raises the
// bar and records intent; it does not make a hostile operator harmless.
package commandpolicy

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// killLine clears the remote shell's current input line (readline Ctrl-U) so a
// blocked command's already-echoed text doesn't linger. The command never runs
// regardless — the guard simply withholds the newline that would execute it.
var killLine = []byte{0x15}

// Rule is a compiled command-control rule.
type Rule struct {
	ID     uuid.UUID
	Name   string
	Action string // flag | block | approval
	re     *regexp.Regexp
}

// Compile turns stored (id, name, action, pattern) tuples into matchable rules,
// skipping any with an invalid regex (patterns are validated at write time, so this
// is just belt-and-suspenders).
func Compile(specs []Spec) []Rule {
	out := make([]Rule, 0, len(specs))
	for _, s := range specs {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, Rule{ID: s.ID, Name: s.Name, Action: s.Action, re: re})
	}
	return out
}

// Spec is the raw rule input to Compile.
type Spec struct {
	ID      uuid.UUID
	Name    string
	Action  string
	Pattern string
}

// Callbacks lets the relay supply the side effects the guard triggers, keeping the
// guard itself free of DB/notify imports. All are called at most once per entered
// command line (never per keystroke), and may be nil.
type Callbacks struct {
	// HasWaiver reports whether the user currently holds an approval waiver for the
	// rule (so a previously-gated command may run).
	HasWaiver func(ruleID uuid.UUID) bool
	// OnFlag / OnBlock / OnApprovalRequest / OnApprovedRun record + notify.
	OnFlag            func(rule Rule, command string)
	OnBlock           func(rule Rule, command string)
	OnApprovalRequest func(rule Rule, command string)
	OnApprovedRun     func(rule Rule, command string)
}

// Guard holds per-connection line state and the compiled ruleset.
type Guard struct {
	rules []Rule
	cb    Callbacks
	line  []byte
}

// NewGuard returns a guard for the given rules, or nil if there are none — a nil
// guard is a pure passthrough (Input returns its bytes unchanged), so a host with
// no policy pays zero cost and sees no behavior change.
func NewGuard(rules []Rule, cb Callbacks) *Guard {
	if len(rules) == 0 {
		return nil
	}
	return &Guard{rules: rules, cb: cb}
}

// Input processes a chunk of terminal input and returns the bytes to forward to the
// remote shell plus an optional notice to echo back to the browser (e.g. a block
// message). Keystrokes are forwarded as they arrive (so remote echo is normal); the
// guard only intervenes at end-of-line, when it has a full command to evaluate.
//
// A nil guard forwards its input unchanged.
func (g *Guard) Input(data []byte) (forward []byte, notice string) {
	if g == nil {
		return data, ""
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == '\r' || b == '\n' {
			line := strings.TrimSpace(string(g.line))
			g.line = g.line[:0]
			if line == "" {
				out = append(out, b)
				continue
			}
			fwd, note := g.decide(line, b)
			out = append(out, fwd...)
			notice += note
			continue
		}
		// Maintain the line buffer: handle backspace, keep printable ASCII, ignore
		// other control/escape bytes (they can't form a matchable command anyway).
		switch {
		case b == 0x7f || b == 0x08:
			if len(g.line) > 0 {
				g.line = g.line[:len(g.line)-1]
			}
		case b >= 0x20 && b < 0x7f:
			g.line = append(g.line, b)
		}
		out = append(out, b) // forward the keystroke immediately
	}
	return out, notice
}

// decide evaluates one completed command line and returns the bytes to forward for
// the line terminator (the newline to execute, or a kill-line to cancel) plus any
// browser notice. The first matching rule wins, in rule order.
func (g *Guard) decide(line string, term byte) (forward []byte, notice string) {
	for _, r := range g.rules {
		if !r.re.MatchString(line) {
			continue
		}
		switch r.Action {
		case "flag":
			if g.cb.OnFlag != nil {
				g.cb.OnFlag(r, line)
			}
			return []byte{term}, "" // allow, execute

		case "block":
			if g.cb.OnBlock != nil {
				g.cb.OnBlock(r, line)
			}
			return killLine, blockNotice(r.Name)

		case "approval":
			if g.cb.HasWaiver != nil && g.cb.HasWaiver(r.ID) {
				if g.cb.OnApprovedRun != nil {
					g.cb.OnApprovedRun(r, line)
				}
				return []byte{term}, "" // waiver held: allow
			}
			if g.cb.OnApprovalRequest != nil {
				g.cb.OnApprovalRequest(r, line)
			}
			return killLine, approvalNotice(r.Name)
		}
	}
	return []byte{term}, "" // no rule matched
}

func blockNotice(rule string) string {
	return "\r\n\x1b[31m[command blocked by policy: " + rule + "]\x1b[0m\r\n"
}

func approvalNotice(rule string) string {
	return "\r\n\x1b[33m[command requires approval (" + rule +
		"): a request was submitted. Once an approver grants it, run the command again.]\x1b[0m\r\n"
}
