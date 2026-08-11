package assistant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestCapabilityCatalogCoversEveryTool keeps the "I couldn't find anything" answer
// honest. That sentence tells the user what Fleet DOES hold, and the previous
// hand-written version had already drifted out of date — it omitted compliance scans,
// so the assistant told an operator Fleet could not retrieve OpenSCAP results while
// holding a table of them. A registered tool with no catalogue entry fails here.
func TestCapabilityCatalogCoversEveryTool(t *testing.T) {
	for _, tool := range tools {
		if capabilityCatalog[tool.Function.Name] == "" {
			t.Errorf("tool %q has no capabilityCatalog entry: the no-answer fallback would deny data Fleet actually has",
				tool.Function.Name)
		}
	}
	for name := range capabilityCatalog {
		found := false
		for _, tool := range tools {
			if tool.Function.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("capabilityCatalog names %q, which is not a registered tool: the fallback would promise data no tool can fetch", name)
		}
	}
	if s := capabilityStatement(); !strings.Contains(s, "compliance") || !strings.Contains(s, "CVE") {
		t.Errorf("capabilityStatement() should name both scan kinds, got: %s", s)
	}
}

// TestEveryToolHasDispatch catches the other half of the same class of bug: a tool
// the model can SEE but that converse() never dispatches falls through to
// {"error":"unknown tool"}, and the model reports that as "I have no tool for this".
// The dispatch is a switch on the tool name, so the check is that every registered
// name appears as a case literal in service.go.
func TestEveryToolHasDispatch(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "service.go", nil, 0)
	if err != nil {
		t.Fatalf("parse service.go: %v", err)
	}
	cases := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, e := range cc.List {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if v, err := strconv.Unquote(lit.Value); err == nil {
				cases[v] = true
			}
		}
		return true
	})
	for _, tool := range tools {
		if !cases[tool.Function.Name] {
			t.Errorf("tool %q is offered to the model but has no dispatch case in converse(); it would return \"unknown tool\"",
				tool.Function.Name)
		}
	}
	// The propose_* tools are dispatched via actionToolKinds, not a case label.
	for _, tool := range actionTools {
		if actionToolKinds[tool.Function.Name] == "" {
			t.Errorf("action tool %q has no actionToolKinds mapping", tool.Function.Name)
		}
	}
}

// TestPromptFitsContextWindow guards the failure this whole change set exists for:
// the system prompt plus every tool schema must fit comfortably inside the context
// window we request, with room left for the conversation and the tool results.
// Ollama does not error when the prompt overflows — it silently discards the OLDEST
// tokens, which are the instructions, and the assistant answers with no tool-choice
// guidance and no answer-scope rules at all.
func TestPromptFitsContextWindow(t *testing.T) {
	floor := promptFloorTokens()
	// Half the window: the other half has to hold tool results and history.
	if budget := numCtx(0) / 2; floor > budget {
		t.Errorf("system prompt + tool schemas ≈ %d tokens, over the %d-token budget (half of the default %d window). "+
			"Either trim the prompt/tool descriptions or raise defaultNumCtx.", floor, budget, numCtx(0))
	}
	if numCtx(0) < minNumCtx || numCtx(1) != minNumCtx || numCtx(65536) != 65536 {
		t.Errorf("numCtx does not floor small values and pass through large ones: %d %d %d", numCtx(0), numCtx(1), numCtx(65536))
	}
	if opts := deterministicOptions(0); opts["num_ctx"] != numCtx(0) {
		t.Errorf("deterministicOptions must always send num_ctx; got %v", opts["num_ctx"])
	}
}
