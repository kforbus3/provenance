package assistant

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEncodeToolResultCapsLargePayloads locks the behaviour that keeps a big tool
// result from evicting the system prompt. Ollama does not reject an oversized prompt
// — it drops the oldest tokens, i.e. the instructions — so an unbounded audit_log or
// vulnerability payload silently turns the assistant into an unguided chatbot
// halfway through a conversation.
func TestEncodeToolResultCapsLargePayloads(t *testing.T) {
	rows := make([]map[string]any, 2000)
	for i := range rows {
		rows[i] = map[string]any{
			"actor": "someone@example.com", "action": "host.update",
			"detail": strings.Repeat("x", 120), "at": "2026-08-11T03:00:00Z",
		}
	}
	out := encodeToolResult(map[string]any{"count": len(rows), "events": rows})
	if len(out) > maxToolPayloadBytes {
		t.Errorf("payload not capped: %d bytes > %d", len(out), maxToolPayloadBytes)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("capped payload must still be valid JSON: %v", err)
	}
	if got["truncated"] != true {
		t.Error("a capped payload must say so, or the model reports a clipped list as the whole story")
	}
	// The true total has to survive, so the answer can say "N of M".
	if total, _ := got["total"].(float64); int(total) != len(rows) {
		t.Errorf("total = %v, want %d", got["total"], len(rows))
	}
	shown, _ := got["shown"].(float64)
	if shown < minRowsKept {
		t.Errorf("shown = %v, must keep at least %d rows so a cap never empties a real answer", shown, minRowsKept)
	}
	if events, _ := got["events"].([]any); len(events) != int(shown) {
		t.Errorf("events length %d does not match shown %v", len(events), shown)
	}
}

// TestEncodeToolResultLeavesSmallPayloadsAlone keeps the common case byte-identical,
// so capping cannot perturb answers that were already correct.
func TestEncodeToolResultLeavesSmallPayloadsAlone(t *testing.T) {
	in := map[string]any{"count": 2, "hosts": []any{"nas", "ai"}}
	want, _ := json.Marshal(in)
	if got := encodeToolResult(in); got != string(want) {
		t.Errorf("small payload was modified:\n got %s\nwant %s", got, want)
	}
}

// TestEncodeToolResultHandlesTypedSlices covers the real payload shapes: tool results
// carry concrete slice types ([]models.AssistantComplianceRow, ...), not []any, so a
// naive type assertion would find no list to trim and drop the data entirely.
func TestEncodeToolResultHandlesTypedSlices(t *testing.T) {
	type row struct {
		Host string `json:"host"`
		Note string `json:"note"`
	}
	rows := make([]row, 3000)
	for i := range rows {
		rows[i] = row{Host: "host-with-a-fairly-long-name", Note: strings.Repeat("y", 60)}
	}
	out := encodeToolResult(map[string]any{"count": len(rows), "hosts": rows})
	if len(out) > maxToolPayloadBytes {
		t.Errorf("typed slice not trimmed: %d bytes", len(out))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got["truncated"] != true {
		t.Error("expected the typed-slice payload to be marked truncated")
	}
}
