package assistant

import (
	"encoding/json"
	"fmt"
	"sort"
)

// The model-facing budget for ONE tool result. Tool results are appended to the
// transcript verbatim, so an unbounded result competes with the system prompt for
// the context window — and Ollama resolves that competition by silently discarding
// the OLDEST tokens, i.e. the instructions. audit_log alone requests 500 rows, which
// serialises to far more than a small model can hold, so every result is capped here.
//
// The cap applies ONLY to what the model reads. The AssistantTable rendered beneath
// the answer still carries every row, so the user never loses data — and because the
// truncation is announced in the payload, the model reports "N of M" instead of
// mistaking a clipped list for the whole story.
const (
	// maxToolPayloadBytes is the per-result budget (~6k tokens at ~4 bytes/token).
	maxToolPayloadBytes = 24000
	// minRowsKept is the floor a list is never trimmed below, so a cap can never
	// turn a real answer into an empty one.
	minRowsKept = 5
)

// encodeToolResult serialises a tool result for the model, trimming the largest
// list in the payload until it fits maxToolPayloadBytes. The returned JSON always
// parses, and a trimmed payload carries an explicit note plus the true total so the
// model can say how many rows it is summarising rather than implying it saw them all.
func encodeToolResult(result any) string {
	raw, err := json.Marshal(result)
	if err != nil {
		return `{"error":"could not encode tool result"}`
	}
	if len(raw) <= maxToolPayloadBytes {
		return string(raw)
	}
	m, ok := result.(map[string]any)
	if !ok {
		// Not a map we can trim structurally — fall back to a plain notice rather than
		// feeding the model invalid, mid-object-truncated JSON.
		return fmt.Sprintf(`{"note":"the result was too large to include in full (%d bytes); the full data is shown to the user in the table beneath the answer","truncated":true}`, len(raw))
	}
	trimmed := trimLargestList(m, len(raw))
	out, err := json.Marshal(trimmed)
	if err != nil {
		return `{"error":"could not encode tool result"}`
	}
	return string(out)
}

// trimLargestList shrinks the biggest list-valued field of a payload map until the
// whole thing fits the budget, halving each round so a very large list converges
// quickly. It copies the map rather than mutating the caller's, because the same
// value also backs the AssistantTable shown to the user.
func trimLargestList(m map[string]any, origBytes int) map[string]any {
	key, items := largestList(m)
	if key == "" {
		return map[string]any{
			"note":      fmt.Sprintf("the result was too large to include in full (%d bytes); summarise from the table shown to the user", origBytes),
			"truncated": true,
		}
	}
	total := len(items)
	out := make(map[string]any, len(m)+3)
	for k, v := range m {
		out[k] = v
	}
	keep := total
	for keep > minRowsKept {
		next := keep / 2
		if next < minRowsKept {
			next = minRowsKept
		}
		out[key] = items[:next]
		out["truncated"] = true
		out["shown"] = next
		out["total"] = total
		out["note"] = fmt.Sprintf(
			"only the first %d of %d %s are included here; the user sees all %d in the table beneath your answer. Say how many there are in total and summarise — do NOT claim these %d are all of them.",
			next, total, key, total, next)
		b, err := json.Marshal(out)
		if err == nil && len(b) <= maxToolPayloadBytes {
			return out
		}
		keep = next
	}
	return out
}

// largestList finds the field holding the longest []any — the row list that is
// almost always what makes a payload oversized. Keys are compared so the choice is
// deterministic when two lists tie.
func largestList(m map[string]any) (string, []any) {
	type cand struct {
		key   string
		items []any
	}
	var cands []cand
	for k, v := range m {
		items, ok := asAnyList(v)
		if !ok || len(items) == 0 {
			continue
		}
		cands = append(cands, cand{k, items})
	}
	if len(cands) == 0 {
		return "", nil
	}
	sort.Slice(cands, func(i, j int) bool {
		if len(cands[i].items) != len(cands[j].items) {
			return len(cands[i].items) > len(cands[j].items)
		}
		return cands[i].key < cands[j].key
	})
	return cands[0].key, cands[0].items
}

// asAnyList normalises a payload field to []any. Tool payloads carry concrete slice
// types ([]models.VulnScan, []authEvRow, ...), so the fast []any assertion is not
// enough — round-trip through JSON for anything else that encodes as an array.
func asAnyList(v any) ([]any, bool) {
	if l, ok := v.([]any); ok {
		return l, true
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || b[0] != '[' {
		return nil, false
	}
	var l []any
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, false
	}
	return l, true
}
