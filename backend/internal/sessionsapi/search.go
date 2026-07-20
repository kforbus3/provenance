package sessionsapi

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
)

// Search bounds — keep a single query's I/O predictable regardless of how many
// recordings exist.
const (
	searchMaxRecordings = 500     // most-recent recordings scanned per query
	searchMaxFileBytes  = 8 << 20 // stop reading a single .cast past this
	searchMaxCleanBytes = 2 << 20 // cap accumulated cleaned text per session
	searchMaxSnippets   = 3       // snippets returned per matching session
	searchSnippetPad    = 60      // characters of context around a match
	searchMaxResults    = 200     // matching sessions returned
	searchScanBuf       = 4 << 20 // bufio line cap (long output lines)
)

// ansiRE strips ANSI/VT escape sequences so a search matches the visible text a
// user typed or saw, not the terminal control codes interleaved with it.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// SearchResult is one matching session with snippets of the matched content.
type SearchResult struct {
	SessionID  string    `json:"sessionId"`
	Username   string    `json:"username"`
	Hostname   string    `json:"hostname"`
	StartedAt  time.Time `json:"startedAt"`
	MatchCount int       `json:"matchCount"`
	Snippets   []string  `json:"snippets"`
}

// search runs a full-text search across recorded session content (the asciicast
// output stream, which echoes typed commands). It's gated by Session.Replay — the
// same permission as watching a recording — since it exposes recording content.
func (h *handler) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		httpx.WriteError(w, http.StatusBadRequest, "q must be at least 2 characters")
		return
	}
	needle := strings.ToLower(q)

	var userID, hostID *uuid.UUID
	if v := r.URL.Query().Get("user"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid user id")
			return
		}
		userID = &id
	}
	if v := r.URL.Query().Get("host"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
			return
		}
		hostID = &id
	}

	refs, err := h.d.Store.RecordingsForSearch(r.Context(), userID, hostID, searchMaxRecordings)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list recordings")
		return
	}

	results := []SearchResult{}
	scanned := 0
	for _, ref := range refs {
		if len(results) >= searchMaxResults {
			break
		}
		text := h.cleanedRecording(ref.Path)
		if text == "" {
			continue
		}
		scanned++
		count, snippets := matchSnippets(strings.ToLower(text), text, needle)
		if count == 0 {
			continue
		}
		results = append(results, SearchResult{
			SessionID: ref.SessionID.String(), Username: ref.Username, Hostname: ref.Hostname,
			StartedAt: ref.StartedAt, MatchCount: count, Snippets: snippets,
		})
	}

	// Searching session content is sensitive; record who searched for what.
	if p := auth.MustPrincipal(r); p != nil {
		_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &p.UserID, ActorName: p.Username, Action: "session.search",
			TargetKind: "session", Detail: map[string]any{"query": q, "matches": len(results)},
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"results":         results,
		"recordingsInSet": len(refs),
		"scanned":         scanned,
		"capped":          len(refs) >= searchMaxRecordings,
	})
}

// cleanedRecording reads an asciicast file and returns its output text with ANSI
// escapes and control characters stripped, bounded in size. Returns "" on any read
// error (a missing/rotated-out recording is simply skipped).
func (h *handler) cleanedRecording(path string) string {
	f, err := os.Open(h.resolvePath(path))
	if err != nil {
		return ""
	}
	defer f.Close()

	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), searchScanBuf)
	read := 0
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		read += len(line)
		if read > searchMaxFileBytes || b.Len() > searchMaxCleanBytes {
			break
		}
		if first {
			first = false // skip the asciicast header object (line 1)
			continue
		}
		// Each event is a JSON array: [time, "o"|"i", "data"]. We only want output.
		var ev []json.RawMessage
		if err := json.Unmarshal(line, &ev); err != nil || len(ev) < 3 {
			continue
		}
		var kind, data string
		if json.Unmarshal(ev[1], &kind) != nil || kind != "o" {
			continue
		}
		if json.Unmarshal(ev[2], &data) != nil {
			continue
		}
		b.WriteString(stripANSI(data))
	}
	return b.String()
}

// stripANSI removes escape sequences and non-printable control characters (keeping
// spaces, tabs, and newlines) so matching and snippets operate on visible text.
func stripANSI(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	return strings.Map(func(rn rune) rune {
		if rn == '\n' || rn == '\t' {
			return rn
		}
		if rn < 0x20 || rn == 0x7f {
			return -1
		}
		return rn
	}, s)
}

// matchSnippets counts occurrences of needle (already lowercased) in lower, and
// returns up to searchMaxSnippets context windows drawn from the original-cased
// text, with whitespace collapsed for display.
func matchSnippets(lower, original, needle string) (int, []string) {
	count := 0
	snippets := []string{}
	from := 0
	for {
		i := strings.Index(lower[from:], needle)
		if i < 0 {
			break
		}
		abs := from + i
		count++
		if len(snippets) < searchMaxSnippets {
			// Draw the window from `original`, clamping every index to its length.
			// ToLower can shift byte offsets for non-ASCII, so guard against a slice
			// that would run past the original or invert (start > end).
			oa := abs
			if oa > len(original) {
				oa = len(original)
			}
			start := oa - searchSnippetPad
			if start < 0 {
				start = 0
			}
			end := oa + len(needle) + searchSnippetPad
			if end > len(original) {
				end = len(original)
			}
			if start > end {
				start = end
			}
			snippets = append(snippets, collapseWS(original[start:end]))
		}
		from = abs + len(needle)
	}
	return count, snippets
}

// collapseWS squeezes runs of whitespace (incl. newlines) into single spaces so a
// snippet is one readable line.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
