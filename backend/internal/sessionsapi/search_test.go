package sessionsapi

import (
	"strings"
	"testing"
)

func TestStripANSI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"color codes", "\x1b[31mred\x1b[0m text", "red text"},
		{"cursor move", "a\x1b[2Kb", "ab"},
		{"osc title", "\x1b]0;my title\x07hello", "hello"},
		{"control chars dropped", "a\x08b\x07c", "abc"},
		{"keeps newline and tab", "line1\nline2\tend", "line1\nline2\tend"},
		{"plain text untouched", "sudo cat /etc/passwd", "sudo cat /etc/passwd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stripANSI(c.in); got != c.want {
				t.Errorf("stripANSI(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestMatchSnippets(t *testing.T) {
	text := "the quick brown fox jumps over the lazy dog and the fox runs"
	lower := strings.ToLower(text)

	count, snips := matchSnippets(lower, text, "fox")
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if len(snips) != 2 {
		t.Fatalf("snippets = %d, want 2", len(snips))
	}
	for _, s := range snips {
		if !strings.Contains(s, "fox") {
			t.Errorf("snippet %q does not contain the match", s)
		}
	}

	if n, _ := matchSnippets(lower, text, "cat"); n != 0 {
		t.Errorf("no-match count = %d, want 0", n)
	}

	// Case-insensitive: caller lowercases the needle; the text's lower form matches.
	if n, _ := matchSnippets(lower, text, "quick"); n != 1 {
		t.Errorf("quick count = %d, want 1", n)
	}

	// Snippet cap: many matches, at most searchMaxSnippets returned.
	many := strings.Repeat("x ", 50)
	c, s := matchSnippets(many, many, "x")
	if c != 50 {
		t.Errorf("many count = %d, want 50", c)
	}
	if len(s) > searchMaxSnippets {
		t.Errorf("snippets = %d, want <= %d", len(s), searchMaxSnippets)
	}
}
