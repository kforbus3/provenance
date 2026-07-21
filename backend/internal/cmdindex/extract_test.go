package cmdindex

import (
	"encoding/json"
	"strings"
	"testing"
)

// buildCast assembles an asciicast v2 stream: a header line plus one event line per
// (time, kind, data) triple.
func buildCast(events [][3]any) []byte {
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24}` + "\n")
	for _, e := range events {
		line, _ := json.Marshal([]any{e[0], e[1], e[2]})
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func texts(cmds []Command) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.Text
	}
	return out
}

func TestExtractCommands(t *testing.T) {
	cast := buildCast([][3]any{
		{0.5, "i", "ls -la\r"},                    // simple command
		{1.0, "o", "total 0\r\n"},                 // output ignored
		{2.0, "i", "cat /etc/hostx"},              // typo...
		{2.5, "i", "\x7fs"},                       // backspace the 'x', type 's' -> hosts
		{2.7, "i", "\r"},                          // submit -> cat /etc/hosts
		{3.0, "i", "rm -rf /tmp/junk\x15clear\r"}, // Ctrl-U kills the line, then "clear"
		{4.0, "i", "echo hi\x03"},                 // Ctrl-C aborts (no submit)
		{4.5, "i", "\x1b[Aecho recalled\r"},       // up-arrow escape stripped -> "echo recalled"
		{5.0, "i", "whoami\r"},
	})
	got := texts(ExtractCommandsBytes(cast))
	want := []string{"ls -la", "cat /etc/hosts", "clear", "echo recalled", "whoami"}
	if len(got) != len(want) {
		t.Fatalf("got %d commands %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractOffsets(t *testing.T) {
	cast := buildCast([][3]any{
		{1.25, "i", "uptime\r"},
	})
	cmds := ExtractCommandsBytes(cast)
	if len(cmds) != 1 || cmds[0].Offset != 1.25 {
		t.Fatalf("offset = %+v, want one command at 1.25", cmds)
	}
}

func TestExtractIgnoresBlankAndAbortedLines(t *testing.T) {
	cast := buildCast([][3]any{
		{0.1, "i", "\r"},       // bare Enter
		{0.2, "i", "   \r"},    // whitespace only
		{0.3, "i", "\x1b[B\r"}, // just an arrow key
		{0.4, "i", "id\r"},     // the only real command
	})
	got := texts(ExtractCommandsBytes(cast))
	if len(got) != 1 || got[0] != "id" {
		t.Fatalf("got %q, want [id]", got)
	}
}
