// Package cmdindex reconstructs the command lines a user typed in a recorded SSH
// terminal session from the session's asciicast "i" (input) events, so they can be
// indexed and searched ("who ran command X").
//
// This is a BEST-EFFORT reconstruction from a raw PTY keystroke stream: it applies
// backspaces and line-kills and strips escape sequences, but tab-completion and
// history-recall (up-arrow) pull text from the shell that never appears in the input
// stream, so a recalled command may be recorded blank or partial. It is well suited to
// substring SEARCH, not to a forensically exact command log — callers should present
// results as "typed", not "executed".
package cmdindex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

// Command is one reconstructed command line and when it was submitted (seconds into
// the session).
type Command struct {
	Text   string
	Offset float64
}

// maxLineLen caps a single reconstructed line so a pathological paste can't produce a
// giant row.
const maxLineLen = 4096

// ExtractCommands parses an asciicast v2 stream and returns the command lines the user
// submitted (Enter-terminated), in order. Non-input events are ignored. It streams
// line by line (via bufio.Reader, no line-length cap) so a large recording with huge
// output events is handled without loading the whole file into memory.
func ExtractCommands(r io.Reader) []Command {
	x := &extractor{br: bufio.NewReader(r), first: true}
	for {
		line, rerr := x.br.ReadBytes('\n')
		if len(line) > 0 {
			x.line(line)
		}
		if rerr != nil {
			break
		}
	}
	return x.out
}

// ExtractCommandsBytes is a convenience wrapper over ExtractCommands for a byte slice.
func ExtractCommandsBytes(cast []byte) []Command { return ExtractCommands(bytes.NewReader(cast)) }

type extractor struct {
	br        *bufio.Reader
	out       []Command
	buf       []rune  // current line being typed
	lineStart float64 // timestamp of the first key of the current line
	haveStart bool
	first     bool
}

// line handles one asciicast line: skips the header (first line) and non-input events;
// feeds "i" event data through the line editor.
func (x *extractor) line(raw []byte) {
	if x.first {
		x.first = false // line 1 is the header object
		return
	}
	raw = bytes.TrimRight(raw, "\r\n")
	if len(raw) == 0 || raw[0] != '[' {
		return
	}
	var ev [3]json.RawMessage
	if json.Unmarshal(raw, &ev) != nil {
		return
	}
	var kind string
	if json.Unmarshal(ev[1], &kind) != nil || kind != "i" {
		return
	}
	var ts float64
	_ = json.Unmarshal(ev[0], &ts)
	var data string
	if json.Unmarshal(ev[2], &data) != nil {
		return
	}
	if !x.haveStart && data != "" {
		x.lineStart = ts
		x.haveStart = true
	}
	x.consume(data, ts)
}

// flush records the current buffer as a submitted command (if it has printable content)
// and resets for the next line.
func (x *extractor) flush(ts float64) {
	s := sanitize(string(x.buf))
	off := x.lineStart
	if !x.haveStart {
		off = ts
	}
	x.buf = x.buf[:0]
	x.haveStart = false
	if s != "" {
		x.out = append(x.out, Command{Text: s, Offset: off})
	}
}

// consume feeds one input event's runes through the line editor, flushing on each
// Enter. It handles backspace, Ctrl-U (kill line), Ctrl-C (abort line), and skips
// escape sequences and other control bytes.
func (x *extractor) consume(data string, ts float64) {
	rs := []rune(data)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\r' || r == '\n':
			x.flush(ts)
		case r == 0x7f || r == 0x08: // backspace / DEL
			if n := len(x.buf); n > 0 {
				x.buf = x.buf[:n-1]
			}
		case r == 0x15: // Ctrl-U: kill whole line
			x.buf = x.buf[:0]
		case r == 0x03: // Ctrl-C: abort the current line
			x.buf = x.buf[:0]
		case r == 0x1b: // ESC: skip an escape sequence (CSI/SS3 or a lone ESC)
			i = skipEscape(rs, i)
		case r < 0x20: // other control byte (Tab, Ctrl-*, bell, ...) — ignore
		default:
			if len(x.buf) < maxLineLen {
				x.buf = append(x.buf, r)
			}
		}
	}
}

// skipEscape advances past an ANSI escape sequence starting at rs[i]=='\x1b'. It
// returns the index of the sequence's final byte (the loop's i++ moves past it). A
// CSI (ESC [) or SS3 (ESC O) runs to a final byte in 0x40–0x7e; anything else is a
// two-byte sequence.
func skipEscape(rs []rune, i int) int {
	if i+1 >= len(rs) {
		return i
	}
	switch rs[i+1] {
	case '[', 'O':
		j := i + 2
		for j < len(rs) && !(rs[j] >= 0x40 && rs[j] <= 0x7e) {
			j++
		}
		return j // final byte (or end)
	default:
		return i + 1 // ESC + one byte
	}
}

// sanitize strips any residual control characters and trims the reconstructed line;
// returns "" for a line with no printable content.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' {
			b.WriteRune(' ')
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
