package winrm

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// Every PowerShell script over roughly 3 KB failed, including this product's own.
//
// -EncodedCommand is base64 of UTF-16LE, about 2.7 characters per source character,
// and the remote end runs the result through cmd.exe with its 8191-character limit.
// Measured against a live Windows Server 2025 host with the Windows enrollment script
// Provenance itself generates:
//
//	script    5,385 bytes
//	encoded  14,352 chars
//	command  14,434 chars   (limit 8,191)
//
// The host answered "The command line is too long." on stderr with exit 1 — nothing
// about scripts, encoding or size, and nothing an operator could act on.
func TestASmallScriptStillGoesOnTheCommandLine(t *testing.T) {
	small := "Get-CimInstance Win32_OperatingSystem"
	if !fitsCommandLine(small) {
		t.Fatal("a one-line script no longer fits the command line")
	}
	cmd := psDirect(small)
	if !strings.Contains(cmd, "-EncodedCommand") || len(cmd) > maxCommandLine {
		t.Errorf("unexpected command line (%d chars)", len(cmd))
	}
}

func TestTheEnrollmentScriptSizedScriptDoesNotFit(t *testing.T) {
	// 5,385 bytes: the size of the real Windows enrollment script.
	big := strings.Repeat("a", 5385)
	if fitsCommandLine(big) {
		t.Fatal("a 5,385-byte script is being sent on the command line; the host will " +
			"refuse it with \"The command line is too long.\"")
	}
}

// fakeRunner records what would be sent to the host.
type fakeRunner struct {
	cmds   []string
	stdins []string
	codes  []int
}

func (f *fakeRunner) RunWithContextWithString(_ context.Context, cmd, stdin string) (string, string, int, error) {
	f.cmds = append(f.cmds, cmd)
	f.stdins = append(f.stdins, stdin)
	code := 0
	if len(f.codes) >= len(f.cmds) {
		code = f.codes[len(f.cmds)-1]
	}
	return "out", "", code, nil
}

// The large-script path must not touch stdin, and must not nest a shell.
//
// Two earlier attempts failed against a live host, which is why both are asserted:
//
//   - Reading the script from stdin and running it in place leaves stdin consumed, and
//     PowerShell splices the remains into any native command the script pipes to. The
//     enrollment script does that (`$priv | & wg.exe pubkey`) and the host answered
//     "wg.exe: Trailing characters found after key" on a well-formed key.
//   - `cmd /c "powershell -File ... < NUL"` nests a shell inside the WinRM shell and
//     hung without ever returning.
func TestALargeScriptUploadsInChunksAndTouchesNeitherStdinNorANestedShell(t *testing.T) {
	script := strings.Repeat("Write-Output 'x'\n", 400)
	f := &fakeRunner{}
	if _, _, _, err := runLarge(context.Background(), f, script); err != nil {
		t.Fatalf("runLarge: %v", err)
	}
	if len(f.cmds) < 2 {
		t.Fatalf("expected chunked upload plus an execute, got %d command(s)", len(f.cmds))
	}
	for i, c := range f.cmds {
		if len(c) > maxCommandLine {
			t.Errorf("command %d is %d chars, over the %d limit", i, len(c), maxCommandLine)
		}
	}
	for i, s := range f.stdins {
		if s != "" {
			t.Errorf("command %d used stdin; a script that pipes to a native command will "+
				"have the remains of stdin spliced into it", i)
		}
	}
	all := strings.Join(f.cmds, "\n")
	decoded := decodeAll(t, f.cmds)
	if strings.Contains(decoded, "cmd.exe") || strings.Contains(all, "< NUL") {
		t.Error("the large-script path nests a shell inside the WinRM shell, which hung " +
			"against a real host")
	}
	if !strings.Contains(decoded, "Remove-Item") {
		t.Error("a failed script would leave its source in TEMP")
	}
	// The script actually arrives: the uploaded chunks must reassemble to it.
	if got := reassemble(t, decoded); !strings.Contains(got, "Write-Output 'x'") {
		t.Error("the uploaded chunks do not reassemble into the caller's script")
	}
	if !strings.HasPrefix(reassemble(t, decoded), "$ProgressPreference") {
		t.Error("the large-script path lost the progress suppression")
	}
}

// An upload that fails must stop rather than run a half-written script.
func TestAFailedUploadDoesNotRunAPartialScript(t *testing.T) {
	f := &fakeRunner{codes: []int{1, 0, 0, 0}}
	_, _, _, err := runLarge(context.Background(), f, strings.Repeat("Write-Output 'x'\n", 400))
	if err == nil {
		t.Fatal("a failed chunk upload was ignored; the host would run a truncated script")
	}
	if len(f.cmds) != 1 {
		t.Errorf("kept going after a failed chunk: %d commands issued", len(f.cmds))
	}
}

func decodeAll(t *testing.T, cmds []string) string {
	t.Helper()
	var b strings.Builder
	for _, c := range cmds {
		i := strings.LastIndex(c, " ")
		raw, err := base64.StdEncoding.DecodeString(c[i+1:])
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		u16 := make([]uint16, 0, len(raw)/2)
		for j := 0; j+1 < len(raw); j += 2 {
			u16 = append(u16, uint16(raw[j])|uint16(raw[j+1])<<8)
		}
		b.WriteString(string(utf16.Decode(u16)))
		b.WriteString("\n")
	}
	return b.String()
}

// reassemble pulls the base64 payload back out of the upload statements.
func reassemble(t *testing.T, decoded string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(decoded, "\n") {
		i := strings.Index(line, "-Value '")
		j := strings.LastIndex(line, "'")
		if i < 0 || j <= i+8 {
			continue
		}
		b.WriteString(line[i+8 : j])
	}
	raw, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		t.Fatalf("reassemble: %v (%d chars)", err, b.Len())
	}
	return string(raw)
}

var _ = fmt.Sprintf
