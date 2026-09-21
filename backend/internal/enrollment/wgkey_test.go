package enrollment

import (
	"strings"
	"testing"
)

// The Windows enrollment script could not generate a keypair, so no Windows host
// could join the overlay at all.
//
// wg.exe reads the private key from stdin and rejects anything after it, including a
// carriage return. PowerShell's native-command pipeline terminates what it writes with
// CRLF, so `$priv | & $wg pubkey` failed with
//
//	wg.exe: Trailing characters found after key
//
// and the script stopped at step 2, before writing a config or installing anything.
// Measured on Windows Server 2025 / PowerShell 5.1: the pipe fails every time, a file
// holding the bare key succeeds every time.
func TestTheWindowsScriptDoesNotPipeTheKeyIntoWgPubkey(t *testing.T) {
	full := windowsWGScript("10.100.0.24", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"jump.example.com:51820", "10.100.0.1/32", 51820)
	// Only what the host will RUN. The comment above the fix quotes the broken form on
	// purpose, so asserting against the raw text would fail on the explanation of the
	// very bug being prevented.
	script := strings.Join(codeLines(full), "\n")

	if strings.Contains(script, "$priv | & $wg pubkey") {
		t.Error("the private key is piped into wg.exe; PowerShell appends CRLF and wg.exe " +
			"answers \"Trailing characters found after key\", so enrollment never gets past " +
			"generating the keypair")
	}
	if !strings.Contains(script, "pubkey <") {
		t.Error("the public key is not derived by redirecting a file into wg.exe pubkey, " +
			"which is the form that works")
	}
	// The private key must not be left lying in TEMP.
	if !strings.Contains(script, "Remove-Item -LiteralPath $keyFile") {
		t.Error("the temporary private-key file is never removed")
	}
	// And a silent failure there must not produce a config with an empty key.
	if !strings.Contains(script, "if (-not $pub)") {
		t.Error("an empty public key is not detected; enrollment would continue and print " +
			"nothing for the operator to paste back")
	}
}

// codeLines drops comment-only lines from a PowerShell script.
func codeLines(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
