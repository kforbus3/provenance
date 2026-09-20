package backup

import (
	"strings"
	"testing"
)

// A truncated dump is the failure a file size cannot show.
//
// pg_dump writes its completion marker last, so a dump whose process died partway
// through looks entirely normal: it decrypts, it has tables, it has data. It simply
// stops. Without checking for the marker, a backup that restores two thirds of an
// estate verifies clean.
func TestScanDumpFindsTruncation(t *testing.T) {
	complete := "--\n-- PostgreSQL database dump\n--\nCREATE TABLE public.hosts (id uuid);\n" +
		"COPY public.hosts (id) FROM stdin;\n\\.\n--\n-- PostgreSQL database dump complete\n--\n"
	truncated := strings.TrimSuffix(complete, "--\n-- PostgreSQL database dump complete\n--\n")

	n, tables, copies, done := scanDump(strings.NewReader(complete))
	if !done || tables != 1 || copies != 1 || n == 0 {
		t.Fatalf("a complete dump read as bytes=%d tables=%d copies=%d complete=%v", n, tables, copies, done)
	}
	if _, _, _, done := scanDump(strings.NewReader(truncated)); done {
		t.Error("a truncated dump reported as complete — a backup missing its tail " +
			"restores part of an estate and looks fine until it is needed")
	}
}

// A marker split across a read boundary must still be seen. The reader takes 64KB at a
// time and the marker is the last line of a very large file, so this is the ordinary
// case, not an edge one.
func TestScanDumpAcrossBufferBoundaries(t *testing.T) {
	body := "CREATE TABLE public.a (id int);\n" + strings.Repeat("x", 200*1024) + "\n" +
		"CREATE TABLE public.b (id int);\n-- PostgreSQL database dump complete\n"
	_, tables, _, done := scanDump(strings.NewReader(body))
	if tables != 2 {
		t.Errorf("counted %d tables across a 200KB span, want 2", tables)
	}
	if !done {
		t.Error("the completion marker was missed because it fell past a buffer boundary")
	}
}

// The final line of a file has no trailing newline, and that is exactly where the
// completion marker lives.
func TestScanDumpFinalLineWithoutNewline(t *testing.T) {
	if _, _, _, done := scanDump(strings.NewReader("CREATE TABLE x (i int);\n-- PostgreSQL database dump complete")); !done {
		t.Error("an unterminated final line was dropped, so every backup whose marker " +
			"is the last line without a newline reads as truncated")
	}
}

func TestVerifyResultVerdicts(t *testing.T) {
	good := VerifyResult{Decrypted: 100, Tables: 3, Complete: true, HMACPresent: true, HMACValid: true}
	if !good.OK() || good.Problem() != "" {
		t.Errorf("a sound backup reported a problem: %q", good.Problem())
	}
	// No sidecar is not corruption: backups written before it existed have none.
	old := VerifyResult{Decrypted: 100, Tables: 3, Complete: true}
	if !old.OK() {
		t.Error("a backup with no HMAC sidecar was failed outright, which would condemn " +
			"every backup taken before the sidecar existed")
	}
	for _, tc := range []struct {
		name string
		v    VerifyResult
		want string
	}{
		{"tampered", VerifyResult{HMACPresent: true, HMACValid: false, Tables: 3, Complete: true, Decrypted: 1}, "altered"},
		{"empty", VerifyResult{Complete: true, Tables: 3}, "decrypts to nothing"},
		{"truncated", VerifyResult{Decrypted: 10, Tables: 3}, "truncated"},
		{"no tables", VerifyResult{Decrypted: 10, Complete: true}, "no table definitions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.v.OK() {
				t.Fatal("reported OK")
			}
			if !strings.Contains(tc.v.Problem(), tc.want) {
				t.Errorf("problem was %q, want something mentioning %q", tc.v.Problem(), tc.want)
			}
		})
	}
}

// pg_dump says why it failed; only openssl's stderr was being kept, so every dump
// failure arrived as "pg_dump=exit status 1".
func TestFirstErrorPullsTheCauseAndTheWayOut(t *testing.T) {
	stderr := "pg_dump: last built-in OID is 16383\n" +
		"pg_dump: error: query failed: ERROR:  query would be affected by row-level security policy for table \"access_policies\"\n" +
		"pg_dump: detail: Query was: COPY public.access_policies (id, name) TO stdout;\n"
	got := firstError(stderr)
	if !strings.Contains(got, "row-level security") {
		t.Errorf("the cause was not picked out: %q", got)
	}
	if !strings.Contains(got, "detail") {
		t.Errorf("the detail line, which names the table, was dropped: %q", got)
	}
	if firstError("nothing interesting here\n") != "" {
		t.Error("invented a cause where pg_dump reported none")
	}
}
