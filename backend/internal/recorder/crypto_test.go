package recorder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// TestEncryptedRecordingRoundTrips proves that when a key is supplied the on-disk file
// is NOT plaintext, yet ReadFile and Open both recover the exact plaintext asciicast.
func TestEncryptedRecordingRoundTrips(t *testing.T) {
	dir := t.TempDir()
	key := []byte("recording-key")

	r, err := New(dir, "enc-1", 80, 24, 1700000000, key)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r.Output([]byte("secret token abc123\n"))
	r.Input([]byte("ls\n"))
	r.Resize(120, 40)
	res := r.Close()

	// On-disk bytes must be encrypted (magic prefix, and the secret must not appear).
	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if !IsEncrypted(raw) {
		t.Fatal("encrypted recording must start with the magic prefix")
	}
	if bytes.Contains(raw, []byte("secret token")) {
		t.Fatal("plaintext leaked into the encrypted recording file")
	}

	// ReadFile transparently decrypts.
	plain, err := ReadFile(res.Path, key)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	assertValidAsciicast(t, plain, "secret token abc123")

	// Open yields the same plaintext via the streaming reader.
	rc, err := Open(res.Path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	streamed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if !bytes.Equal(streamed, plain) {
		t.Fatal("streaming Open must match ReadFile output")
	}

	// Wrong key must fail rather than return garbage.
	if _, err := ReadFile(res.Path, []byte("wrong-key")); err == nil {
		t.Fatal("decrypting with the wrong key must error")
	}
}

// TestLegacyPlaintextPassThrough proves that with no key the format is unchanged and
// the readers pass a plaintext recording through untouched (transparent upgrade path).
func TestLegacyPlaintextPassThrough(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "plain-1", 80, 24, 1700000000) // no key
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r.Output([]byte("hello\n"))
	res := r.Close()

	raw, _ := os.ReadFile(res.Path)
	if IsEncrypted(raw) {
		t.Fatal("no-key recording must be legacy plaintext")
	}
	// ReadFile with any key returns the raw plaintext unchanged.
	got, err := ReadFile(res.Path, []byte("ignored"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("legacy plaintext must pass through ReadFile unchanged")
	}
	assertValidAsciicast(t, got, "hello")
}

func assertValidAsciicast(t *testing.T, data []byte, wantOutput string) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(data))
	if !sc.Scan() {
		t.Fatal("missing header line")
	}
	var hdr map[string]any
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
	if v, _ := hdr["version"].(float64); v != 2 {
		t.Fatalf("expected asciicast version 2, got %v", hdr["version"])
	}
	found := false
	for sc.Scan() {
		var ev []any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("event not JSON array: %v (%s)", err, sc.Text())
		}
		if len(ev) == 3 {
			if s, _ := ev[2].(string); strings.Contains(s, wantOutput) {
				found = true
			}
		}
	}
	if wantOutput != "" && !found {
		t.Fatalf("expected an event containing data %q", wantOutput)
	}
}
