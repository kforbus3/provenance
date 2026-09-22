package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A recording that lost content used to present itself as complete.
//
// Write errors were discarded — the encrypted path logged a warning and the plaintext
// path said nothing at all — and the recording then got a SHA-256 and a database row
// like any other. A truncated transcript that looks whole is worse than a missing one:
// somebody reviewing the session sees a coherent recording and has no way to know the
// interesting part is the bit that never got written.
func TestARecordingThatLostContentSaysSo(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "sess", 80, 24, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Truncated() {
		t.Error("a fresh recording reports itself truncated")
	}

	// Close the underlying file so every subsequent write fails, which is what a full
	// disk or a revoked permission looks like from here.
	if err := r.f.Close(); err != nil {
		t.Fatal(err)
	}
	r.Output([]byte("rm -rf /important\n"))
	r.Output([]byte("more output\n"))

	if !r.Truncated() {
		t.Error("content was dropped and the recording does not report it, so it will be " +
			"stored, hashed and replayed as though it were complete")
	}
	if r.DroppedFrames() != 2 {
		t.Errorf("dropped %d frame(s), want 2", r.DroppedFrames())
	}
}

// The happy path must stay clean, or the flag means nothing.
func TestACompleteRecordingIsNotMarkedTruncated(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "sess", 80, 24, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.Output([]byte("hello\n"))
	res := r.Close()
	if r.Truncated() {
		t.Error("a recording that wrote successfully reports itself truncated")
	}
	if res.SHA256 == "" || res.SizeBytes == 0 {
		t.Errorf("unexpected result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "sess.cast")); err != nil {
		t.Errorf("recording file missing: %v", err)
	}
}

// Encrypted recordings must behave the same way — that path only warned before.
func TestAnEncryptedRecordingAlsoReportsLostContent(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "sess", 80, 24, 0, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.f.Close(); err != nil {
		t.Fatal(err)
	}
	r.Output([]byte("secret output\n"))
	if !r.Truncated() {
		t.Error("an encrypted recording dropped content without reporting it")
	}
}

// Four corrupt bytes must not decide an allocation.
//
// frameReader read a 32-bit frame length from the file and passed it straight to
// make(). A truncated recording from a crashed session, a bit-flip on disk, or an
// edited file could therefore ask for up to 4 GiB — turning "replay this session"
// into an out-of-memory kill of the backend.
func TestACorruptFrameLengthIsRefusedNotAllocated(t *testing.T) {
	dir := t.TempDir()
	key := []byte(strings.Repeat("k", 32))
	r, err := New(dir, "sess", 80, 24, 0, key)
	if err != nil {
		t.Fatal(err)
	}
	r.Output([]byte("hello\n"))
	res := r.Close()

	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Overwrite the first frame's length with something enormous, leaving the magic
	// header intact so it is still recognised as a recording.
	i := len(recMagic)
	if len(raw) < i+4 {
		t.Fatalf("recording too short to corrupt: %d bytes", len(raw))
	}
	raw[i], raw[i+1], raw[i+2], raw[i+3] = 0xFF, 0xFF, 0xFF, 0xFF
	bad := filepath.Join(dir, "corrupt.cast")
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rc, err := Open(bad, key)
	if err != nil {
		return // refused at open: also acceptable
	}
	defer rc.Close()
	buf := make([]byte, 64)
	if _, err := rc.Read(buf); err == nil {
		t.Error("a frame claiming ~4 GiB was accepted; the length from the file must not " +
			"size an allocation")
	}
}
