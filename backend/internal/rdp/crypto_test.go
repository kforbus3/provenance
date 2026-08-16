package rdp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/recorder"
)

// A representative slice of a guacd Guacamole session recording (length-prefixed
// instruction stream). Large enough to span more than one seal chunk boundary.
func sampleRecording() []byte {
	var b bytes.Buffer
	b.WriteString("5.audio,1.1,31.audio/L16;rate=44100,channels=2;\n")
	for i := 0; i < 5000; i++ {
		b.WriteString("4.sync,4.1234;3.img,1.0,5.14.20,1.0,1.0,3.640,3.480;\n")
	}
	b.WriteString("10.disconnect;\n")
	return b.Bytes()
}

// With a key set: the on-disk file must be encrypted (magic prefix, no plaintext
// leak), and reading it back through recorder must recover the exact original bytes.
func TestEncryptFileAtRest_EncryptsAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.guac")
	orig := sampleRecording()
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	key := []byte("this-is-a-32-byte-recording-key!")
	if err := encryptFileAtRest(path, key); err != nil {
		t.Fatalf("encryptFileAtRest: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	if !recorder.IsEncrypted(onDisk) {
		t.Fatalf("on-disk file is not marked encrypted (missing magic)")
	}
	// No plaintext leak: a distinctive substring from the original must not appear
	// anywhere in the ciphertext.
	if bytes.Contains(onDisk, []byte("audio/L16")) {
		t.Fatalf("plaintext leaked into the encrypted file on disk")
	}
	if bytes.Contains(onDisk, []byte("disconnect")) {
		t.Fatalf("plaintext leaked into the encrypted file on disk")
	}

	// Read-back through the shared recorder reader recovers the original exactly.
	got, err := recorder.ReadFile(path, key)
	if err != nil {
		t.Fatalf("recorder.ReadFile: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(orig))
	}
}

// With no key: the file is left as plaintext (legacy passthrough) and still reads back
// unchanged through the recorder reader.
func TestEncryptFileAtRest_NoKeyPassthrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.guac")
	orig := sampleRecording()
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	if err := encryptFileAtRest(path, nil); err != nil {
		t.Fatalf("encryptFileAtRest(nil key): %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if recorder.IsEncrypted(onDisk) {
		t.Fatalf("file was encrypted despite empty key")
	}
	if !bytes.Equal(onDisk, orig) {
		t.Fatalf("no-key path modified the file")
	}
	// recorder reads legacy plaintext unchanged (key ignored).
	got, err := recorder.ReadFile(path, nil)
	if err != nil {
		t.Fatalf("recorder.ReadFile: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("plaintext round-trip mismatch")
	}
}

// Encrypting twice must be idempotent: the second call sees the magic and leaves the
// already-encrypted file intact (no double-encryption).
func TestEncryptFileAtRest_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.guac")
	orig := sampleRecording()
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	key := []byte("this-is-a-32-byte-recording-key!")
	if err := encryptFileAtRest(path, key); err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	first, _ := os.ReadFile(path)
	if err := encryptFileAtRest(path, key); err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatalf("second encrypt modified an already-encrypted file")
	}
	got, err := recorder.ReadFile(path, key)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("round-trip after idempotent re-encrypt mismatch")
	}
}

// A missing recording file (session too short for guacd to write anything) is a no-op,
// not an error.
func TestEncryptFileAtRest_MissingFile(t *testing.T) {
	if err := encryptFileAtRest(filepath.Join(t.TempDir(), "nope.guac"), []byte("k")); err != nil {
		t.Fatalf("missing file should be a no-op, got %v", err)
	}
}
