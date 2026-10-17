package sessionsapi

import (
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/recorder"
)

// Content search matched nothing in production, for every query: "scanned 0 of 59".
// The reader opened recordings with os.Open, and production encrypts them, so it
// read ciphertext, parsed no events and skipped every file. The existing search tests
// only ever fed it plaintext, so they could not see it.
//
// This writes the recording the way the recorder writes it, with a key, and searches
// it through the same handler the endpoint uses. The plaintext case is kept so the
// legacy pass-through path is still covered.
func TestContentSearchReadsEncryptedRecordings(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"encrypted", []byte(strings.Repeat("k", 32))},
		{"plaintext", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec, err := recorder.New(dir, "sess", 80, 24, 0, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			rec.Output([]byte("keith@ai:~$ \x1b[32msudo systemctl restart nginx\x1b[0m\r\n"))
			res := rec.Close()

			if tc.key != nil {
				raw, err := recorder.ReadFile(res.Path, nil)
				if err == nil && strings.Contains(string(raw), "systemctl") {
					t.Fatal("the recording is not encrypted on disk, so this case proves nothing")
				}
			}

			h := &handler{d: &app.Deps{Cfg: &config.Config{RecordingDir: dir, RecordingEncryptionKey: tc.key}}}
			text := h.cleanedRecording(res.Path)
			n, snippets := matchSnippets(strings.ToLower(text), text, "systemctl restart")
			if n != 1 || len(snippets) != 1 {
				t.Fatalf("search found %d matches in %q; want 1", n, text)
			}
		})
	}
}
