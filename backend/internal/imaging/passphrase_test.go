package imaging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/config"
)

func svcWithDir(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	return &Service{cfg: &config.Config{ArtifactDir: dir}}, dir
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The passphrase is filed under the image's name, so the name has to be settled
// before the build starts — and it has to be one the build will actually produce.
func TestFreeImageNameTakesTheBaseWhenNothingIsThere(t *testing.T) {
	s, _ := svcWithDir(t)
	if got := s.FreeImageName("debian-trixie-amd64-ab"); got != "debian-trixie-amd64-ab.img" {
		t.Errorf("FreeImageName = %q, want the plain base name", got)
	}
}

// Rebuilding must not overwrite: the sidecar's own comment records that it once
// did, and the cost was the recovery key of a machine already in the field.
func TestFreeImageNameSkipsNamesAlreadyInTheLibrary(t *testing.T) {
	s, dir := svcWithDir(t)
	touch(t, filepath.Join(dir, "debian-trixie-amd64-ab.img"))
	if got := s.FreeImageName("debian-trixie-amd64-ab"); got != "debian-trixie-amd64-ab-2.img" {
		t.Errorf("FreeImageName = %q, want -2", got)
	}
	touch(t, filepath.Join(dir, "debian-trixie-amd64-ab-2.img"))
	if got := s.FreeImageName("debian-trixie-amd64-ab"); got != "debian-trixie-amd64-ab-3.img" {
		t.Errorf("FreeImageName = %q, want -3", got)
	}
}

// Every extension counts. An uncompressed build landing beside the .zst of the
// same name is two different images sharing one identity — and one passphrase
// that no longer says which it opens.
func TestFreeImageNameCountsCompressedVariants(t *testing.T) {
	for _, ext := range []string{".img", ".img.zst", ".img.gz"} {
		s, dir := svcWithDir(t)
		touch(t, filepath.Join(dir, "base"+ext))
		if got := s.FreeImageName("base"); got != "base-2.img" {
			t.Errorf("with %s present, FreeImageName = %q, want base-2.img", ext, got)
		}
	}
}

// The name reaches a shell command line and is also a path component in a secrets
// manager. It is sanitised the same way the builder sanitises it.
func TestFreeImageNameSanitizes(t *testing.T) {
	s, _ := svcWithDir(t)
	cases := map[string]string{
		// '/' becomes '-'; '.' is legal in an image name so ".." survives as
		// characters. That is the builder's own rule, and it is safe because what
		// makes ".." dangerous is a separator next to it — see the traversal test.
		"debian/../etc": "debian-..-etc.img",
		// The trailing '/' becomes '-' and is then trimmed with the rest.
		"a b;rm -rf /": "a-b-rm--rf.img",
		"  spaced  ":   "spaced.img",
		"--leading--":  "leading.img",
		"":             "image.img",
		"...":          "image.img",
		"ok_name-1.2":  "ok_name-1.2.img",
	}
	for in, want := range cases {
		if got := s.FreeImageName(in); got != want {
			t.Errorf("FreeImageName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A name must never escape the output directory or the secrets-manager prefix.
//
// The property that matters is not "contains no ..", because '.' is a legal
// character in an image name and `ok_name-1.2` is fine. It is that the name has
// no path SEPARATOR, so joining it to a directory cannot leave that directory
// however many dots it contains.
func TestFreeImageNameCannotTraverse(t *testing.T) {
	s, dir := svcWithDir(t)
	for _, in := range []string{
		"../../etc/shadow", "/etc/shadow", "a/../../b", "..", "../..",
		`..\..\windows`, "a/b/c",
	} {
		got := s.FreeImageName(in)
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("FreeImageName(%q) = %q, which contains a path separator", in, got)
		}
		joined := filepath.Clean(filepath.Join(dir, got))
		if !strings.HasPrefix(joined, dir+string(os.PathSeparator)) {
			t.Errorf("FreeImageName(%q) = %q, which joins to %q — outside %q", in, got, joined, dir)
		}
		// The same name is one path component in the secrets manager. The property
		// is that normalising the reference does not MOVE it — not that the name
		// avoids the characters '.' and '.', which are legal in an image name.
		const prefix = "secret/blackfriars/images/"
		ref := prefix + got
		if cleaned := filepath.Clean(ref); cleaned != ref || !strings.HasPrefix(cleaned, prefix) {
			t.Errorf("FreeImageName(%q) = %q: ref %q normalises to %q", in, got, ref, cleaned)
		}
	}
}

// One secret per image whatever it was compressed to. Rebuilding the same image
// with a different --compress must not strand the passphrase under the old name.
func TestSecretNameForImageIgnoresCompression(t *testing.T) {
	for _, in := range []string{
		"debian-trixie-amd64-ab.img",
		"debian-trixie-amd64-ab.img.zst",
		"debian-trixie-amd64-ab.img.gz",
		"/output/debian-trixie-amd64-ab.img.zst",
	} {
		if got := secretNameForImage(in); got != "debian-trixie-amd64-ab.img" {
			t.Errorf("secretNameForImage(%q) = %q, want the .img name", in, got)
		}
	}
}

// Two builds must not get the same passphrase, and it must not be short.
func TestGeneratePassphraseIsRandomAndLong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		p, err := generatePassphrase()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) < 40 {
			t.Fatalf("passphrase %q is %d chars, want a 256-bit value", p, len(p))
		}
		if seen[p] {
			t.Fatal("generatePassphrase returned a duplicate")
		}
		seen[p] = true
		// It travels through a shell environment and a JSON body; base64url keeps
		// it free of anything that needs quoting.
		if strings.ContainsAny(p, "\"'`$\\ \n/+=") {
			t.Fatalf("passphrase %q contains a character that needs quoting", p)
		}
	}
}

// imageBaseName decides what the secret is filed under, so its defaults must
// match the builder's or the two disagree about the image's identity.
func TestImageBaseNameMatchesTheBuilderDefaults(t *testing.T) {
	if got := imageBaseName(map[string]any{}); got != "debian-trixie-amd64-ab" {
		t.Errorf("imageBaseName(empty) = %q, want the builder's own default", got)
	}
	got := imageBaseName(map[string]any{"distro": "ubuntu", "suite": "noble", "arch": "arm64"})
	if got != "ubuntu-noble-arm64-ab" {
		t.Errorf("imageBaseName = %q", got)
	}
	// An explicit name wins and loses its extension, so the free-name search and
	// the secret key agree on the stem.
	for _, in := range []string{"custom.img", "custom.img.zst", "custom"} {
		if got := imageBaseName(map[string]any{"name": in}); got != "custom" {
			t.Errorf("imageBaseName(%q) = %q, want custom", in, got)
		}
	}
}

// The flag arrives as JSON from a browser, but a form or a script may send it as
// a string; reading only bools would silently skip storing the passphrase, which
// is the failure this whole path exists to prevent.
func TestTruthyAcceptsBoolsAndStrings(t *testing.T) {
	for _, v := range []any{true, "true", "1"} {
		if !truthy(v) {
			t.Errorf("truthy(%#v) = false, want true", v)
		}
	}
	for _, v := range []any{false, "false", "0", "", nil, 1, "yes"} {
		if truthy(v) {
			t.Errorf("truthy(%#v) = true, want false", v)
		}
	}
}
