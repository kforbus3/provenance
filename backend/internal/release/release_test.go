package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildTestBundle writes a valid signed bundle to a temp file and returns its path,
// the signing key's public half, and the manifest.
func buildTestBundle(t *testing.T, version, minFrom string, imgContent []byte) (path string, pub ed25519.PublicKey, m Manifest) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "backend.tar")
	if err := os.WriteFile(imgPath, imgContent, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, size, err := HashFile(imgPath)
	if err != nil {
		t.Fatal(err)
	}
	m = Manifest{
		SchemaVersion:          ManifestSchema,
		Version:                version,
		BuildDate:              "2026-07-25T00:00:00Z",
		MinFromVersion:         minFrom,
		Components:             []string{"backend"},
		Images:                 []ImageRef{{Component: "backend", Image: "fleet-terminal-backend", Tag: version, File: "images/backend.tar", Digest: digest, Bytes: size}},
		MigrationCompatibility: CompatAdditive,
	}
	mj, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(mj, priv)
	path = filepath.Join(dir, "bundle.fleetup")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(f, mj, sig, map[string]string{"images/backend.tar": imgPath}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path, pub, m
}

func TestBundleRoundTrip(t *testing.T) {
	content := bytes.Repeat([]byte("fleetd-image-bytes"), 100)
	path, pub, _ := buildTestBundle(t, "v0.61.0", "v0.55.0", content)

	b, err := Open(path, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	if b.Manifest.Version != "v0.61.0" {
		t.Fatalf("version = %q", b.Manifest.Version)
	}
	if err := b.Manifest.CheckUpgradeable("v0.60.0"); err != nil {
		t.Fatalf("CheckUpgradeable: %v", err)
	}
	imgs, err := b.ExtractImages(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("ExtractImages: %v", err)
	}
	got, err := os.ReadFile(imgs["backend"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("extracted image content mismatch")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	path, _, _ := buildTestBundle(t, "v0.61.0", "v0.55.0", []byte("img"))
	otherPub, _, _ := GenerateKey()
	if _, err := Open(path, []ed25519.PublicKey{otherPub}); err == nil {
		t.Fatal("expected Open to fail with a non-signing key")
	}
}

func TestVerifyRejectsEmptyTrustSet(t *testing.T) {
	path, _, _ := buildTestBundle(t, "v0.61.0", "v0.55.0", []byte("img"))
	if _, err := Open(path, nil); err == nil {
		t.Fatal("expected Open to fail closed with no trusted keys")
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	// Sign one manifest, then swap in a different manifest body under the same sig.
	pub, priv, _ := GenerateKey()
	gj, _ := json.Marshal(Manifest{SchemaVersion: ManifestSchema, Version: "v0.61.0"})
	sig := Sign(gj, priv)
	tampered, _ := json.Marshal(Manifest{SchemaVersion: ManifestSchema, Version: "v9.9.9"})
	if err := Verify(tampered, sig, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected Verify to reject a manifest that wasn't the one signed")
	}
}

func TestExtractDetectsDigestTamper(t *testing.T) {
	// Sign a manifest, then rewrite the bundle's image bytes so the digest no longer
	// matches — ExtractImages must reject it even though the signature is valid.
	pub, priv, _ := GenerateKey()
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "backend.tar")
	os.WriteFile(imgPath, []byte("original-image"), 0o600)
	digest, size, _ := HashFile(imgPath)
	m := Manifest{SchemaVersion: ManifestSchema, Version: "v0.61.0", MigrationCompatibility: CompatAdditive,
		Components: []string{"backend"},
		Images:     []ImageRef{{Component: "backend", Image: "fleet-terminal-backend", Tag: "v0.61.0", File: "images/backend.tar", Digest: digest, Bytes: size}}}
	mj, _ := json.Marshal(m)
	sig := Sign(mj, priv)

	// Write the bundle but substitute different image bytes (same signed manifest).
	evil := filepath.Join(dir, "evil.tar")
	os.WriteFile(evil, []byte("malicious-image-payload"), 0o600)
	var buf bytes.Buffer
	if err := WriteBundle(&buf, mj, sig, map[string]string{"images/backend.tar": evil}); err != nil {
		t.Fatal(err)
	}
	b, err := openReader(&buf, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("openReader (sig should still verify): %v", err)
	}
	if _, err := b.ExtractImages(filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected ExtractImages to reject a digest mismatch")
	}
}

func TestCheckUpgradeable(t *testing.T) {
	m := Manifest{Version: "v0.61.0", MinFromVersion: "v0.55.0"}
	cases := []struct {
		current string
		wantErr bool
		name    string
	}{
		{"v0.60.0", false, "newer than current, above min"},
		{"v0.61.0", true, "same version (not newer)"},
		{"v0.62.0", true, "current is newer (downgrade)"},
		{"v0.54.0", true, "current below minFromVersion"},
		{"v0.55.0", false, "current exactly at min"},
		{"dev", false, "dev build installs anything"},
		{"v0.61.0-rc1+abcdef", true, "prerelease suffix ignored -> same triple"},
	}
	for _, c := range cases {
		err := m.CheckUpgradeable(c.current)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: current=%s err=%v wantErr=%v", c.name, c.current, err, c.wantErr)
		}
	}
}

func TestParseKeysRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKey()
	keys, err := ParsePublicKeys(EncodePublicKey(pub) + " , " + EncodePublicKey(pub))
	if err != nil || len(keys) != 2 {
		t.Fatalf("ParsePublicKeys: keys=%d err=%v", len(keys), err)
	}
	gotPriv, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil || !bytes.Equal(gotPriv, priv) {
		t.Fatalf("ParsePrivateKey round-trip failed: %v", err)
	}
	if _, err := ParsePublicKeys("not-base64!!"); err == nil {
		t.Fatal("expected ParsePublicKeys to reject garbage")
	}
}
