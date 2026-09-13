package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		Lineage:                Lineage,
		SchemaVersion:          ManifestSchema,
		Version:                version,
		BuildDate:              "2026-07-25T00:00:00Z",
		MinFromVersion:         minFrom,
		Components:             []string{"backend"},
		Images:                 []ImageRef{{Component: "backend", Image: "provenance-backend", Tag: version, File: "images/backend.tar", Digest: digest, Bytes: size}},
		MigrationCompatibility: CompatAdditive,
	}
	mj, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(mj, priv)
	path = filepath.Join(dir, "bundle.provup")
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
	content := bytes.Repeat([]byte("provd-image-bytes"), 100)
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
		Images:     []ImageRef{{Component: "backend", Image: "provenance-backend", Tag: "v0.61.0", File: "images/backend.tar", Digest: digest, Bytes: size}}}
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
	m := Manifest{Version: "v0.61.0", MinFromVersion: "v0.55.0", Lineage: Lineage}
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

// Version numbers alone cannot answer "is this the same product?". This repository
// carries tags from two earlier product lines it was forked from, and their
// numbering runs AHEAD of the current one — so a Moorgate-era v2.0.2 bundle
// outranks a running v1.3.0 by semver. A gate that only asks "is it newer?" accepts
// it and installs a different, older codebase over the running stack.
//
// This is not hypothetical: that exact bundle was sitting in the deployment's
// updates volume.
func TestABundleFromAnotherProductLineIsRefusedEvenWhenItIsNewer(t *testing.T) {
	moorgate := Manifest{Version: "v2.0.2", MinFromVersion: "0.0.0", Lineage: "moorgate"}
	err := moorgate.CheckUpgradeable("v1.3.0")
	if err == nil {
		t.Fatal("a v2.0.2 bundle from another product line was accepted over a running v1.3.0")
	}
	if !strings.Contains(err.Error(), "different product") {
		t.Errorf("error %q does not say the product differs", err)
	}
	// And it must be refused for being a different product, not merely for being
	// older — because it is NOT older, which is the whole trap.
	if strings.Contains(err.Error(), "not newer") {
		t.Errorf("refused on version ordering rather than identity: %v", err)
	}
}

// A bundle that predates lineage tagging cannot assert it is this product, and the
// bundles that predate it are exactly the dangerous ones. Refused, with the remedy
// named.
func TestABundleWithNoLineageIsRefused(t *testing.T) {
	old := Manifest{Version: "v9.9.9", MinFromVersion: "0.0.0"}
	err := old.CheckUpgradeable("v1.3.0")
	if err == nil {
		t.Fatal("a bundle declaring no lineage was accepted")
	}
	if !strings.Contains(err.Error(), "lineage") || !strings.Contains(err.Error(), "provctl") {
		t.Errorf("error %q does not name the problem and the remedy", err)
	}
}

// Identity is checked BEFORE ordering, or a foreign bundle with a high version
// number never reaches the identity test at all.
func TestLineageIsCheckedBeforeVersionOrdering(t *testing.T) {
	// Same version as the running build: ordering alone would reject this as "not
	// newer". The error must still be the lineage one, proving identity ran first.
	foreign := Manifest{Version: "v1.3.0", MinFromVersion: "0.0.0", Lineage: "moorgate"}
	err := foreign.CheckUpgradeable("v1.3.0")
	if err == nil || !strings.Contains(err.Error(), "different product") {
		t.Fatalf("identity is not checked first; got %v", err)
	}
}

// A genuine release of this line still installs, and the lineage match is not
// case-sensitive — it is a name, not a token to be typed exactly.
func TestOurOwnLineageStillInstalls(t *testing.T) {
	for _, l := range []string{Lineage, strings.ToUpper(Lineage), " " + Lineage + " "} {
		m := Manifest{Version: "v1.4.0", MinFromVersion: "0.0.0", Lineage: l}
		if err := m.CheckUpgradeable("v1.3.0"); err != nil {
			t.Errorf("lineage %q was refused: %v", l, err)
		}
	}
}

// A "dev" running build is allowed to install anything on version grounds, and that
// must NOT become a hole in the identity check — a developer machine is exactly
// where a stray foreign bundle gets tried.
func TestADevBuildStillRefusesAForeignBundle(t *testing.T) {
	foreign := Manifest{Version: "v2.0.2", MinFromVersion: "0.0.0", Lineage: "moorgate"}
	if err := foreign.CheckUpgradeable("dev"); err == nil {
		t.Fatal("a dev build accepted a bundle from another product line")
	}
}

// The builder must stamp the lineage, or every bundle it produces is refused by the
// gate it just gained.
func TestBuiltManifestsDeclareTheLineage(t *testing.T) {
	if Lineage == "" {
		t.Fatal("Lineage constant is empty")
	}
	m := Manifest{Version: "v1.4.0", MinFromVersion: "0.0.0", Lineage: Lineage}
	if err := m.CheckUpgradeable("v1.3.0"); err != nil {
		t.Fatalf("a manifest stamped with the build's own lineage was refused: %v", err)
	}
}
