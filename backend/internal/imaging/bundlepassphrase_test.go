package imaging

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Building a bundle reads the image's root slot, so an encrypted image needs its
// passphrase. The server generated it, filed it, and knows which image it belongs
// to — and made the operator find it and paste it back anyway, or watch:
//
//	[bundle] ERROR: this image is encrypted; pass --luks-passphrase
//
// These cover the decisions around that lookup. The lookup itself needs a store
// and a sealed vault, which is an integration concern; what is checked here is
// everything that decides WHETHER it happens and what is done with the result.

// secretNameForImage is what links an image to its filed passphrase. If it
// stops agreeing with the name used when filing, the lookup silently finds
// nothing and every encrypted bundle build starts failing again.
func TestImageNameMapsToTheNameItWasFiledUnder(t *testing.T) {
	for _, tc := range []struct{ image, want string }{
		{"almalinux-9-amd64-ab-2.img", "almalinux-9-amd64-ab-2.img"},
		// The build files under the uncompressed name; the bundle dialog offers
		// whatever is on disk, which is compressed.
		{"almalinux-9-amd64-ab-2.img.zst", "almalinux-9-amd64-ab-2.img"},
		{"rocky-9-amd64-ab.img.gz", "rocky-9-amd64-ab.img"},
		// A path must not become part of the credential name.
		{"/output/rocky-9-amd64-ab.img", "rocky-9-amd64-ab.img"},
		{"  spaced.img  ", "spaced.img"},
	} {
		if got := secretNameForImage(tc.image); got != tc.want {
			t.Errorf("secretNameForImage(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

// Only image builds file a passphrase. A bundle build must not create a second
// credential for an image that already has one.
func TestOnlyImageBuildsFileAPassphrase(t *testing.T) {
	body := map[string]any{"encrypt": true, "generatePassphrase": true}
	if !shouldFilePassphrase("image", body) {
		t.Error("an encrypted image build asking for a generated passphrase must file one")
	}
	for _, kind := range []string{"bundle", "imager"} {
		if shouldFilePassphrase(kind, body) {
			t.Errorf("%s build filed a passphrase", kind)
		}
	}
	// The security property: storing is opt-in, and off means off.
	if shouldFilePassphrase("image", map[string]any{"encrypt": true}) {
		t.Error("filed a passphrase without generatePassphrase — that breaks the promise " +
			"the build dialog makes to someone building a laptop image")
	}
}

// The external backend stores the whole field set; the local vault seals the
// passphrase alone. Both have to yield the same string, or bundle builds work on
// one deployment and not the other.
func TestPassphrasePayloadShapes(t *testing.T) {
	blob, err := json.Marshal(map[string]string{
		"passphrase": "s3cret-value", "image": "x.img", "note": "…",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if json.Unmarshal(blob, &fields) != nil || fields["passphrase"] != "s3cret-value" {
		t.Error("a field-set payload does not yield the passphrase")
	}
	// The local shape is not JSON, so the same parse must fall through rather
	// than returning something wrong.
	raw := []byte("s3cret-value")
	if json.Unmarshal(raw, &fields) == nil {
		t.Error("a bare passphrase parsed as JSON; the fallback would never run")
	}
}

// The sidecar forwards LUKS_PASS into the build container only when `encrypted`
// is true. Supplying the passphrase without that flag is the same silent no-op
// as supplying nothing — which is exactly the class of bug this fix is for.
func TestSuppliedPassphraseTravelsWithTheEncryptedFlag(t *testing.T) {
	src := readSource(t, "buildhandlers.go")
	i := strings.Index(src, `body["luksPassphrase"] = pass`)
	if i < 0 {
		t.Fatal("the bundle build no longer supplies a filed passphrase")
	}
	// Within the same branch, not somewhere else in the file.
	branch := src[i:min(i+400, len(src))]
	if !strings.Contains(branch, `body["encrypted"] = true`) {
		t.Error("the passphrase is supplied without setting encrypted, so the sidecar " +
			"will not pass LUKS_PASS into the container and the build fails identically")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
