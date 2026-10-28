package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/config"
)

// grype's real output for questarr's pinned digest after its publisher deleted the
// build from ghcr.io (captured 2026-10-27). The registry's answer comes after the
// image reference and the request URL, about 350 characters in.
const deletedDigestErr = "[0008] ERROR failed to catalog: errors occurred attempting to resolve " +
	"'ghcr.io/doezer/questarr@sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78':\n" +
	"  - oci-registry: failed to get image descriptor from registry: GET " +
	"https://ghcr.io/v2/doezer/questarr/manifests/sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78: " +
	"MANIFEST_UNKNOWN: manifest unknown\n" +
	"  - oci-model: failed to fetch descriptor: GET " +
	"https://ghcr.io/v2/doezer/questarr/manifests/sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78: " +
	"MANIFEST_UNKNOWN: manifest unknown"

// The health page read "1 image(s) could not be scanned" and nothing else, and the
// stored error stopped at "manifests/sha256:" -- the reply was cut to 300
// characters before anything read it, so the reason never survived.
func TestADeletedImageIsNamedAsDeletedNotAsAFailedScan(t *testing.T) {
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": deletedDigestErr})
	}))
	t.Cleanup(scanner.Close)
	s := &Service{cfg: &config.Config{GrypeScannerURL: scanner.URL}}

	_, err := s.scanImage(context.Background(),
		"ghcr.io/doezer/questarr@sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78")
	var se *scanError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a scanError", err)
	}
	if !strings.HasPrefix(se.why, "no longer in its registry") {
		t.Errorf("why = %q, want it to say the image is gone from its registry", se.why)
	}
	// And it leads the stored text, which is cut at 500.
	if !strings.HasPrefix(err.Error(), "no longer in its registry") {
		t.Errorf("stored error does not lead with the reason: %q", err.Error())
	}
}

func TestUnscannableReasons(t *testing.T) {
	cases := []struct{ raw, want string }{
		{deletedDigestErr, "no longer in its registry"},
		{`GET https://registry-1.docker.io/v2/library/x/manifests/1.0: TOOMANYREQUESTS: retry-after: 548µs`, "the registry is rate limiting"},
		{`GET https://ghcr.io/v2/private/app/manifests/v1: UNAUTHORIZED: authentication required`, "the registry refused access"},
		// A digest is hex, and hex contains status numbers. "404" inside one is not
		// a 404; nor "401", nor "429".
		{"failed to catalog 'x@sha256:a404b401c429d403': connection reset by peer", "scan failed"},
	}
	for _, c := range cases {
		if got := unscannableReason(c.raw); !strings.HasPrefix(got, c.want) {
			t.Errorf("unscannableReason(%.60q…) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestShortRefKeepsTheNameAndEnoughOfTheDigest(t *testing.T) {
	got := shortRef("ghcr.io/doezer/questarr@sha256:9e179255fa24f2b553c81261d793d8edd1fc9f32cf029c9282dbe760a88b7b78")
	if got != "ghcr.io/doezer/questarr@sha256:9e179255fa24…" {
		t.Errorf("shortRef = %q", got)
	}
	if shortRef("nginx:1.31-alpine") != "nginx:1.31-alpine" {
		t.Error("a tag reference was altered")
	}
}
