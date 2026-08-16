package ssrf

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSafeClientDialRefusesLoopback proves the validating DialContext blocks a
// disallowed target at dial time — the DNS-rebinding TOCTOU protection — even
// when the caller has NOT pre-validated the URL. A loopback host must never be
// dialed.
func TestSafeClientDialRefusesLoopback(t *testing.T) {
	c := SafeClient(2 * time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:80/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("SafeClient dialed a loopback target; the validating dialer should have refused it")
	}
	if !strings.Contains(err.Error(), "disallowed") {
		t.Errorf("expected a disallowed-address error, got: %v", err)
	}
}

// TestValidateURLBlocksMetadataAndLoopback covers the early-rejection path callers
// use before issuing a request.
func TestValidateURLBlocksMetadataAndLoopback(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/",             // loopback
		"http://169.254.169.254/latest", // cloud metadata (link-local)
		"http://[::1]:8080/",            // IPv6 loopback
		"ftp://example.com/",            // wrong scheme
	} {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("ValidateURL(%q) allowed a disallowed target", raw)
		}
	}
	// A private-network integration target is allowed on purpose (admins point
	// these at internal services).
	if err := ValidateURL("http://10.0.0.5:9200/"); err != nil {
		t.Errorf("ValidateURL rejected a legitimate private-network target: %v", err)
	}
}
