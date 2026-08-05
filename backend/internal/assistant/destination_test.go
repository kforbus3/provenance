package assistant

import (
	"context"
	"testing"
)

// The settings page promises data never leaves your network. Whether that is
// true depends entirely on the URL an administrator typed, so the check has to
// agree with the promise.
func TestClassifyDestination(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		url      string
		external bool
		why      string
	}{
		{"http://localhost:11434", false, "loopback by name"},
		{"http://127.0.0.1:11434", false, "loopback"},
		{"http://[::1]:11434", false, "loopback v6"},
		{"http://10.10.0.50:11434", false, "RFC 1918"},
		{"http://192.168.1.10:11434", false, "RFC 1918"},
		{"http://172.16.0.9:11434", false, "RFC 1918"},
		{"http://[fd00::1]:11434", false, "unique local"},
		{"http://100.64.0.3:11434", false, "shared address space / overlay"},
		{"http://93.184.216.34:11434", true, "a public address"},
		{"http://[2606:4700:4700::1111]:11434", true, "a public v6 address"},
		{"", false, "nothing configured is not egress"},
		{"://nonsense", false, "an unparseable URL is not evidence of egress"},
		// A hostname is deliberately not asserted here: resolving one makes the
		// result depend on the DNS available to whoever runs the test. The
		// resolution path is exercised in production by Status; what this test
		// pins down is the classification, which is the part that decides
		// whether Fleet claims the data stayed on the network.
	} {
		got := classifyDestination(ctx, tc.url)
		if got.External != tc.external {
			t.Errorf("classifyDestination(%q).External = %v, want %v (%s)",
				tc.url, got.External, tc.external, tc.why)
		}
	}
}
