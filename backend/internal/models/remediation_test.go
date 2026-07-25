package models

import "testing"

func TestClassifyRemediation(t *testing.T) {
	obsolete := map[string]bool{"libdns-export1104": true}
	pending := map[string]bool{"openssl": true}

	cases := []struct {
		name         string
		f            VulnFinding
		updatesKnown bool
		want         string
	}{
		{
			name: "orphaned package -> remove, even with a fixed version",
			f:    VulnFinding{Package: "libdns-export1104", FixedVersion: "1:9.16.15-1"},
			want: RemediationRemove, updatesKnown: true,
		},
		{
			name: "package in pending updates -> update",
			f:    VulnFinding{Package: "openssl", FixedVersion: "3.0.0"},
			want: RemediationUpdate, updatesKnown: true,
		},
		{
			name: "orphaned wins over pending if somehow in both",
			f:    VulnFinding{Package: "libdns-export1104"},
			want: RemediationRemove, updatesKnown: true,
		},
		{
			name: "has fix, not obsolete, not pending, updates checked -> unavailable (no-DSA/held/OS upgrade)",
			f:    VulnFinding{Package: "bash", FixedVersion: "5.2-1"},
			want: RemediationUnavailable, updatesKnown: true,
		},
		{
			name: "has fix but updates never checked -> unknown (avoid false 'no fix')",
			f:    VulnFinding{Package: "bash", FixedVersion: "5.2-1"},
			want: "", updatesKnown: false,
		},
		{
			name: "no fix version, not obsolete -> unknown",
			f:    VulnFinding{Package: "bash"},
			want: "", updatesKnown: true,
		},
	}
	for _, c := range cases {
		if got := ClassifyRemediation(c.f, obsolete, pending, c.updatesKnown); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
