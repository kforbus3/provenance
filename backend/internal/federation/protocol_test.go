package federation

import "testing"

// TestEffectiveProtocol locks the join-handshake protocol negotiation, including the
// legacy-compatibility path: a pre-versioning site sends protocolVersion 0 but a
// non-empty apiVersion "v1", and the hub must treat that as protocol 1 rather than
// rejecting it as too old. A modern site sends its real protocolVersion, which wins.
func TestEffectiveProtocol(t *testing.T) {
	cases := []struct {
		name string
		req  joinReq
		want int
	}{
		{"modern site", joinReq{ProtocolVersion: 2, APIVersion: "v1"}, 2},
		{"legacy v1 apiVersion", joinReq{ProtocolVersion: 0, APIVersion: "v1"}, 1},
		{"legacy empty apiVersion", joinReq{ProtocolVersion: 0, APIVersion: ""}, 1},
		{"unknown legacy apiVersion", joinReq{ProtocolVersion: 0, APIVersion: "v0"}, 0},
		{"explicit v1", joinReq{ProtocolVersion: 1}, 1},
	}
	for _, c := range cases {
		if got := effectiveProtocol(c.req); got != c.want {
			t.Errorf("%s: effectiveProtocol = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestProtocolConstants guards the invariant that this build never advertises a
// minimum it can't itself speak — a bump to MinSupportedProtocol above ProtocolVersion
// would make the hub reject its own sites.
func TestProtocolConstants(t *testing.T) {
	if MinSupportedProtocol > ProtocolVersion {
		t.Fatalf("MinSupportedProtocol (%d) must not exceed ProtocolVersion (%d)", MinSupportedProtocol, ProtocolVersion)
	}
}
