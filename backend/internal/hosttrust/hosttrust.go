// Package hosttrust states, for one host, what its access path actually guarantees.
//
// Provenance offers several ways to make a host reachable, and they are not equally
// strong. The convenient ones exist for real reasons — a host on the jump host's LAN
// does not need an overlay, and a box that cannot trust the CA still needs a vaulted
// password — but nothing showed an operator which of those they had ended up with.
// The paths are described in the enrollment guide, chosen at enrollment, and then
// invisible: two hosts sit side by side in the list, one reachable only through a
// tunnel with a per-session certificate, the other on its management address with a
// standing password, and the UI says the same thing about both.
//
// That is how a convenient onboarding route becomes the production security posture
// without anybody deciding it should be.
//
// This derives the posture from the host record instead of storing it. A stored tier
// is a second copy of the truth and a second thing to go stale; a host whose auth
// method is edited later would keep a label describing how it used to work.
package hosttrust

// Tier names an access path, strongest first. The order is meaningful: Compare orders
// hosts by how much the path gives up.
type Tier string

const (
	// TierBrokeredOverlay is the design the product is built around: a per-session,
	// per-host certificate, and reachability only through the overlay.
	TierBrokeredOverlay Tier = "brokered-overlay"
	// TierBrokeredDirect keeps the ephemeral certificate but reaches the host on its
	// management address.
	TierBrokeredDirect Tier = "brokered-direct"
	// TierVaultedOverlay confines traffic to the overlay but authenticates with a
	// standing credential held in the vault.
	TierVaultedOverlay Tier = "vaulted-overlay"
	// TierVaultedDirect is both: a standing credential, over the management network.
	TierVaultedDirect Tier = "vaulted-direct"
)

// Posture is what a host's path gives and gives up. Every field is derived.
type Posture struct {
	Tier Tier `json:"tier"`
	// Credential: "ephemeral-certificate" or "standing-vaulted".
	Credential string `json:"credential"`
	// Reachability: "overlay" or "direct".
	Reachability string `json:"reachability"`

	// PerSessionCredential is true when each session authenticates to the HOST with
	// key material minted for it and discarded after. False for vaulted credentials:
	// the jump-host hop still uses the session certificate, but the final hop
	// presents a stored secret shared by every user and every session.
	PerSessionCredential bool `json:"perSessionCredential"`
	// RevocableByCertificate is true when ending access means revoking a certificate
	// serial into the KRL. False for vaulted credentials, where it means rotating a
	// secret that other sessions may still be holding.
	RevocableByCertificate bool `json:"revocableByCertificate"`
	// ConfinedToOverlay is true when the host has an overlay address, so strict
	// overlay mode can hold connections to the tunnel. A host without one can be
	// reached by anything that can route to its management address.
	ConfinedToOverlay bool `json:"confinedToOverlay"`

	// GivesUp names, in plain words, what this path does not provide. Empty for the
	// strongest tier. This is the field worth putting in front of a person.
	GivesUp []string `json:"givesUp,omitempty"`
}

// Assess derives a host's posture. protocol is "ssh" or "rdp"; authMethod is
// "prov_cert", "vault_password" or "vault_ssh_key"; overlayAddr is the host's overlay
// address, empty when it has none.
func Assess(authMethod, protocol, overlayAddr string) Posture {
	brokered := authMethod == "prov_cert"
	// RDP hosts always authenticate with a vaulted credential -- there is no such
	// thing as an SSH certificate for a Windows desktop session -- so the protocol
	// decides this regardless of what the auth method column says.
	if protocol == "rdp" {
		brokered = false
	}
	overlay := overlayAddr != ""

	p := Posture{
		PerSessionCredential:   brokered,
		RevocableByCertificate: brokered,
		ConfinedToOverlay:      overlay,
	}
	switch {
	case brokered && overlay:
		p.Tier, p.Credential, p.Reachability = TierBrokeredOverlay, "ephemeral-certificate", "overlay"
	case brokered:
		p.Tier, p.Credential, p.Reachability = TierBrokeredDirect, "ephemeral-certificate", "direct"
	case overlay:
		p.Tier, p.Credential, p.Reachability = TierVaultedOverlay, "standing-vaulted", "overlay"
	default:
		p.Tier, p.Credential, p.Reachability = TierVaultedDirect, "standing-vaulted", "direct"
	}

	if !brokered {
		p.GivesUp = append(p.GivesUp,
			"authenticates with a standing credential shared by every user and session, not one minted per session",
			"ending one person's access means rotating that credential, not revoking a certificate serial")
	}
	if !overlay {
		p.GivesUp = append(p.GivesUp,
			"reachable on its management address, so strict overlay mode cannot confine connections to a tunnel")
	}
	if protocol == "rdp" {
		p.GivesUp = append(p.GivesUp,
			"desktop sessions are recorded through guacd and encrypted when the session ends, not as they are written")
	}
	return p
}

// rank orders tiers strongest (0) to weakest.
func rank(t Tier) int {
	switch t {
	case TierBrokeredOverlay:
		return 0
	case TierBrokeredDirect:
		return 1
	case TierVaultedOverlay:
		return 2
	case TierVaultedDirect:
		return 3
	}
	return 4
}

// AtLeast reports whether t is at least as strong as floor.
func AtLeast(t, floor Tier) bool { return rank(t) <= rank(floor) }

// All returns every tier, strongest first — for reports that must account for each
// one rather than only the tiers that happen to be in use.
func All() []Tier {
	return []Tier{TierBrokeredOverlay, TierBrokeredDirect, TierVaultedOverlay, TierVaultedDirect}
}
