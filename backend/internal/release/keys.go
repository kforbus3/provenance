package release

import "crypto/ed25519"

// embeddedTrustKeys is the base64 Ed25519 release public key(s) baked into the binary
// at build time via -ldflags "-X github.com/kforbus3/Moorgate/backend/internal/release.embeddedTrustKeys=<b64[,b64...]>".
// It is empty in a plain `go build`; a real release build stamps the publisher's key.
// When empty and no runtime keys are configured, TrustedKeys returns nothing and
// verification fails closed (no upgrade can be applied) — the intended safe default.
var embeddedTrustKeys = ""

// TrustedKeys returns the release public keys to verify bundles against: the
// build-embedded key(s) plus any supplied at runtime (extra is a comma/space list,
// typically from FLEET_RELEASE_TRUST_KEYS — used for key rotation or bringing your own
// key to a source build). Deduplication isn't necessary; Verify tries each in turn.
func TrustedKeys(extra string) ([]ed25519.PublicKey, error) {
	keys, err := ParsePublicKeys(embeddedTrustKeys)
	if err != nil {
		return nil, err
	}
	more, err := ParsePublicKeys(extra)
	if err != nil {
		return nil, err
	}
	return append(keys, more...), nil
}
