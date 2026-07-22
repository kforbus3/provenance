package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestSiteRotateMessage_SignVerify locks the site-key-rotation wire contract: the
// site signs siteRotateMessage(siteID,newPub,nonce) with its CURRENT key and the
// hub verifies with the same construction. Any drift in the byte layout between the
// two sides would break rotation, so this guards it deterministically.
func TestSiteRotateMessage_SignVerify(t *testing.T) {
	curPub, curPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	const siteID = "0ca66f27-139a-4f4f-b4d7-1bb29ba9e748"
	const nonce = "test-nonce-123"

	msg := siteRotateMessage(siteID, newPub, nonce)
	sig := ed25519.Sign(curPriv, msg)

	if !ed25519.Verify(curPub, siteRotateMessage(siteID, newPub, nonce), sig) {
		t.Fatal("valid signature failed to verify")
	}

	// The message must be deterministic for the same inputs.
	if string(msg) != string(siteRotateMessage(siteID, newPub, nonce)) {
		t.Fatal("siteRotateMessage is not deterministic")
	}

	// Any changed field must invalidate the signature (binding).
	otherNew, _, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string][]byte{
		"different new key": siteRotateMessage(siteID, otherNew, nonce),
		"different nonce":   siteRotateMessage(siteID, newPub, "other-nonce"),
		"different site":    siteRotateMessage("11111111-1111-1111-1111-111111111111", newPub, nonce),
	}
	for name, tampered := range cases {
		if ed25519.Verify(curPub, tampered, sig) {
			t.Errorf("%s: signature verified against a different message (not bound)", name)
		}
	}
}
