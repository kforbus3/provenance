package federation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// randToken returns a URL-safe random token string of n bytes of entropy.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the SHA-256 of a token string, for at-rest storage/lookup.
func hashToken(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// siteRotateMessage is the exact byte string a site signs with its CURRENT
// private key to authorize rotating to newPub. Binding siteID + nonce makes the
// signature specific to this site and single-use. Both sides construct it
// identically so the hub can verify with the site's active public key.
func siteRotateMessage(siteID string, newPub []byte, nonce string) []byte {
	h := sha256.New()
	h.Write([]byte("fleet-fed-site-rotate\x00"))
	h.Write([]byte(siteID))
	h.Write([]byte{0})
	h.Write(newPub)
	h.Write([]byte{0})
	h.Write([]byte(nonce))
	return h.Sum(nil)
}
