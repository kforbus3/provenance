package auth

import (
	"strings"
	"testing"
)

func TestNewAPIToken(t *testing.T) {
	tok, hash, prefix, err := NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, APITokenPrefix) {
		t.Fatalf("token %q missing prefix %q", tok, APITokenPrefix)
	}
	if HashToken(tok) != hash {
		t.Fatal("returned hash does not match HashToken(token)")
	}
	if len(prefix) != 12 || !strings.HasPrefix(tok, prefix) {
		t.Fatalf("display prefix %q is not the first 12 chars of the token", prefix)
	}
	// The hash must not be derivable-looking from the prefix, and tokens must be unique.
	tok2, hash2, _, _ := NewAPIToken()
	if tok == tok2 || hash == hash2 {
		t.Fatal("consecutive tokens are not unique")
	}
}
