package auth

import (
	"strings"
	"testing"
)

func TestNewRecoveryCodeFormatAndHash(t *testing.T) {
	code, hash, err := newRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	// Format xxxx-xxxx-xxxx.
	parts := strings.Split(code, "-")
	if len(parts) != 3 {
		t.Fatalf("expected 3 groups, got %q", code)
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Fatalf("group %q is not 4 chars", p)
		}
	}
	// The hash is of the normalized (dash-stripped) code, so a user can type it
	// with or without dashes.
	if hash != HashToken(normalizeRecoveryCode(code)) {
		t.Fatal("hash is not of the normalized code")
	}
	if HashToken(normalizeRecoveryCode(strings.ToLower(strings.ReplaceAll(code, "-", " ")))) != hash {
		t.Fatal("normalization is not tolerant of spacing/case")
	}
}

func TestRecoveryCodesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, _, err := newRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatalf("duplicate code %q", code)
		}
		seen[code] = true
	}
}

func TestNormalizeRejectsEmpty(t *testing.T) {
	if normalizeRecoveryCode("---") != "" {
		t.Fatal("expected empty normalization for punctuation-only input")
	}
}
