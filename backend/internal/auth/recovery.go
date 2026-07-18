package auth

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/google/uuid"
)

// recoveryCodeCount is how many one-time codes a generation produces.
const recoveryCodeCount = 10

// recoveryAlphabet is a 32-symbol set with visually ambiguous characters
// (0/O, 1/I/L) removed. 32 divides 256 evenly, so drawing bytes mod 32 is
// bias-free. 12 symbols give ~60 bits of entropy per code.
var recoveryAlphabet = []byte("ABCDEFGHJKMNPQRSTUVWXYZ23456789")

// newRecoveryCode returns a formatted one-time recovery code (xxxx-xxxx-xxxx) and
// its storage hash.
func newRecoveryCode() (code, hash string, err error) {
	const n = 12
	buf := make([]byte, n)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	b := make([]byte, n)
	for i := range buf {
		b[i] = recoveryAlphabet[int(buf[i])%len(recoveryAlphabet)]
	}
	code = string(b[0:4]) + "-" + string(b[4:8]) + "-" + string(b[8:12])
	hash = HashToken(normalizeRecoveryCode(code))
	return code, hash, nil
}

// normalizeRecoveryCode strips formatting (dashes, spaces, case) so a user can
// type a code with or without its dashes.
func normalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// GenerateRecoveryCodes creates a fresh set of one-time recovery codes for the
// user (invalidating any previous set) and returns the plaintext codes, which are
// shown to the user exactly once.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		code, hash, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// ConsumeRecoveryCode verifies and consumes a recovery code for the user during
// the MFA step. Returns true only if an unused matching code existed.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, input string) bool {
	norm := normalizeRecoveryCode(input)
	if norm == "" {
		return false
	}
	ok, err := s.store.ConsumeRecoveryCode(ctx, userID, HashToken(norm))
	return err == nil && ok
}
