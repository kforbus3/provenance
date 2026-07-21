// Package auth implements password hashing, token issuance, session management,
// and the HTTP authentication layer.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Tuned for interactive logins; adjust for the deployment's
// hardware via these constants.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// pbkdf2Iterations is the PBKDF2-HMAC-SHA256 work factor for FIPS-mode password
// hashing (SP 800-132); 600k matches current OWASP guidance for PBKDF2-SHA256.
const pbkdf2Iterations = 600_000

// passwordFIPS selects PBKDF2 (FIPS) vs Argon2id for NEW hashes. Set once at boot
// from FLEET_FIPS_MODE; default false keeps Argon2id so non-FIPS installs are
// unchanged. VerifyPassword auto-detects the stored algorithm, so both verify
// regardless — enabling verify-then-upgrade-on-login during a FIPS migration.
var passwordFIPS bool

// SetPasswordFIPS selects the password KDF for subsequent hashes. Call once at boot.
func SetPasswordFIPS(on bool) { passwordFIPS = on }

// HashPassword returns an encoded hash string: PBKDF2-HMAC-SHA256 in FIPS mode,
// Argon2id otherwise (both PHC-style).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if passwordFIPS {
		key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, argonKeyLen)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s", pbkdf2Iterations,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(key)), nil
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash (Argon2id or
// PBKDF2), using a constant-time comparison.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) < 2 {
		return false, errors.New("invalid hash format")
	}
	switch parts[1] {
	case "argon2id":
		return verifyArgon2(password, parts)
	case "pbkdf2-sha256":
		return verifyPBKDF2(password, parts)
	default:
		return false, errors.New("invalid hash format")
	}
}

// PasswordNeedsRehash reports whether a stored hash uses a different KDF than the
// active profile — so the login path can transparently re-hash it (M5). In FIPS
// mode, an Argon2id hash needs upgrading to PBKDF2; otherwise nothing needs it.
func PasswordNeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) < 2 {
		return true
	}
	if passwordFIPS {
		return parts[1] != "pbkdf2-sha256"
	}
	return false
}

func verifyArgon2(password string, parts []string) (bool, error) {
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func verifyPBKDF2(password string, parts []string) (bool, error) {
	if len(parts) != 5 {
		return false, errors.New("invalid hash format")
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iter); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// PasswordPolicy defines complexity requirements.
type PasswordPolicy struct {
	MinLength     int  `json:"min_length"`
	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
	History       int  `json:"history"`
}

// DefaultPolicy is used when settings are unavailable.
var DefaultPolicy = PasswordPolicy{MinLength: 12, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true, History: 5}

// Validate checks a password against the policy, returning a descriptive error.
func (p PasswordPolicy) Validate(pw string) error {
	if len(pw) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters", p.MinLength)
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if p.RequireUpper && !hasUpper {
		return errors.New("password must contain an uppercase letter")
	}
	if p.RequireLower && !hasLower {
		return errors.New("password must contain a lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		return errors.New("password must contain a digit")
	}
	if p.RequireSymbol && !hasSymbol {
		return errors.New("password must contain a symbol")
	}
	return nil
}
