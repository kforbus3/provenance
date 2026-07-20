package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/fleet-terminal/backend/internal/models"
)

// totpAlg is the HMAC hash for TOTP, set once at boot from the crypto profile:
// SHA-256 under FIPS, SHA-1 otherwise. All of a deployment's TOTP secrets use one
// algorithm (a FIPS migration re-enrolls users), so a package-level value is correct.
var totpAlg = otp.AlgorithmSHA1

// SetTOTPAlgorithm selects the TOTP HMAC hash. Call once at boot.
func SetTOTPAlgorithm(a otp.Algorithm) { totpAlg = a }

// GenerateTOTP creates a new TOTP secret for an account and returns the base32
// secret plus the otpauth:// URL (rendered as a QR code by the client).
func GenerateTOTP(issuer, account string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account, Digits: otp.DigitsSix, Algorithm: totpAlg,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP checks a 6-digit code against a base32 secret, allowing a small
// clock skew window.
func ValidateTOTP(secret, code string) bool {
	ok, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: totpAlg,
	})
	return err == nil && ok
}

// --- secret encryption at rest (AES-256-GCM, key derived from the JWT secret) ---

// mfaKey derives the AES key that protects TOTP secrets at rest. In FIPS mode it
// uses HKDF-SHA256 (an approved KDF); otherwise it keeps the original bare-SHA-256
// derivation so existing non-FIPS secrets keep decrypting. A fresh FIPS deploy has
// no prior secrets, so there is nothing to migrate.
func (s *Service) mfaKey() [32]byte {
	var out [32]byte
	if s.cfg.FIPSMode {
		k, err := hkdf.Key(sha256.New, s.cfg.JWTSecret, []byte("fleet-mfa"), "totp-at-rest-v1", 32)
		if err == nil {
			copy(out[:], k)
			return out
		}
		// Fall through to the legacy derivation only if HKDF somehow fails.
	}
	return sha256.Sum256(append([]byte("mfa:"), s.cfg.JWTSecret...))
}

// EncryptSecret encrypts a TOTP secret for storage.
func (s *Service) EncryptSecret(plain string) ([]byte, error) {
	key := s.mfaKey()
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

// DecryptSecret reverses EncryptSecret.
func (s *Service) DecryptSecret(enc []byte) (string, error) {
	key := s.mfaKey()
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	if len(enc) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := enc[:gcm.NonceSize()], enc[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// --- MFA challenge token (issued after password step, before session) ---

type mfaClaims struct {
	UserID  uuid.UUID `json:"uid"`
	Purpose string    `json:"pur"`
	jwt.RegisteredClaims
}

// IssueMFAChallenge mints a short-lived token proving the password step passed.
func (s *Service) IssueMFAChallenge(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := mfaClaims{
		UserID: userID, Purpose: "mfa",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.cfg.JWTSecret)
}

// ParseMFAChallenge validates a challenge token and returns the user id.
func (s *Service) ParseMFAChallenge(token string) (uuid.UUID, error) {
	claims := &mfaClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.cfg.JWTSecret, nil
	})
	if err != nil || !t.Valid || claims.Purpose != "mfa" {
		return uuid.Nil, errors.New("invalid mfa challenge")
	}
	return claims.UserID, nil
}

// IssueMFASetupToken mints a short-lived token authorizing a user with no
// confirmed factor to enroll one as a precondition of completing login. It is
// NOT a session: it only unlocks the forced-enrollment endpoints.
func (s *Service) IssueMFASetupToken(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := mfaClaims{
		UserID: userID, Purpose: "mfa_setup",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.cfg.JWTSecret)
}

// ParseMFASetupToken validates a setup token and returns the user id.
func (s *Service) ParseMFASetupToken(token string) (uuid.UUID, error) {
	claims := &mfaClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.cfg.JWTSecret, nil
	})
	if err != nil || !t.Valid || claims.Purpose != "mfa_setup" {
		return uuid.Nil, errors.New("invalid mfa setup token")
	}
	return claims.UserID, nil
}

// MFARequiredFor reports whether MFA is mandatory for a user — either the global
// require_mfa setting is on, or the user's own require_mfa flag is set. Super
// admins are included so the strongest accounts cannot opt out when required.
func (s *Service) MFARequiredFor(ctx context.Context, u *models.User) bool {
	if u != nil && u.RequireMFA {
		return true
	}
	return s.store.MFAGloballyRequired(ctx)
}

// VerifyUserTOTP checks a code against all of the user's confirmed TOTP secrets.
func (s *Service) VerifyUserTOTP(secrets [][]byte, code string) bool {
	for _, enc := range secrets {
		if sec, err := s.DecryptSecret(enc); err == nil && ValidateTOTP(sec, code) {
			return true
		}
	}
	return false
}

// VerifyUserTOTPNoReplay validates a code and rejects one whose timestep was
// already used (replay within the skew window). It is deliberately FAIL-OPEN: it
// only ever returns false for an invalid code or a *provably* reused step; if the
// step can't be determined or the store errors, a valid code is still accepted,
// so a legitimate user is never locked out by this check.
func (s *Service) VerifyUserTOTPNoReplay(ctx context.Context, userID uuid.UUID, secrets [][]byte, code string) bool {
	for _, enc := range secrets {
		sec, err := s.DecryptSecret(enc)
		if err != nil || !ValidateTOTP(sec, code) {
			continue
		}
		step, ok := matchTOTPStep(sec, code)
		if !ok {
			return true // valid but step indeterminate → accept (fail-open)
		}
		last, err := s.store.TOTPLastStep(ctx, userID)
		if err != nil {
			return true // DB error → don't block a valid code
		}
		if step <= last {
			return false // this or an earlier step was already used → replay
		}
		_ = s.store.SetTOTPLastStep(ctx, userID, step)
		return true
	}
	return false
}

// matchTOTPStep returns the timestep whose generated code equals code, within the
// same skew window ValidateTOTP allows. ok is false if none matches.
func matchTOTPStep(secret, code string) (int64, bool) {
	const period, skew = int64(30), int64(1)
	cur := time.Now().Unix() / period
	for d := -skew; d <= skew; d++ {
		step := cur + d
		gen, err := totp.GenerateCodeCustom(secret, time.Unix(step*period, 0), totp.ValidateOpts{
			Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: totpAlg,
		})
		if err == nil && subtle.ConstantTimeCompare([]byte(gen), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
