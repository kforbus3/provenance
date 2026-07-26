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

// mfaKeys returns the AES-256 keys that protect TOTP secrets at rest, ordered
// primary-first. EncryptSecret always uses the primary; DecryptSecret tries each in
// turn so that adopting a dedicated key (or migrating FIPS derivations) never strands an
// existing secret.
//
//   - If FLEET_MFA_ENCRYPTION_KEY is set, the primary is HKDF(that key) — decoupled from
//     JWTSecret, so the JWT secret can rotate without bricking stored MFA secrets. The
//     JWT-derived key(s) are kept as fallbacks so pre-existing secrets still decrypt.
//   - Otherwise the primary is the JWT-derived key (HKDF in FIPS, else legacy SHA-256),
//     preserving the previous behavior exactly.
func (s *Service) mfaKeys() [][32]byte {
	var keys [][32]byte
	add := func(k [32]byte) { keys = append(keys, k) }

	// Dedicated key first, when configured.
	if len(s.cfg.MFAEncryptionKey) > 0 {
		if k, err := hkdf.Key(sha256.New, s.cfg.MFAEncryptionKey, []byte("fleet-mfa"), "totp-at-rest-v2", 32); err == nil {
			var out [32]byte
			copy(out[:], k)
			add(out)
		}
	}
	// JWT-derived HKDF key (FIPS primary / non-FIPS fallback after a dedicated key).
	if k, err := hkdf.Key(sha256.New, s.cfg.JWTSecret, []byte("fleet-mfa"), "totp-at-rest-v1", 32); err == nil {
		var out [32]byte
		copy(out[:], k)
		add(out)
	}
	// Legacy bare-SHA-256 JWT derivation (original non-FIPS scheme) — kept last so
	// secrets written before HKDF still decrypt.
	add(sha256.Sum256(append([]byte("mfa:"), s.cfg.JWTSecret...)))
	return keys
}

// EncryptSecret encrypts a TOTP secret for storage using the primary MFA key.
func (s *Service) EncryptSecret(plain string) ([]byte, error) {
	key := s.mfaKeys()[0]
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

// DecryptSecret reverses EncryptSecret, trying each candidate key so a key migration
// (JWT-derived → dedicated) doesn't strand previously-encrypted secrets.
func (s *Service) DecryptSecret(enc []byte) (string, error) {
	var lastErr error = errors.New("no mfa key available")
	for _, key := range s.mfaKeys() {
		gcm, err := newGCM(key)
		if err != nil {
			lastErr = err
			continue
		}
		if len(enc) < gcm.NonceSize() {
			return "", errors.New("ciphertext too short")
		}
		nonce, ct := enc[:gcm.NonceSize()], enc[gcm.NonceSize():]
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err == nil {
			return string(plain), nil
		}
		lastErr = err
	}
	return "", lastErr
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
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
