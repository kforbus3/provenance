package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the JWT access-token payload.
type Claims struct {
	UserID    uuid.UUID `json:"uid"`
	SessionID uuid.UUID `json:"sid"`
	Username  string    `json:"usr"`
	jwt.RegisteredClaims
}

// IssueAccessToken signs a short-lived access token for a session.
func IssueAccessToken(secret []byte, userID, sessionID uuid.UUID, username string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		Username:  username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// ParseAccessToken validates a token and returns its claims.
func ParseAccessToken(secret []byte, tokenStr string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// NewRefreshToken returns a high-entropy opaque refresh token and its storage hash.
// Only the hash is persisted, so a database leak cannot reconstruct live tokens.
func NewRefreshToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	hash = HashToken(token)
	return token, hash, nil
}

// APITokenPrefix marks a service-account API token in the Authorization header,
// so RequireAuth can route it to token auth instead of JWT parsing. JWTs are
// base64 "eyJ..." and never collide with this.
const APITokenPrefix = "flt_"

// NewAPIToken returns a service-account API token: the full secret (shown once at
// creation), its storage hash (only this is persisted), and a short non-secret
// prefix for later display in the UI.
func NewAPIToken() (token, hash, prefix string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", err
	}
	token = APITokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	hash = HashToken(token)
	prefix = token
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return token, hash, prefix, nil
}

// HashToken returns the hex SHA-256 of an opaque token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewCSRFToken returns a random CSRF token (double-submit cookie pattern).
func NewCSRFToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
