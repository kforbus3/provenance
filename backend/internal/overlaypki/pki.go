// Package overlaypki is an X.509 certificate authority (ECDSA P-256) for the FIPS
// OpenVPN / strongSwan overlay. OpenVPN authenticates peers with X.509 certificates,
// which Fleet's SSH CA (internal/ca) cannot issue — so this is a parallel PKI of the
// same key type and assurance. It is only used when FLEET_OVERLAY=openvpn; the
// default WireGuard overlay never touches it.
//
// The CA private key is generated and held in the backend, sealed at rest with the
// same passphrase as the SSH CA, and never leaves the process.
package overlaypki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
)

// caTTL is the overlay CA lifetime; client/server leaf certs are much shorter-lived.
const caTTL = 10 * 365 * 24 * time.Hour

// PKI issues and holds the overlay X.509 CA.
type PKI struct {
	store      *store.Store
	passphrase []byte

	mu        sync.RWMutex
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
}

// New constructs the overlay PKI bound to the store and at-rest passphrase.
func New(st *store.Store, cfg *config.Config) *PKI {
	return &PKI{store: st, passphrase: cfg.CAKeyPassphrase}
}

// EnsureCA loads the active overlay CA into memory, generating one on first use.
// Safe to call on every boot; a no-op once the CA exists.
func (p *PKI) EnsureCA(ctx context.Context) error {
	rec, err := p.store.GetActiveOverlayCA(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return p.generate(ctx)
	}
	if err != nil {
		return err
	}
	keyDER, err := secretbox.OpenBytes(p.passphrase, rec.KeyEnc)
	if err != nil {
		return fmt.Errorf("decrypt overlay CA key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("parse overlay CA key: %w", err)
	}
	block, _ := pem.Decode([]byte(rec.CertPEM))
	if block == nil {
		return errors.New("overlay CA cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse overlay CA cert: %w", err)
	}
	p.set(cert, key, []byte(rec.CertPEM))
	return nil
}

func (p *PKI) generate(ctx context.Context) error {
	cert, key, certPEM, err := GenerateCA()
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyEnc, err := secretbox.SealBytes(p.passphrase, keyDER)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(cert.Raw)
	if _, err := p.store.InsertOverlayCA(ctx, string(certPEM), keyEnc, hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	p.set(cert, key, certPEM)
	return nil
}

// GenerateCA creates a fresh ECDSA P-256 X.509 CA. Pure (no store), so it's unit-
// and integration-testable in isolation.
func GenerateCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "Fleet Overlay CA"},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(caTTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, certPEM, nil
}

func (p *PKI) set(cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM []byte) {
	p.mu.Lock()
	p.caCert, p.caKey, p.caCertPEM = cert, key, certPEM
	p.mu.Unlock()
}

// CACertPEM returns the CA certificate (PEM) that servers and clients trust.
func (p *PKI) CACertPEM() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.caCertPEM
}

// Fingerprint returns the CA cert's SHA-256 hex fingerprint (or "" if uninitialized).
func (p *PKI) Fingerprint() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.caCert == nil {
		return ""
	}
	sum := sha256.Sum256(p.caCert.Raw)
	return hex.EncodeToString(sum[:])
}

// IssueServer issues a server certificate (extKeyUsage serverAuth) for the OpenVPN
// server, with the given DNS-name and IP SANs.
func (p *PKI) IssueServer(cn string, dnsNames []string, ips []net.IP, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	c, k, _, err := p.issue(cn, dnsNames, ips, ttl, x509.ExtKeyUsageServerAuth)
	return c, k, err
}

// IssueClient issues a client certificate (extKeyUsage clientAuth) for a managed
// host. Returns the cert + key PEM and the decimal serial (for tracking).
func (p *PKI) IssueClient(cn string, ttl time.Duration) (certPEM, keyPEM []byte, serial string, err error) {
	return p.issue(cn, nil, nil, ttl, x509.ExtKeyUsageClientAuth)
}

func (p *PKI) issue(cn string, dnsNames []string, ips []net.IP, ttl time.Duration, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte, serial string, err error) {
	p.mu.RLock()
	caCert, caKey := p.caCert, p.caKey
	p.mu.RUnlock()
	if caCert == nil || caKey == nil {
		return nil, nil, "", errors.New("overlay CA not initialized")
	}
	return IssueFrom(caCert, caKey, cn, dnsNames, ips, ttl, eku)
}

// IssueFrom signs a leaf certificate (ECDSA P-256, SHA-256) with the given CA. Pure
// (no store), so the exact issuance path is integration-testable against a real
// OpenVPN server.
func IssueFrom(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, dnsNames []string, ips []net.IP, ttl time.Duration, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte, serial string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now()
	sn := randSerial()
	tmpl := &x509.Certificate{
		SerialNumber:       sn,
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          now.Add(-1 * time.Minute),
		NotAfter:           now.Add(ttl),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{eku},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, sn.String(), nil
}

// randSerial returns a random positive 128-bit certificate serial number.
func randSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// rand failure is fatal elsewhere; fall back to a time-based serial.
		return big.NewInt(time.Now().UnixNano())
	}
	return n.Add(n, big.NewInt(1))
}

// RecordClient tracks an issued client cert for a host (status / future CRL).
func (p *PKI) RecordClient(ctx context.Context, hostID uuid.UUID, cn, serial string, notAfter time.Time) error {
	return p.store.RecordOverlayClient(ctx, hostID, cn, serial, notAfter)
}
