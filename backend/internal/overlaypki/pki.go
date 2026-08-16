// Package overlaypki is an X.509 certificate authority (ECDSA P-256) for the FIPS
// OpenVPN overlay. OpenVPN authenticates peers with X.509 certificates,
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

	"github.com/kforbus3/Moorgate/backend/internal/config"
	"github.com/kforbus3/Moorgate/backend/internal/secretbox"
	"github.com/kforbus3/Moorgate/backend/internal/store"
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

// ResealCA re-seals the overlay CA private key to the active KDF profile if it needs
// it (only relevant if the CA was created outside FIPS then FIPS was enabled).
// Returns whether it changed. Used by the FIPS migration sweep.
func (p *PKI) ResealCA(ctx context.Context) (bool, error) {
	rec, err := p.store.GetActiveOverlayCA(ctx)
	if err != nil {
		return false, err
	}
	newEnc, changed, err := secretbox.ResealBytes(p.passphrase, rec.KeyEnc)
	if err != nil || !changed {
		return false, err
	}
	if err := p.store.UpdateOverlayCAKeyEnc(ctx, rec.ID, newEnc); err != nil {
		return false, err
	}
	return true, nil
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

// crlValidity is how long a generated CRL claims to be current.
//
// It is deliberately long. OpenVPN refuses every connection once the CRL it was
// given has passed its nextUpdate — so a short validity turns "nobody enrolled a
// host for a while" into a fleet-wide outage, which is a far worse failure than a
// stale revocation list. Freshness here comes from regenerating and redistributing
// on every revocation, not from expiry: the CA, the server and the list are all
// Fleet-managed and the list is pushed the moment it changes.
const crlValidity = 10 * 365 * 24 * time.Hour

// RevokeHostClients revokes every unexpired client certificate issued to a host and
// returns how many were revoked.
//
// Call it BEFORE the host row is deleted: overlay_clients cascades on host delete, so
// afterwards there is nothing left to say which serial belonged to it. The revocation
// itself is recorded in overlay_revocations, which has no host reference and outlives
// the host — see 0073_overlay_revocations.sql.
func (p *PKI) RevokeHostClients(ctx context.Context, hostID uuid.UUID, reason string) (int, error) {
	certs, err := p.store.OverlayClientsForHost(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("list overlay client certs: %w", err)
	}
	if len(certs) == 0 {
		return 0, nil
	}
	if err := p.store.RevokeOverlayClients(ctx, certs, reason); err != nil {
		return 0, fmt.Errorf("record overlay revocations: %w", err)
	}
	return len(certs), nil
}

// CRLPEM builds the current certificate revocation list, signed by the overlay CA.
//
// An empty list is a valid, signed CRL and is what a fleet with nothing revoked gets.
// That matters: the OpenVPN server config carries `crl-verify`, and OpenVPN refuses
// to start if that file is missing — so there must always be a CRL to write, from the
// very first enrollment.
func (p *PKI) CRLPEM(ctx context.Context) ([]byte, error) {
	if err := p.EnsureCA(ctx); err != nil {
		return nil, err
	}
	p.mu.RLock()
	caCert, caKey := p.caCert, p.caKey
	p.mu.RUnlock()
	if caCert == nil || caKey == nil {
		return nil, errors.New("overlay CA unavailable")
	}

	// Expired entries are dropped: the server refuses such a certificate on its own
	// dates, so carrying it only grows the list every host has to download.
	_, _ = p.store.PruneExpiredOverlayRevocations(ctx)
	revoked, err := p.store.RevokedOverlaySerials(ctx)
	if err != nil {
		return nil, fmt.Errorf("list overlay revocations: %w", err)
	}

	now := time.Now()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		serial, ok := new(big.Int).SetString(r.Serial, 10)
		if !ok {
			// A serial we cannot parse cannot be revoked, and silently dropping it
			// would leave a certificate live with nothing to show for it.
			return nil, fmt.Errorf("overlay revocation has an unparseable serial %q (cn %q)", r.Serial, r.CommonName)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: now,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		// A monotonic-enough CRL number; consumers only require it to change.
		Number:                    randSerial(),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign overlay CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
