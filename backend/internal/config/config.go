// Package config loads and validates runtime configuration from the environment.
//
// All configuration is sourced from environment variables so the same binary
// runs identically across local Docker, Kubernetes, and systemd deployments.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved application configuration.
type Config struct {
	// Server
	HTTPAddr        string        // e.g. ":8080"
	PublicURL       string        // external base URL, used for cookies/WebAuthn
	ShutdownTimeout time.Duration

	// Database
	DatabaseURL     string
	DBMaxConns      int32
	DBMinConns      int32
	MigrateOnStart  bool

	// Redis (jobs/cache). Optional; if empty an in-process scheduler is used.
	RedisURL string

	// Auth / crypto
	JWTSecret         []byte        // HMAC secret for access tokens
	AccessTokenTTL    time.Duration // short-lived
	RefreshTokenTTL   time.Duration // long-lived rotating
	SessionIdleTTL    time.Duration
	SessionAbsoluteTTL time.Duration // hard cap on session age (0 = unlimited)
	CookieDomain      string
	CookieSecure      bool
	CSRFSecret        []byte

	// Per-IP rate limiting (0 disables). General applies to the whole API; Auth
	// is a stricter limit for the unauthenticated auth/bootstrap endpoints. Both
	// key on the client IP, resolved via RealIP (trust X-Forwarded-For only when
	// behind a reverse proxy that sets it — keep the app off the public internet
	// directly).
	RateLimitPerMin     int
	RateLimitBurst      int
	AuthRateLimitPerMin int
	AuthRateLimitBurst  int

	// WebAuthn / passkeys relying-party settings
	WebAuthnRPID     string   // relying party id (registrable domain), e.g. "localhost"
	WebAuthnRPName   string   // human-readable RP name
	WebAuthnOrigins  []string // allowed origins, e.g. http://localhost:5173

	// SSH Certificate Authority
	CAKeyPassphrase []byte        // encrypts CA private key at rest
	UserCertTTL     time.Duration // ephemeral user certificate lifetime (7d)
	CertRenewBefore time.Duration // renew this long before expiry (~24h)
	HostCertTTL     time.Duration

	// Jump host (SSH gateway egress point)
	JumpHost           string // host:port of the jump host
	JumpUser           string
	JumpKnownHostsFile string

	// WireGuard overlay (used by host enrollment to provision tunnels)
	WGInterface    string // e.g. "wg0"
	WGSubnet       string // CIDR of the overlay, e.g. "10.100.0.0/24"
	WGJumpIP       string // jump host's address on the overlay
	WGJumpEndpoint string // endpoint managed hosts dial to reach the jump, host:port
	WGPort         int    // WireGuard listen port on managed hosts

	// Session recordings storage
	RecordingDir string

	// OpenSCAP scan report storage
	ScanDir     string
	ScanTimeout time.Duration // max duration of a scan/remediation (oscap can be slow)

	// SCAP content cache (datastreams the backend provisions to hosts whose OS
	// is newer than their packaged content). Empty disables auto-provisioning.
	ScapContentDir     string
	ScapContentVersion string // ComplianceAsCode release tag; empty = latest

	// Ansible runner sidecar base URL (e.g. http://ansible-runner:8000). The
	// backend delegates playbook validation/lint (and, later, execution) to it.
	// Empty disables the Ansible playbook feature's runner-backed operations.
	AnsibleRunnerURL string

	// Encrypted database backups: destination directory and the passphrase used
	// to encrypt them (openssl AES-256-CBC, PBKDF2). The passphrase falls back to
	// the CA passphrase if unset; set a distinct one to decouple the two.
	BackupDir        string
	BackupPassphrase string

	// SFTP upload size cap in bytes (0 = unlimited).
	MaxUploadBytes int64

	// Observability
	LogLevel     string
	LogFormat    string // "json" or "text"
	OTLPEndpoint string // optional OTLP/gRPC tracing endpoint
	TracingOn    bool

	// Bootstrap
	AllowBootstrap bool

	Environment string // "development" | "production"
}

// Load reads configuration from the environment, applies defaults, and validates.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:           env("FLEET_HTTP_ADDR", ":8080"),
		PublicURL:          env("FLEET_PUBLIC_URL", "https://localhost:8443"),
		ShutdownTimeout:    envDuration("FLEET_SHUTDOWN_TIMEOUT", 20*time.Second),
		DatabaseURL:        env("FLEET_DATABASE_URL", "postgres://fleet:fleet@postgres:5432/fleet?sslmode=disable"),
		DBMaxConns:         int32(envInt("FLEET_DB_MAX_CONNS", 20)),
		DBMinConns:         int32(envInt("FLEET_DB_MIN_CONNS", 2)),
		MigrateOnStart:     envBool("FLEET_MIGRATE_ON_START", true),
		RedisURL:           env("FLEET_REDIS_URL", "redis://redis:6379/0"),
		AccessTokenTTL:     envDuration("FLEET_ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:    envDuration("FLEET_REFRESH_TOKEN_TTL", 720*time.Hour),
		SessionIdleTTL:     envDuration("FLEET_SESSION_IDLE_TTL", 30*time.Minute),
		SessionAbsoluteTTL: envDuration("FLEET_SESSION_ABSOLUTE_TTL", 12*time.Hour),
		CookieDomain:       env("FLEET_COOKIE_DOMAIN", ""),
		CookieSecure:       envBool("FLEET_COOKIE_SECURE", true),
		RateLimitPerMin:     envInt("FLEET_RATE_LIMIT_PER_MIN", 600),
		RateLimitBurst:      envInt("FLEET_RATE_LIMIT_BURST", 120),
		AuthRateLimitPerMin: envInt("FLEET_AUTH_RATE_LIMIT_PER_MIN", 20),
		AuthRateLimitBurst:  envInt("FLEET_AUTH_RATE_LIMIT_BURST", 10),
		UserCertTTL:        envDuration("FLEET_USER_CERT_TTL", 7*24*time.Hour),
		CertRenewBefore:    envDuration("FLEET_CERT_RENEW_BEFORE", 24*time.Hour),
		HostCertTTL:        envDuration("FLEET_HOST_CERT_TTL", 365*24*time.Hour),
		JumpHost:           env("FLEET_JUMP_HOST", "jumphost:22"),
		JumpUser:           env("FLEET_JUMP_USER", "fleet"),
		JumpKnownHostsFile: env("FLEET_JUMP_KNOWN_HOSTS", ""),
		WGInterface:        env("FLEET_WG_INTERFACE", "wg0"),
		WGSubnet:           env("FLEET_WG_SUBNET", "10.100.0.0/24"),
		WGJumpIP:           env("FLEET_WG_JUMP_IP", "10.100.0.1"),
		WGJumpEndpoint:     env("FLEET_WG_JUMP_ENDPOINT", "jumphost:51820"),
		WGPort:             envInt("FLEET_WG_PORT", 51820),
		RecordingDir:       env("FLEET_RECORDING_DIR", "/var/lib/fleet/recordings"),
		ScanDir:            env("FLEET_SCAN_DIR", "/var/lib/fleet/scans"),
		ScanTimeout:        envDuration("FLEET_SCAN_TIMEOUT", 60*time.Minute),
		ScapContentDir:     env("FLEET_SCAP_CONTENT_DIR", "/var/lib/fleet/scap-content"),
		ScapContentVersion: env("FLEET_SCAP_CONTENT_VERSION", ""),
		AnsibleRunnerURL:   env("FLEET_ANSIBLE_RUNNER_URL", "http://ansible-runner:8000"),
		BackupDir:          env("FLEET_BACKUP_DIR", "/var/lib/fleet/backups"),
		BackupPassphrase:   env("FLEET_BACKUP_PASSPHRASE", ""),
		MaxUploadBytes:     envInt64("FLEET_MAX_UPLOAD_BYTES", 5<<30), // 5 GiB default
		LogLevel:           env("FLEET_LOG_LEVEL", "info"),
		LogFormat:          env("FLEET_LOG_FORMAT", "json"),
		OTLPEndpoint:       env("FLEET_OTLP_ENDPOINT", ""),
		TracingOn:          envBool("FLEET_TRACING", false),
		AllowBootstrap:     envBool("FLEET_ALLOW_BOOTSTRAP", true),
		Environment:        env("FLEET_ENV", "development"),
	}

	c.JWTSecret = []byte(env("FLEET_JWT_SECRET", ""))
	c.CSRFSecret = []byte(env("FLEET_CSRF_SECRET", ""))
	c.CAKeyPassphrase = []byte(env("FLEET_CA_PASSPHRASE", ""))

	// WebAuthn: derive sensible localhost defaults from the public URL.
	c.WebAuthnRPID = env("FLEET_WEBAUTHN_RPID", hostOnly(c.PublicURL))
	c.WebAuthnRPName = env("FLEET_WEBAUTHN_RP_NAME", "Fleet Terminal")
	if origins := env("FLEET_WEBAUTHN_ORIGINS", ""); origins != "" {
		c.WebAuthnOrigins = strings.Split(origins, ",")
	} else {
		c.WebAuthnOrigins = []string{c.PublicURL, "http://localhost:5173", "http://localhost:8080"}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	var missing []string
	if c.Environment == "production" {
		if len(c.JWTSecret) < 32 {
			missing = append(missing, "FLEET_JWT_SECRET (>=32 bytes)")
		}
		if len(c.CSRFSecret) < 16 {
			missing = append(missing, "FLEET_CSRF_SECRET (>=16 bytes)")
		}
		if len(c.CAKeyPassphrase) < 16 {
			missing = append(missing, "FLEET_CA_PASSPHRASE (>=16 bytes)")
		}
	}
	// Development fallbacks: derive deterministic-but-warned secrets so the stack boots.
	if len(c.JWTSecret) == 0 {
		c.JWTSecret = []byte("dev-insecure-jwt-secret-change-me-0000000000")
	}
	if len(c.CSRFSecret) == 0 {
		c.CSRFSecret = []byte("dev-insecure-csrf-secret-change")
	}
	if len(c.CAKeyPassphrase) == 0 {
		c.CAKeyPassphrase = []byte("dev-insecure-ca-passphrase-change")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required production config: %s", strings.Join(missing, ", "))
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("FLEET_DATABASE_URL is required")
	}
	return nil
}

// IsProduction reports whether the app runs in production mode.
func (c *Config) IsProduction() bool { return c.Environment == "production" }

// hostOnly extracts the bare host from a URL (no scheme, no port), used as the
// default WebAuthn relying-party id.
func hostOnly(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, ":/"); i >= 0 {
		u = u[:i]
	}
	if u == "" {
		return "localhost"
	}
	return u
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
