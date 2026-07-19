// Package config loads and validates runtime configuration from the environment.
//
// All configuration is sourced from environment variables so the same binary
// runs identically across local Docker, Kubernetes, and systemd deployments.
package config

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved application configuration.
type Config struct {
	// Server
	HTTPAddr        string // e.g. ":8080"
	PublicURL       string // external base URL, used for cookies/WebAuthn
	ShutdownTimeout time.Duration

	// Database
	DatabaseURL    string
	DBMaxConns     int32
	DBMinConns     int32
	MigrateOnStart bool

	// Redis (jobs/cache). Optional; if empty an in-process scheduler is used.
	RedisURL string

	// Auth / crypto
	JWTSecret          []byte        // HMAC secret for access tokens
	AccessTokenTTL     time.Duration // short-lived
	RefreshTokenTTL    time.Duration // long-lived rotating
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration // hard cap on session age (0 = unlimited)
	CookieDomain       string
	CookieSecure       bool
	CSRFSecret         []byte

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
	WebAuthnRPID    string   // relying party id (registrable domain), e.g. "localhost"
	WebAuthnRPName  string   // human-readable RP name
	WebAuthnOrigins []string // allowed origins, e.g. http://localhost:5173

	// SSH Certificate Authority
	CAKeyPassphrase []byte        // encrypts CA private key at rest
	UserCertTTL     time.Duration // ephemeral user certificate lifetime (12h)
	CertRenewBefore time.Duration // renew this long before expiry (~3h)
	HostCertTTL     time.Duration

	// Jump host (SSH gateway egress point)
	JumpHost           string // host:port of the jump host
	JumpUser           string
	JumpKnownHostsFile string

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is trusted when
	// deriving the client IP for rate-limiting and audit. XFF from any other peer
	// is ignored (so it can't be spoofed to bypass the auth rate limiter). Default:
	// private + loopback ranges (covers a reverse proxy on the same host/network).
	TrustedProxies []string

	// SSHInsecureHostKeys disables SSH host-key verification on the gateway. It
	// exists only for the local test fabric (ephemeral containers with changing
	// host keys); it is refused in production. Default false → trust-on-first-use
	// verification.
	SSHInsecureHostKeys bool

	// HostScopedOnly locks managed-host certificate authorization down to
	// host-scoped principals: enrollment writes ONLY "fleet-h-<hostID>" into each
	// managed host's AuthorizedPrincipalsFile (dropping the fleet-wide "fleet"),
	// and system/playbook credentials add the target host's scoped principal.
	// Certificates still also carry "fleet" — that authenticates the jump-host hop
	// (the jump host always trusts "fleet") — but because a locked managed host no
	// longer trusts "fleet", a certificate minted for one host is rejected by every
	// other host, so it cannot be replayed to reach a host the user was not granted.
	//
	// Off by default. Turning it on is safe and needs no ordering: certs always
	// carry "fleet", so they keep working on hosts not yet re-enrolled, while each
	// host that IS re-enrolled under lockdown immediately stops accepting any other
	// host's certificate. Do NOT lock down the jump host itself — it must keep
	// trusting "fleet".
	HostScopedOnly bool

	// WireGuard overlay (used by host enrollment to provision tunnels)
	WGInterface    string // e.g. "wg0"
	WGSubnet       string // CIDR of the overlay, e.g. "10.100.0.0/24"
	WGJumpIP       string // jump host's address on the overlay
	WGJumpEndpoint string // endpoint managed hosts dial to reach the jump, host:port
	WGPort         int    // WireGuard listen port on managed hosts

	// Host metric history (append-only time series behind trend queries). Sample
	// bounds how often a per-host sample is recorded (independent of the 30s probe
	// cadence, to keep the table small); Retention bounds how long samples are kept
	// before the retention loop prunes them. Retention 0 disables history entirely.
	MetricHistorySample    time.Duration
	MetricHistoryRetention time.Duration

	// MonitorConcurrency bounds how many hosts the health-check sweep probes at
	// once. Each probe opens a fresh SSH connection to the jump host, so this must
	// stay under the jump host's sshd MaxStartups pre-auth limit (OpenSSH default
	// 10) — leaving headroom for user terminals and KRL pushes — or a rotating
	// subset of probes is refused and hosts flap offline. Raise it only after
	// raising MaxStartups on the jump host.
	MonitorConcurrency int

	// Operational-history retention. ActivityRetention bounds how long SSH
	// sessions, SFTP transfers, scans (+ their on-disk reports), playbook runs,
	// and login-attempt records are kept; AuditRetention separately bounds the
	// tamper-evident audit chain (pruning it truncates the verifiable window, so
	// it is kept distinct and conservative). Both 0 = keep forever (the default),
	// so no deployment loses history unless an operator opts in.
	ActivityRetention time.Duration
	AuditRetention    time.Duration

	// Session recordings storage
	RecordingDir string

	// OpenSCAP scan report storage
	ScanDir     string
	ScanTimeout time.Duration // max duration of a scan/remediation (oscap can be slow)

	// ReencryptSecrets, when true, opportunistically re-encrypts existing at-rest
	// secrets (the CA key) from the legacy SHA-256 envelope to the argon2id one on
	// boot. Off by default so a fresh deploy stays roll-back-compatible (an older
	// build can still read the legacy CA key); the dual-read path means new writes
	// are argon2id either way. Enable once you won't need to roll back.
	ReencryptSecrets bool

	// ControlPlaneHosts names Fleet's own control-plane host(s) — the box(es)
	// running the backend/jump host. Remediating one can lock Fleet out of the
	// whole fleet (e.g. an ip_forward/rp_filter sysctl breaking Docker's bridge),
	// so it requires an extra confirmation. Hosts may also be marked with a
	// "control-plane" or "protected" tag; the jump host is detected automatically.
	ControlPlaneHosts []string

	// SCAP content cache (datastreams the backend provisions to hosts whose OS
	// is newer than their packaged content). Empty disables auto-provisioning.
	ScapContentDir     string
	ScapContentVersion string // ComplianceAsCode release tag; empty = latest

	// Ansible runner sidecar base URL (e.g. http://ansible-runner:8000). The
	// backend delegates playbook validation/lint (and, later, execution) to it.
	// Empty disables the Ansible playbook feature's runner-backed operations.
	AnsibleRunnerURL string
	GrypeScannerURL  string // vulnerability-scanner sidecar
	MSRCAPIURL       string // Microsoft Security Update Guide API (Windows CVE mapping)
	MSRCMonths       int    // how many recent MSRC releases an online update fetches

	// CARotateAfter is how old the active SSH CA key may get before Fleet sends a
	// rotation-reminder notification (the CA never auto-expires; rotation is
	// manual via fleetctl rotate-ca).
	CARotateAfter time.Duration

	// Encrypted database backups: destination directory and the passphrase used
	// to encrypt them (openssl AES-256-CBC, PBKDF2). The passphrase falls back to
	// the CA passphrase if unset; set a distinct one to decouple the two.
	BackupDir        string
	BackupPassphrase string

	// VaultPassphrase encrypts stored credentials (the secrets vault) at rest with
	// secretbox. Must be set and distinct from the CA passphrase in production;
	// falls back to the CA passphrase in development. Resolve it via VaultKey().
	VaultPassphrase string

	// GuacdAddr is the address of the guacd sidecar that brokers RDP/VNC desktop
	// sessions. RDPProxyHost is the hostname guacd uses to reach THIS backend for
	// the per-session tunnel to the target (the backend's name on the internal
	// network, e.g. the compose service name).
	GuacdAddr    string
	RDPProxyHost string
	// RDPDriveDir is the base directory (on the shared rdp-drive volume) where guacd
	// stores per-session redirected-drive files for RDP file transfer. The backend
	// removes a session's subdir when it ends.
	RDPDriveDir string
	// RDPCollectFacts enables best-effort Windows fact collection over WinRM for RDP
	// hosts (OS/CPU/memory/uptime), using the host's open-policy vault credential
	// through the jump host. RDPWinRMPorts is tried in order (HTTPS 5986, then 5985).
	RDPCollectFacts bool
	RDPWinRMPorts   []int

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
		HTTPAddr:               env("FLEET_HTTP_ADDR", ":8080"),
		PublicURL:              env("FLEET_PUBLIC_URL", "https://localhost:8443"),
		ShutdownTimeout:        envDuration("FLEET_SHUTDOWN_TIMEOUT", 20*time.Second),
		DatabaseURL:            env("FLEET_DATABASE_URL", "postgres://fleet:fleet@postgres:5432/fleet?sslmode=disable"),
		DBMaxConns:             int32(envInt("FLEET_DB_MAX_CONNS", 20)),
		DBMinConns:             int32(envInt("FLEET_DB_MIN_CONNS", 2)),
		MigrateOnStart:         envBool("FLEET_MIGRATE_ON_START", true),
		RedisURL:               env("FLEET_REDIS_URL", "redis://redis:6379/0"),
		AccessTokenTTL:         envDuration("FLEET_ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:        envDuration("FLEET_REFRESH_TOKEN_TTL", 720*time.Hour),
		SessionIdleTTL:         envDuration("FLEET_SESSION_IDLE_TTL", 30*time.Minute),
		SessionAbsoluteTTL:     envDuration("FLEET_SESSION_ABSOLUTE_TTL", 12*time.Hour),
		CookieDomain:           env("FLEET_COOKIE_DOMAIN", ""),
		CookieSecure:           envBool("FLEET_COOKIE_SECURE", true),
		RateLimitPerMin:        envInt("FLEET_RATE_LIMIT_PER_MIN", 600),
		RateLimitBurst:         envInt("FLEET_RATE_LIMIT_BURST", 120),
		AuthRateLimitPerMin:    envInt("FLEET_AUTH_RATE_LIMIT_PER_MIN", 20),
		AuthRateLimitBurst:     envInt("FLEET_AUTH_RATE_LIMIT_BURST", 10),
		UserCertTTL:            envDuration("FLEET_USER_CERT_TTL", 12*time.Hour),
		CertRenewBefore:        envDuration("FLEET_CERT_RENEW_BEFORE", 3*time.Hour),
		HostCertTTL:            envDuration("FLEET_HOST_CERT_TTL", 365*24*time.Hour),
		JumpHost:               env("FLEET_JUMP_HOST", "jumphost:22"),
		JumpUser:               env("FLEET_JUMP_USER", "fleet"),
		JumpKnownHostsFile:     env("FLEET_JUMP_KNOWN_HOSTS", ""),
		SSHInsecureHostKeys:    envBool("FLEET_SSH_INSECURE_HOST_KEYS", false),
		HostScopedOnly:         envBool("FLEET_HOST_SCOPED_ONLY", false),
		TrustedProxies:         trustedProxiesFromEnv(),
		WGInterface:            env("FLEET_WG_INTERFACE", "wg0"),
		WGSubnet:               env("FLEET_WG_SUBNET", "10.100.0.0/24"),
		WGJumpIP:               env("FLEET_WG_JUMP_IP", "10.100.0.1"),
		WGJumpEndpoint:         env("FLEET_WG_JUMP_ENDPOINT", "jumphost:51820"),
		WGPort:                 envInt("FLEET_WG_PORT", 51820),
		MetricHistorySample:    envDuration("FLEET_METRIC_HISTORY_SAMPLE", 5*time.Minute),
		MetricHistoryRetention: envDuration("FLEET_METRIC_HISTORY_RETENTION", 720*time.Hour),
		MonitorConcurrency:     envInt("FLEET_MONITOR_CONCURRENCY", 6),
		ActivityRetention:      envDuration("FLEET_ACTIVITY_RETENTION", 0),
		AuditRetention:         envDuration("FLEET_AUDIT_RETENTION", 0),
		RecordingDir:           env("FLEET_RECORDING_DIR", "/var/lib/fleet/recordings"),
		ScanDir:                env("FLEET_SCAN_DIR", "/var/lib/fleet/scans"),
		ScanTimeout:            envDuration("FLEET_SCAN_TIMEOUT", 60*time.Minute),
		ControlPlaneHosts:      splitList(env("FLEET_CONTROL_PLANE_HOSTS", "")),
		ReencryptSecrets:       envBool("FLEET_REENCRYPT_SECRETS", false),
		ScapContentDir:         env("FLEET_SCAP_CONTENT_DIR", "/var/lib/fleet/scap-content"),
		ScapContentVersion:     env("FLEET_SCAP_CONTENT_VERSION", ""),
		AnsibleRunnerURL:       env("FLEET_ANSIBLE_RUNNER_URL", "http://ansible-runner:8000"),
		GrypeScannerURL:        env("FLEET_GRYPE_SCANNER_URL", "http://grype-scanner:8000"),
		MSRCAPIURL:             env("FLEET_MSRC_API_URL", "https://api.msrc.microsoft.com"),
		MSRCMonths:             envInt("FLEET_MSRC_MONTHS", 12),
		CARotateAfter:          envDuration("FLEET_CA_ROTATE_AFTER", 365*24*time.Hour),
		BackupDir:              env("FLEET_BACKUP_DIR", "/var/lib/fleet/backups"),
		BackupPassphrase:       env("FLEET_BACKUP_PASSPHRASE", ""),
		VaultPassphrase:        env("FLEET_VAULT_PASSPHRASE", ""),
		GuacdAddr:              env("FLEET_GUACD_ADDR", "guacd:4822"),
		RDPProxyHost:           env("FLEET_RDP_PROXY_HOST", "backend"),
		RDPDriveDir:            env("FLEET_RDP_DRIVE_DIR", "/var/lib/fleet/rdp-drive"),
		RDPCollectFacts:        envBool("FLEET_RDP_COLLECT_FACTS", true),
		RDPWinRMPorts:          parseIntList(env("FLEET_RDP_WINRM_PORTS", "5986,5985")),
		MaxUploadBytes:         envInt64("FLEET_MAX_UPLOAD_BYTES", 5<<30), // 5 GiB default
		LogLevel:               env("FLEET_LOG_LEVEL", "info"),
		LogFormat:              env("FLEET_LOG_FORMAT", "json"),
		OTLPEndpoint:           env("FLEET_OTLP_ENDPOINT", ""),
		TracingOn:              envBool("FLEET_TRACING", false),
		AllowBootstrap:         envBool("FLEET_ALLOW_BOOTSTRAP", true),
		Environment:            env("FLEET_ENV", "development"),
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
	// Secrets and the accept-any host-key toggle are only permitted their insecure
	// defaults in an explicit "development" environment (the local test fabric).
	// Every other environment — production, staging, or anything unrecognized —
	// must supply real secrets; otherwise the CA signing key, tokens, and CSRF
	// tokens would be protected by publicly-known constants. Fail closed.
	if c.Environment != "development" {
		var missing []string
		if len(c.JWTSecret) < 32 {
			missing = append(missing, "FLEET_JWT_SECRET (>=32 bytes)")
		}
		if len(c.CSRFSecret) < 16 {
			missing = append(missing, "FLEET_CSRF_SECRET (>=16 bytes)")
		}
		if len(c.CAKeyPassphrase) < 16 {
			missing = append(missing, "FLEET_CA_PASSPHRASE (>=16 bytes)")
		}
		if len(missing) > 0 {
			return fmt.Errorf("missing required config for %q environment: %s",
				c.Environment, strings.Join(missing, ", "))
		}
		if c.SSHInsecureHostKeys {
			return fmt.Errorf("FLEET_SSH_INSECURE_HOST_KEYS must not be enabled outside development")
		}
	} else {
		// Development-only fallbacks so the local stack boots without configured
		// secrets. Never reached in production/staging (secrets required above).
		// Token/CSRF secrets are generated fresh per boot rather than using shared
		// hardcoded constants, so a dev instance that is accidentally exposed is
		// never protected by a publicly-known key (tokens simply reset on restart).
		var ephemeral []string
		if len(c.JWTSecret) == 0 {
			c.JWTSecret = randomSecret(32)
			ephemeral = append(ephemeral, "FLEET_JWT_SECRET (ephemeral)")
		}
		if len(c.CSRFSecret) == 0 {
			c.CSRFSecret = randomSecret(32)
			ephemeral = append(ephemeral, "FLEET_CSRF_SECRET (ephemeral)")
		}
		if len(c.CAKeyPassphrase) == 0 {
			// The CA key is encrypted at rest with this, so it must stay stable
			// across restarts — a random value would make a persisted dev CA
			// undecryptable. This is the one remaining fixed dev default.
			c.CAKeyPassphrase = []byte("dev-insecure-ca-passphrase-change")
			ephemeral = append(ephemeral, "FLEET_CA_PASSPHRASE (fixed insecure default)")
		}
		if len(ephemeral) > 0 {
			slog.Warn("running in DEVELOPMENT mode with insecure secrets — set FLEET_ENV=production and provide real secrets for any non-local deployment",
				"secrets", strings.Join(ephemeral, ", "))
		}
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("FLEET_DATABASE_URL is required")
	}
	// The renewal window must sit inside the cert lifetime; otherwise every
	// EnsureHostCredential call sees a cert already "due for renewal" and re-mints
	// on every connection. Only enforced when a TTL is actually set: Load() always
	// applies non-zero defaults, so real configs are always checked; a zero TTL only
	// occurs in direct struct construction (tests) that isn't exercising cert TTLs.
	if c.UserCertTTL > 0 && c.CertRenewBefore >= c.UserCertTTL {
		return fmt.Errorf("FLEET_CERT_RENEW_BEFORE (%s) must be less than FLEET_USER_CERT_TTL (%s)",
			c.CertRenewBefore, c.UserCertTTL)
	}
	return nil
}

// randomSecret returns n cryptographically-random bytes, used only for ephemeral
// development secrets. crypto/rand failure is a catastrophic platform fault, so it
// panics rather than silently returning a weak key.
func randomSecret(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("config: cannot generate development secret: " + err.Error())
	}
	return b
}

// IsProduction reports whether the app runs in production mode.
func (c *Config) IsProduction() bool { return c.Environment == "production" }

// VaultKey returns the secrets-vault encryption passphrase. In production it must
// be set and distinct from the CA passphrase (a single leaked key must not unlock
// both the CA and the credential vault); in development it falls back to the CA
// passphrase so the local stack works without extra configuration. Callers seal/
// open vault secrets with the returned key and surface the error to the operator.
func (c *Config) VaultKey() ([]byte, error) {
	if c.VaultPassphrase != "" {
		if c.IsProduction() && c.VaultPassphrase == string(c.CAKeyPassphrase) {
			return nil, fmt.Errorf("FLEET_VAULT_PASSPHRASE must differ from FLEET_CA_PASSPHRASE")
		}
		return []byte(c.VaultPassphrase), nil
	}
	if c.IsProduction() {
		return nil, fmt.Errorf("FLEET_VAULT_PASSPHRASE is required in production to use the credential vault")
	}
	return c.CAKeyPassphrase, nil
}

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

// defaultTrustedProxies are the private + loopback ranges trusted for
// X-Forwarded-For by default — enough for a reverse proxy co-located on the host
// or Docker network, while ignoring XFF from public (attacker) peers.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
}

func trustedProxiesFromEnv() []string {
	if v := splitList(env("FLEET_TRUSTED_PROXIES", "")); len(v) > 0 {
		return v
	}
	return defaultTrustedProxies
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseIntList parses a comma-separated list of ints, skipping unparseable entries.
func parseIntList(s string) []int {
	var out []int
	for _, p := range splitList(s) {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	return out
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
