// Package config loads and validates runtime configuration from the environment.
//
// All configuration is sourced from environment variables so the same binary
// runs identically across local Docker, Kubernetes, and systemd deployments.
package config

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kforbus3/provenance/backend/internal/extsecret"
	"github.com/kforbus3/provenance/backend/internal/kms"
)

// Config is the fully-resolved application configuration.
type Config struct {
	// Server
	HTTPAddr  string // e.g. ":8080"
	PublicURL string // external base URL, used for cookies/WebAuthn

	// Aldgate, the log collector. Empty disables the Logs page, which is the
	// case for any deployment that has not stood one up -- so it is absent
	// rather than broken, and the page says how to point at one.
	AldgateURL      string
	AldgateUser     string
	AldgatePassword string
	// Console tier credentials. The embedded log console runs AS one of these,
	// chosen per request from the viewer's Provenance permissions, so nobody
	// types a collector password and no browser is ever sent one. Provisioned by
	// Aldgate's bootstrap; leave them unset and the console falls back to asking
	// for a password, which is what it did before this existed.
	AldgateConsoleViewerUser     string
	AldgateConsoleViewerPassword string
	AldgateConsoleAdminUser      string
	AldgateConsoleAdminPassword  string
	ShutdownTimeout              time.Duration

	// FIPS mode (opt-in policy profile). When true, every crypto choice routes
	// through the FIPS-approved set (ECDSA P-256 CA/certs, PBKDF2 KDF, pinned SSH
	// suites, SHA-256 TOTP, ES256 WebAuthn) and the boot self-check fails closed if
	// the validated Go crypto module isn't active or a non-FIPS artifact remains.
	// Off by default — non-FIPS installs are unchanged.
	FIPSMode bool
	// Overlay selects the host-reachability transport: "wireguard" (default) or,
	// under FIPS, "openvpn". Empty derives from FIPSMode.
	Overlay string

	// Database
	DatabaseURL    string
	DBMaxConns     int32
	DBMinConns     int32
	MigrateOnStart bool
	// MultiTenancy enables the MSP multi-tenant mode (PROV_MULTI_TENANCY). Default
	// off: Provenance is single-tenant and every row belongs to the seeded default tenant,
	// with no tenant filtering (behavior unchanged). When on, Postgres row-level
	// security scopes every query to the request's tenant. See docs/multi-tenancy-plan.md.
	MultiTenancy bool
	// DRStandbyToken authorizes the promote action on the read-only DR standby
	// console (a write-free break-glass path, since a standby DB can't create a
	// login session). Empty = the standby console is status-only; promote via
	// provctl / your DB tooling instead.
	DRStandbyToken string

	// Redis (jobs/cache). Optional; if empty an in-process scheduler is used.
	RedisURL string

	// Auth / crypto
	JWTSecret []byte // HMAC secret for access tokens
	// MFAEncryptionKey, when set (PROV_MFA_ENCRYPTION_KEY), is a dedicated key for
	// encrypting TOTP secrets at rest, decoupled from JWTSecret. Empty = derive from
	// JWTSecret (legacy). Setting it lets JWTSecret rotate without bricking stored MFA
	// secrets; existing secrets still decrypt via the legacy fallback.
	MFAEncryptionKey   []byte
	AccessTokenTTL     time.Duration // short-lived
	RefreshTokenTTL    time.Duration // long-lived rotating
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration // hard cap on session age (0 = unlimited)
	CookieDomain       string
	CookieSecure       bool
	CSRFSecret         []byte
	// AuditHMACKey (PROV_AUDIT_HMAC_KEY), when set, keys the audit-log integrity
	// chain with HMAC-SHA256 instead of a bare SHA-256 hash, so a party with only
	// database write access cannot silently rewrite history and recompute a valid
	// chain. Required in production; a fixed insecure default is used in development
	// so a local chain stays verifiable across restarts.
	AuditHMACKey []byte

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

	// External KMS / HSM (envelope-protects the master passphrases at rest). When
	// KMSProvider is anything other than "local", the CA and/or vault passphrases may
	// be supplied as KMS-wrapped blobs (*_WRAPPED below) instead of plaintext; Provenance
	// unwraps them once at boot via ResolveSecrets. The at-rest sealing format itself
	// is unchanged, so enabling or disabling a KMS backend needs no re-seal. See
	// internal/kms and docs/kms.md.
	KMSProvider            string // "local" | "vault-transit" | "aws-kms" | "azure-keyvault" | "gcp-kms"
	KMSKeyID               string
	KMSVaultAddr           string
	KMSVaultToken          string
	KMSVaultCACertFile     string
	KMSVaultTLSSkipVerify  bool
	KMSAWSRegion           string
	KMSAWSAccessKey        string
	KMSAWSSecretKey        string
	KMSAWSSessionToken     string
	KMSAWSEndpoint         string
	KMSAzureVaultURL       string
	KMSAzureTenantID       string
	KMSAzureClientID       string
	KMSAzureClientSecret   string
	KMSGCPCredentialsJSON  string
	KMSGCPCredentialsFile  string
	CAKeyPassphraseWrapped string // KMS-wrapped PROV_CA_PASSPHRASE (optional)
	VaultPassphraseWrapped string // KMS-wrapped PROV_VAULT_PASSPHRASE (optional)

	// External secrets manager (vault-of-record). When configured, a vault credential
	// marked external-backed is fetched on demand from the manager (HashiCorp Vault KV)
	// instead of from a locally sealed blob. Off by default; non-external secrets are
	// unaffected.
	ExtSecretVaultAddr          string
	ExtSecretVaultToken         string
	ExtSecretVaultCACertFile    string
	ExtSecretVaultTLSSkipVerify bool
	ExtSecretAWSRegion          string
	ExtSecretAWSAccessKey       string
	ExtSecretAWSSecretKey       string
	ExtSecretAWSSessionToken    string
	ExtSecretAWSEndpoint        string

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

	// TrustedProxyHops is how many reverse proxies sit in front of this server.
	// The client is the X-Forwarded-For entry that many places from the right —
	// the address the outermost proxy actually saw — so a caller cannot reach it
	// by prepending entries of its own.
	//
	// It is stated rather than inferred. Deciding which entries are proxies by
	// whether they are private addresses looks reasonable and is wrong: the
	// default trusted list has to include RFC1918 because the proxy is on a
	// Docker bridge or the LAN, which made every private CLIENT look like a
	// proxy too. Default 1 matches the shipped compose, which has one nginx in
	// front of the backend.
	TrustedProxyHops int

	// SSHInsecureHostKeys disables SSH host-key verification on the gateway. It
	// exists only for the local test fabric (ephemeral containers with changing
	// host keys); it is refused in production. Default false → trust-on-first-use
	// verification.
	SSHInsecureHostKeys bool

	// HostScopedOnly locks managed-host certificate authorization down to
	// host-scoped principals: enrollment writes ONLY "prov-h-<hostID>" into each
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

	// OpenVPN overlay (the certificate-authenticated / FIPS transport).
	//
	// It has its OWN subnet, because both overlays terminate on the same jump host
	// and both put the jump host's address on their interface: sharing one subnet
	// gives that host two connected routes for the same /24, the kernel resolves it
	// once rather than per destination, and whichever interface loses takes every
	// host on it offline. Separate subnets are what make a per-host choice of
	// transport — and switching a host between them — actually work.
	//
	// A host's assigned address still lives in the one wg_address column whichever
	// overlay assigned it, so the gateway, monitor and every consumer stay
	// transport-agnostic; only the pool it is drawn from differs.
	OVPNPort   int    // UDP listen port on the jump host
	OVPNSubnet string // CIDR of the OpenVPN overlay, e.g. "10.101.0.0/24"
	OVPNJumpIP string // jump host's address on the OpenVPN overlay

	// OverlayPeerIsolation makes the overlay a strict hub-and-spoke management
	// network: the jump host refuses to forward traffic between two managed hosts,
	// so a host can reach the jump host and nothing else on the overlay. On by
	// default — every path Provenance uses (terminal, SFTP, monitor, playbooks, the DB
	// and Kubernetes brokers) originates ON the jump host, so none of them is a
	// forwarded flow and none is affected. Turn it off only if a deployment
	// genuinely needs managed hosts to talk to each other over the overlay;
	// leaving it on keeps a single compromised host from reaching the rest of the
	// fleet's SSH/RDP/WinRM ports directly, bypassing Provenance's brokering and audit.
	OverlayPeerIsolation bool

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

	// MonitorOfflineConfirmations is how many consecutive failed probes it takes to
	// flip a previously-online host to offline (and alert). The confirming re-probes
	// run MonitorConfirmDelay apart within the same sweep, so a transient hiccup — a
	// jump-host sshd connection reset, a DNS blip — doesn't flap the host and page
	// anyone. 1 restores the old single-check behavior. Hosts already offline are
	// not re-probed extra times, so steady-state sweep cost is unchanged.
	MonitorOfflineConfirmations int
	MonitorConfirmDelay         time.Duration

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
	// RecordingEncryptionKey (PROV_RECORDING_KEY), when set, encrypts session
	// recordings at rest with AES-256-GCM. Empty leaves recordings as plaintext on
	// disk (legacy behavior); a warning is emitted in production.
	RecordingEncryptionKey []byte
	// RecordingAllowPlaintext (PROV_RECORDING_ALLOW_PLAINTEXT) is the explicit,
	// recorded decision to record sessions unencrypted outside development. Without
	// it a non-development environment refuses to start with no recording key, the
	// same way it refuses to start with no JWT or audit-chain secret.
	//
	// Session recordings are not metadata. A terminal recording contains whatever the
	// operator typed and whatever came back: pasted passwords, tokens, database rows,
	// key material. Writing them 0640 in plaintext gives anyone who can read that
	// directory the contents of every privileged session — which is a larger prize
	// than the credentials this product exists to keep out of their hands.
	RecordingAllowPlaintext bool
	// AllowUnrecordedSessions (PROV_ALLOW_UNRECORDED_SESSIONS) lets a privileged
	// session proceed when its recording could not be started.
	//
	// The default is to refuse it. A product whose promise is audited privileged
	// access should not quietly hand somebody a root shell it cannot record: a full
	// disk, a permissions mistake, or a database that would not accept the session row
	// all produced exactly that, with no log line and nothing in the audit trail to
	// say the session was unrecorded.
	//
	// Refusing has a real cost -- a disk-full condition stops privileged access -- so
	// the escape hatch exists, and taking it is counted and audited per session rather
	// than being the silent default.
	AllowUnrecordedSessions bool

	// OpenSCAP scan report storage
	ScanDir     string
	ScanTimeout time.Duration // max duration of a scan/remediation (oscap can be slow)
	// VulnScanTimeout bounds a single host's vulnerability scan (collect package DBs
	// over SSH + the grype-scanner request). It must be generous: a fleet-wide
	// scheduled scan queues many hosts at the shared scanner, so a per-host request
	// can legitimately wait behind others before grype runs.
	VulnScanTimeout time.Duration

	// PlaybookTimeout bounds a single playbook run end to end. A run is sequential
	// across its inventory and every host that takes a new kernel adds a reboot and
	// a wait_for_connection on top of its upgrade, so the bound scales with host
	// count, not with per-host work: a fleet-wide upgrade can legitimately outgrow
	// the default long before any individual host is in trouble. Raise this rather
	// than splitting a fleet into batches — a run killed at the deadline reports
	// exit 124 with no failed host, which reads as a fleet problem when it is only
	// a budget one.
	PlaybookTimeout time.Duration

	// ReencryptSecrets, when true, opportunistically re-encrypts existing at-rest
	// secrets (the CA key) from the legacy SHA-256 envelope to the argon2id one on
	// boot. Off by default so a fresh deploy stays roll-back-compatible (an older
	// build can still read the legacy CA key); the dual-read path means new writes
	// are argon2id either way. Enable once you won't need to roll back.
	ReencryptSecrets bool

	// ControlPlaneHosts names Provenance's own control-plane host(s) — the box(es)
	// running the backend/jump host. Remediating one can lock Provenance out of the
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
	// AnsibleRunnerToken (PROV_ANSIBLE_RUNNER_TOKEN) is a shared secret the backend
	// presents to the runner sidecar's /run API (X-Runner-Token). The runner rejects
	// unauthenticated calls when this is set, so nothing else on the Docker network
	// can submit playbooks (which would be remote code execution). Required in
	// production; empty disables the check in development.
	AnsibleRunnerToken string

	// --- Imaging: OS images, PXE and updates (see docs/imaging.md) -----------
	//
	// ArtifactDir is where built images, update bundles and the netboot imager
	// live -- the directory the builder container writes into and the
	// provisioning server serves from.
	ArtifactDir string

	// ImagingSecretPrefix is where a generated LUKS recovery passphrase is filed
	// in the EXTERNAL secrets manager, when one is connected. The image name is
	// appended, so a Vault KV ref reads "secret/provenance/images/<image>".
	//
	// Ignored without an external manager: the passphrase then goes into Provenance's
	// own credential vault, which needs no path.
	ImagingSecretPrefix string
	// ControlURL is the address machines reach this server on *after* they have
	// left the provisioning network. Every other address in a deployment is on
	// the imaging segment, which a machine is on for the twenty minutes it takes
	// to image it and never again. Empty and machines fall back to the address
	// they were imaged from, which they stop being able to reach the moment they
	// are unracked -- they keep running perfectly and are simply never heard
	// from again.
	ControlURL string
	// AgentInterval is how often a machine's agent checks in, in seconds. Sent
	// back in every reply, so changing it re-paces the whole fleet without
	// touching a machine.
	AgentInterval int
	// AgentToken, when set, must be presented by an agent to check in. Off by
	// default: the first heartbeat comes from a machine that was just imaged and
	// holds no credential. Set it when the control plane is reachable from a
	// network that is not the provisioning one.
	AgentToken string
	// ImagingNudge controls whether machines a live rollout is waiting on are
	// asked to check in immediately rather than waiting for their own timer.
	// This is the whole of the "push"; off, rollouts still work, only slower.
	ImagingNudge bool
	// BuilderRunnerURL is the builder-runner sidecar: the only thing in a
	// deployment that touches the Docker socket. Building an image means running
	// a privileged container that loop-mounts a disk, so the ability to ask for
	// one is the host -- and it is deliberately not held by the process that also
	// holds the certificate authority.
	BuilderRunnerURL string
	// BuilderRunnerToken is the shared secret sent as X-Runner-Token, exactly as
	// for the Ansible runner. Required in production for the same reason.
	BuilderRunnerToken string

	GrypeScannerURL string // vulnerability-scanner sidecar
	MSRCAPIURL      string // Microsoft Security Update Guide API (Windows CVE mapping)
	MSRCMonths      int    // how many recent MSRC releases an online update fetches

	// CARotateAfter is how old the active SSH CA key may get before Provenance sends a
	// rotation-reminder notification (the CA never auto-expires; rotation is
	// manual via provctl rotate-ca).
	CARotateAfter time.Duration

	// Encrypted database backups: destination directory and the passphrase used
	// to encrypt them (openssl AES-256-CBC, PBKDF2). The passphrase falls back to
	// the CA passphrase if unset; set a distinct one to decouple the two.
	BackupDir string
	// BackupDatabaseURL is the connection backups are taken over, when it differs
	// from the serving one.
	//
	// It has to differ under multi-tenancy. Tenant isolation requires the serving
	// role to be NOSUPERUSER NOBYPASSRLS, and pg_dump run as such a role fails on
	// every table with a row-level security policy — so without this a multi-tenant
	// deployment can take no backup at all, and therefore cannot upgrade, since the
	// upgrade refuses to start without a successful pre-upgrade backup.
	BackupDatabaseURL string
	BackupPassphrase  string

	// In-UI upgrade system. ReleaseTrustKeys are extra base64 Ed25519 release public
	// keys (comma/space-separated) trusted in addition to any baked into the binary —
	// used for key rotation or a source build. UpdatesDir stages uploaded bundles for
	// the updater sidecar to read. UpdaterURL/UpdaterToken address the privileged
	// prov-updater sidecar that performs the container swap over the Docker socket.
	ReleaseTrustKeys string
	UpdatesDir       string
	UpdaterURL       string
	UpdaterToken     string
	// UpdateChannelURL, when set, is the signed release-channel index the UI's "check
	// for updates" fetches (later the Provenance product site). Empty disables pull-based
	// updates; manual bundle upload still works.
	UpdateChannelURL string

	// VaultPassphrase encrypts stored credentials (the secrets vault) at rest with
	// secretbox. Must be set and distinct from the CA passphrase in production;
	// falls back to the CA passphrase in development. Resolve it via VaultKey().
	VaultPassphrase string
	// VaultRotationCheck is how often the leader scans for password credentials whose
	// scheduled rotation is due (the per-credential interval is set in the UI).
	VaultRotationCheck time.Duration

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

	// Multi-site federation. Mode selects the instance's role:
	//   standalone (default) — today's behavior, no federation code active.
	//   hub  — aggregates and manages remote "site" instances (single pane of glass).
	//   site — a normal Provenance instance that also dials out to a hub and accepts
	//          hub-authorized, key-verified requests (managed mode).
	// Standalone requires none of the fields below and is byte-for-byte unchanged.
	Mode string

	// Site-mode: how to reach and trust the hub.
	HubURL            string // wss://hub/federation/link (the hub's public base for federation)
	HubJoinToken      string // one-time pairing token, only needed for the first join
	HubKeyFingerprint string // pinned hub federation public-key fingerprint (TOFU defense)
	// FederationTransport selects how the site reaches the hub. The application
	// protocol is always WSS (outbound TLS 443 + Ed25519 auth). "wireguard" is not a
	// distinct wire protocol: it declares that the WSS link rides an operator-provided
	// WireGuard/VPN underlay (point HubURL at the hub's overlay address), so no inbound
	// reachability is exposed on the public internet. Both values run identical code.
	FederationTransport string // "wss" (default) | "wireguard" (WSS over a WG underlay)

	Environment string // "development" | "production"
}

// Load reads configuration from the environment, applies defaults, and validates.
func Load() (*Config, error) {
	// Say so before anything reads them, so the warning appears above whatever
	// the deprecated setting went on to affect.
	warnDeprecated()

	c := &Config{
		HTTPAddr:                     env("PROV_HTTP_ADDR", ":8080"),
		PublicURL:                    env("PROV_PUBLIC_URL", "https://localhost:8443"),
		AldgateURL:                   env("PROV_ALDGATE_URL", ""),
		AldgateUser:                  env("PROV_ALDGATE_USER", "admin"),
		AldgatePassword:              env("PROV_ALDGATE_PASSWORD", ""),
		AldgateConsoleViewerUser:     env("PROV_ALDGATE_CONSOLE_VIEWER_USER", "prov_viewer"),
		AldgateConsoleViewerPassword: env("PROV_ALDGATE_CONSOLE_VIEWER_PASSWORD", ""),
		AldgateConsoleAdminUser:      env("PROV_ALDGATE_CONSOLE_ADMIN_USER", "prov_admin"),
		AldgateConsoleAdminPassword:  env("PROV_ALDGATE_CONSOLE_ADMIN_PASSWORD", ""),
		ShutdownTimeout:              envDuration("PROV_SHUTDOWN_TIMEOUT", 20*time.Second),
		DatabaseURL:                  env("PROV_DATABASE_URL", "postgres://prov:prov@postgres:5432/prov?sslmode=disable"),
		DBMaxConns:                   int32(envInt("PROV_DB_MAX_CONNS", 20)),
		DBMinConns:                   int32(envInt("PROV_DB_MIN_CONNS", 2)),
		MigrateOnStart:               envBool("PROV_MIGRATE_ON_START", true),
		MultiTenancy:                 envBool("PROV_MULTI_TENANCY", false),
		DRStandbyToken:               env("PROV_DR_STANDBY_TOKEN", ""),
		FIPSMode:                     envBool("PROV_FIPS_MODE", false),
		Overlay:                      env("PROV_OVERLAY", ""),
		RedisURL:                     env("PROV_REDIS_URL", "redis://redis:6379/0"),
		AccessTokenTTL:               envDuration("PROV_ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:              envDuration("PROV_REFRESH_TOKEN_TTL", 720*time.Hour),
		SessionIdleTTL:               envDuration("PROV_SESSION_IDLE_TTL", 30*time.Minute),
		SessionAbsoluteTTL:           envDuration("PROV_SESSION_ABSOLUTE_TTL", 12*time.Hour),
		CookieDomain:                 env("PROV_COOKIE_DOMAIN", ""),
		CookieSecure:                 envBool("PROV_COOKIE_SECURE", true),
		RateLimitPerMin:              envInt("PROV_RATE_LIMIT_PER_MIN", 600),
		RateLimitBurst:               envInt("PROV_RATE_LIMIT_BURST", 120),
		AuthRateLimitPerMin:          envInt("PROV_AUTH_RATE_LIMIT_PER_MIN", 20),
		AuthRateLimitBurst:           envInt("PROV_AUTH_RATE_LIMIT_BURST", 10),
		UserCertTTL:                  envDuration("PROV_USER_CERT_TTL", 12*time.Hour),
		CertRenewBefore:              envDuration("PROV_CERT_RENEW_BEFORE", 3*time.Hour),
		HostCertTTL:                  envDuration("PROV_HOST_CERT_TTL", 365*24*time.Hour),
		JumpHost:                     env("PROV_JUMP_HOST", "jumphost:22"),
		JumpUser:                     env("PROV_JUMP_USER", "prov"),
		JumpKnownHostsFile:           env("PROV_JUMP_KNOWN_HOSTS", ""),
		SSHInsecureHostKeys:          envBool("PROV_SSH_INSECURE_HOST_KEYS", false),
		HostScopedOnly:               envBool("PROV_HOST_SCOPED_ONLY", false),
		TrustedProxies:               trustedProxiesFromEnv(),
		TrustedProxyHops:             envInt("PROV_TRUSTED_PROXY_HOPS", 1),
		WGInterface:                  env("PROV_WG_INTERFACE", "wg0"),
		WGSubnet:                     env("PROV_WG_SUBNET", "10.100.0.0/24"),
		WGJumpIP:                     env("PROV_WG_JUMP_IP", "10.100.0.1"),
		WGJumpEndpoint:               env("PROV_WG_JUMP_ENDPOINT", "jumphost:51820"),
		WGPort:                       envInt("PROV_WG_PORT", 51820),
		OVPNPort:                     envInt("PROV_OVPN_PORT", 1194),
		OVPNSubnet:                   env("PROV_OVPN_SUBNET", ""),
		OVPNJumpIP:                   env("PROV_OVPN_JUMP_IP", ""),
		OverlayPeerIsolation:         envBool("PROV_OVERLAY_PEER_ISOLATION", true),
		VaultRotationCheck:           envDuration("PROV_VAULT_ROTATION_CHECK", 30*time.Minute),
		MetricHistorySample:          envDuration("PROV_METRIC_HISTORY_SAMPLE", 5*time.Minute),
		MetricHistoryRetention:       envDuration("PROV_METRIC_HISTORY_RETENTION", 720*time.Hour),
		MonitorConcurrency:           envInt("PROV_MONITOR_CONCURRENCY", 6),
		MonitorOfflineConfirmations:  envInt("PROV_MONITOR_OFFLINE_CONFIRMATIONS", 3),
		MonitorConfirmDelay:          envDuration("PROV_MONITOR_CONFIRM_DELAY", 10*time.Second),
		ActivityRetention:            envDuration("PROV_ACTIVITY_RETENTION", 0),
		AuditRetention:               envDuration("PROV_AUDIT_RETENTION", 0),
		RecordingDir:                 env("PROV_RECORDING_DIR", "/var/lib/prov/recordings"),
		ScanDir:                      env("PROV_SCAN_DIR", "/var/lib/prov/scans"),
		ScanTimeout:                  envDuration("PROV_SCAN_TIMEOUT", 60*time.Minute),
		VulnScanTimeout:              envDuration("PROV_VULN_SCAN_TIMEOUT", 20*time.Minute),
		PlaybookTimeout:              envDuration("PROV_PLAYBOOK_TIMEOUT", 30*time.Minute),
		ControlPlaneHosts:            splitList(env("PROV_CONTROL_PLANE_HOSTS", "")),
		ReencryptSecrets:             envBool("PROV_REENCRYPT_SECRETS", false),
		ScapContentDir:               env("PROV_SCAP_CONTENT_DIR", "/var/lib/prov/scap-content"),
		ScapContentVersion:           env("PROV_SCAP_CONTENT_VERSION", ""),
		AnsibleRunnerURL:             env("PROV_ANSIBLE_RUNNER_URL", "http://ansible-runner:8000"),
		AnsibleRunnerToken:           env("PROV_ANSIBLE_RUNNER_TOKEN", ""),
		ArtifactDir:                  env("PROV_ARTIFACT_DIR", "/output"),
		ImagingSecretPrefix:          strings.Trim(env("PROV_IMAGING_SECRET_PREFIX", "secret/provenance/images"), "/"),
		ControlURL:                   strings.TrimRight(env("PROV_CONTROL_URL", ""), "/"),
		AgentInterval:                envInt("PROV_AGENT_INTERVAL", 300),
		AgentToken:                   env("PROV_AGENT_TOKEN", ""),
		ImagingNudge:                 envBool("PROV_IMAGING_NUDGE", true),
		// No default. Unlike the Ansible runner, this sidecar is not part of
		// every deployment -- it needs the Docker socket and a lot of disk, and a
		// fleet that consumes images someone else builds should not be made to
		// run it, nor to invent a secret for a service it does not have.
		BuilderRunnerURL:    strings.TrimRight(env("PROV_BUILDER_RUNNER_URL", ""), "/"),
		BuilderRunnerToken:  env("PROV_BUILDER_RUNNER_TOKEN", ""),
		GrypeScannerURL:     env("PROV_GRYPE_SCANNER_URL", "http://grype-scanner:8000"),
		MSRCAPIURL:          env("PROV_MSRC_API_URL", "https://api.msrc.microsoft.com"),
		MSRCMonths:          envInt("PROV_MSRC_MONTHS", 12),
		CARotateAfter:       envDuration("PROV_CA_ROTATE_AFTER", 365*24*time.Hour),
		BackupDir:           env("PROV_BACKUP_DIR", "/var/lib/prov/backups"),
		BackupDatabaseURL:   env("PROV_BACKUP_DATABASE_URL", ""),
		ReleaseTrustKeys:    env("PROV_RELEASE_TRUST_KEYS", ""),
		UpdatesDir:          env("PROV_UPDATES_DIR", "/var/lib/prov/updates"),
		UpdaterURL:          env("PROV_UPDATER_URL", "http://prov-updater:9000"),
		UpdaterToken:        env("PROV_UPDATER_TOKEN", ""),
		UpdateChannelURL:    env("PROV_UPDATE_CHANNEL_URL", ""),
		BackupPassphrase:    env("PROV_BACKUP_PASSPHRASE", ""),
		VaultPassphrase:     env("PROV_VAULT_PASSPHRASE", ""),
		GuacdAddr:           env("PROV_GUACD_ADDR", "guacd:4822"),
		RDPProxyHost:        env("PROV_RDP_PROXY_HOST", "backend"),
		RDPDriveDir:         env("PROV_RDP_DRIVE_DIR", "/var/lib/prov/rdp-drive"),
		RDPCollectFacts:     envBool("PROV_RDP_COLLECT_FACTS", true),
		RDPWinRMPorts:       parseIntList(env("PROV_RDP_WINRM_PORTS", "5986,5985")),
		MaxUploadBytes:      envInt64("PROV_MAX_UPLOAD_BYTES", 5<<30), // 5 GiB default
		LogLevel:            env("PROV_LOG_LEVEL", "info"),
		LogFormat:           env("PROV_LOG_FORMAT", "json"),
		OTLPEndpoint:        env("PROV_OTLP_ENDPOINT", ""),
		TracingOn:           envBool("PROV_TRACING", false),
		AllowBootstrap:      envBool("PROV_ALLOW_BOOTSTRAP", true),
		Mode:                strings.ToLower(env("PROV_MODE", "standalone")),
		HubURL:              env("PROV_HUB_URL", ""),
		HubJoinToken:        env("PROV_HUB_JOIN_TOKEN", ""),
		HubKeyFingerprint:   env("PROV_HUB_KEY_FINGERPRINT", ""),
		FederationTransport: strings.ToLower(env("PROV_FEDERATION_TRANSPORT", "wss")),
		Environment:         env("PROV_ENV", "development"),
	}

	c.JWTSecret = []byte(env("PROV_JWT_SECRET", ""))
	c.MFAEncryptionKey = []byte(env("PROV_MFA_ENCRYPTION_KEY", ""))
	c.CSRFSecret = []byte(env("PROV_CSRF_SECRET", ""))
	c.CAKeyPassphrase = []byte(env("PROV_CA_PASSPHRASE", ""))
	c.AuditHMACKey = []byte(env("PROV_AUDIT_HMAC_KEY", ""))
	c.RecordingEncryptionKey = []byte(env("PROV_RECORDING_KEY", ""))
	c.RecordingAllowPlaintext = envBool("PROV_RECORDING_ALLOW_PLAINTEXT", false)
	c.AllowUnrecordedSessions = envBool("PROV_ALLOW_UNRECORDED_SESSIONS", false)
	if c.RecordingAllowPlaintext && len(c.RecordingEncryptionKey) == 0 {
		// Said once, at every start, because the choice is invisible afterwards: the
		// recordings look identical either way until somebody opens one.
		slog.Warn("session recordings are being written UNENCRYPTED",
			"reason", "PROV_RECORDING_ALLOW_PLAINTEXT=true and no PROV_RECORDING_KEY",
			"contents", "recordings hold pasted credentials and command output from privileged sessions",
			"fix", "set PROV_RECORDING_KEY to a 32-byte hex value and restart")
	}

	// External KMS / HSM backend (default "local" = no wrapping, behavior unchanged).
	c.KMSProvider = env("PROV_KMS_PROVIDER", "local")
	c.KMSKeyID = env("PROV_KMS_KEY_ID", "")
	c.KMSVaultAddr = env("PROV_KMS_VAULT_ADDR", "")
	c.KMSVaultToken = env("PROV_KMS_VAULT_TOKEN", "")
	c.KMSVaultCACertFile = env("PROV_KMS_VAULT_CACERT", "")
	c.KMSVaultTLSSkipVerify = envBool("PROV_KMS_VAULT_SKIP_VERIFY", false)
	c.KMSAWSRegion = env("PROV_KMS_AWS_REGION", "")
	c.KMSAWSAccessKey = env("PROV_KMS_AWS_ACCESS_KEY_ID", "")
	c.KMSAWSSecretKey = env("PROV_KMS_AWS_SECRET_ACCESS_KEY", "")
	c.KMSAWSSessionToken = env("PROV_KMS_AWS_SESSION_TOKEN", "")
	c.KMSAWSEndpoint = env("PROV_KMS_AWS_ENDPOINT", "")
	c.KMSAzureVaultURL = env("PROV_KMS_AZURE_VAULT_URL", "")
	c.KMSAzureTenantID = env("PROV_KMS_AZURE_TENANT_ID", "")
	c.KMSAzureClientID = env("PROV_KMS_AZURE_CLIENT_ID", "")
	c.KMSAzureClientSecret = env("PROV_KMS_AZURE_CLIENT_SECRET", "")
	c.KMSGCPCredentialsJSON = env("PROV_KMS_GCP_CREDENTIALS", "")
	c.KMSGCPCredentialsFile = env("PROV_KMS_GCP_CREDENTIALS_FILE", "")
	c.CAKeyPassphraseWrapped = env("PROV_CA_PASSPHRASE_WRAPPED", "")
	c.VaultPassphraseWrapped = env("PROV_VAULT_PASSPHRASE_WRAPPED", "")

	// External secrets manager (vault-of-record).
	c.ExtSecretVaultAddr = env("PROV_EXTSECRET_VAULT_ADDR", "")
	c.ExtSecretVaultToken = env("PROV_EXTSECRET_VAULT_TOKEN", "")
	c.ExtSecretVaultCACertFile = env("PROV_EXTSECRET_VAULT_CACERT", "")
	c.ExtSecretVaultTLSSkipVerify = envBool("PROV_EXTSECRET_VAULT_SKIP_VERIFY", false)
	c.ExtSecretAWSRegion = env("PROV_EXTSECRET_AWS_REGION", "")
	c.ExtSecretAWSAccessKey = env("PROV_EXTSECRET_AWS_ACCESS_KEY_ID", "")
	c.ExtSecretAWSSecretKey = env("PROV_EXTSECRET_AWS_SECRET_ACCESS_KEY", "")
	c.ExtSecretAWSSessionToken = env("PROV_EXTSECRET_AWS_SESSION_TOKEN", "")
	c.ExtSecretAWSEndpoint = env("PROV_EXTSECRET_AWS_ENDPOINT", "")

	// WebAuthn: derive sensible localhost defaults from the public URL.
	c.WebAuthnRPID = env("PROV_WEBAUTHN_RPID", hostOnly(c.PublicURL))
	c.WebAuthnRPName = env("PROV_WEBAUTHN_RP_NAME", "Provenance")
	if origins := env("PROV_WEBAUTHN_ORIGINS", ""); origins != "" {
		c.WebAuthnOrigins = strings.Split(origins, ",")
	} else {
		c.WebAuthnOrigins = []string{c.PublicURL, "http://localhost:5173", "http://localhost:8080"}
	}

	// Derive the overlay transport from FIPS mode when not set explicitly. WireGuard
	// has no FIPS mode, so a FIPS deployment defaults to OpenVPN.
	if c.Overlay == "" {
		if c.FIPSMode {
			c.Overlay = "openvpn"
		} else {
			c.Overlay = "wireguard"
		}
	}

	applyOverlayDefaults(c)

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// applyOverlayDefaults resolves the OpenVPN overlay's address plan.
//
// It must NOT share the WireGuard subnet on a deployment that runs both — one jump
// host, two interfaces, one /24 means the kernel picks a single winner for the whole
// subnet and every host behind the other interface goes dark.
//
// The exception is a deployment that only ever speaks OpenVPN: there is no WireGuard
// hub to collide with, and its hosts already hold addresses out of PROV_WG_SUBNET.
// Moving that pool would invalidate every enrolled address at once, so an install
// whose DEFAULT overlay is the cert overlay keeps the subnet it has unless told
// otherwise.
func applyOverlayDefaults(c *Config) {
	if c.OVPNSubnet == "" {
		// Its own subnet, ALWAYS -- including when the cert overlay is the default.
		//
		// It used to inherit the WireGuard pool in that case, to spare an install from
		// moving addresses it had already handed out. But the jump host runs the
		// WireGuard server regardless, so both overlays then terminate on it with the
		// same prefix: two connected routes for 10.100.0.0/24, the kernel picks wg0,
		// and every OpenVPN-enrolled host becomes unreachable ("No route to host")
		// while its tunnel sits there perfectly established. QA hit this on a FIPS
		// deployment -- where PROV_OVERLAY=openvpn is not a choice but a consequence,
		// since WireGuard is not an approved algorithm.
		//
		// An install that genuinely wants them to share a pool can still say so with
		// PROV_OVPN_SUBNET; it just is not what happens by accident.
		c.OVPNSubnet = "10.101.0.0/24"
	}
	if c.OVPNJumpIP == "" {
		c.OVPNJumpIP = firstHost(c.OVPNSubnet)
	}
}

// firstHost returns the first usable address of an IPv4 CIDR ("10.101.0.0/24" →
// "10.101.0.1"), which is the address the overlay's server takes on the jump host.
// Empty when the CIDR does not parse — validate() reports that.
func firstHost(cidr string) string {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipnet.IP.To4() == nil {
		return ""
	}
	ip := ipnet.IP.To4()
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]+1).String()
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
			missing = append(missing, "PROV_JWT_SECRET (>=32 bytes)")
		}
		if len(c.CSRFSecret) < 16 {
			missing = append(missing, "PROV_CSRF_SECRET (>=16 bytes)")
		}
		// The CA passphrase may be supplied plaintext (>=16 bytes) OR as a KMS-wrapped
		// blob that ResolveSecrets unwraps at boot. Accept either; the length of the
		// unwrapped value is re-checked after unwrapping in ResolveSecrets.
		if len(c.CAKeyPassphrase) < 16 && !c.caPassphraseViaKMS() {
			missing = append(missing, "PROV_CA_PASSPHRASE (>=16 bytes) or PROV_CA_PASSPHRASE_WRAPPED with PROV_KMS_PROVIDER")
		}
		// A dedicated key for the tamper-evident audit chain, held outside the DB so a
		// party with only database write access cannot forge a valid chain.
		if len(c.AuditHMACKey) < 32 {
			missing = append(missing, "PROV_AUDIT_HMAC_KEY (>=32 bytes)")
		}
		// Session recordings hold the contents of privileged sessions, so outside
		// development they are encrypted at rest or the operator says, explicitly and
		// on the record, that they should not be. Bundle upgrades generate the key
		// automatically (ConfigAdditions), so this is reached only by a deployment
		// upgraded some other way.
		if len(c.RecordingEncryptionKey) == 0 && !c.RecordingAllowPlaintext {
			missing = append(missing, "PROV_RECORDING_KEY (>=32 bytes) — or set "+
				"PROV_RECORDING_ALLOW_PLAINTEXT=true to record privileged sessions unencrypted")
		}
		// Authenticate the backend to the Ansible runner sidecar so nothing else on the
		// container network can submit playbooks (remote code execution).
		if len(c.AnsibleRunnerToken) < 16 {
			missing = append(missing, "PROV_ANSIBLE_RUNNER_TOKEN (>=16 bytes)")
		}
		// Same reasoning, one step worse: the builder runner starts *privileged*
		// containers, so anything on the container network that can reach it
		// unauthenticated is root on the host. Required only when a runner is
		// actually configured -- a deployment that never builds images should not
		// be made to invent a secret for a service it does not run.
		if c.BuilderRunnerURL != "" && len(c.BuilderRunnerToken) < 16 {
			missing = append(missing, "PROV_BUILDER_RUNNER_TOKEN (>=16 bytes)")
		}
		if len(missing) > 0 {
			return fmt.Errorf("missing required config for %q environment: %s",
				c.Environment, strings.Join(missing, ", "))
		}
		if c.SSHInsecureHostKeys {
			return fmt.Errorf("PROV_SSH_INSECURE_HOST_KEYS must not be enabled outside development")
		}
		if c.KMSVaultTLSSkipVerify {
			return fmt.Errorf("PROV_KMS_VAULT_SKIP_VERIFY must not be enabled outside development")
		}
		// A production instance still pointing at localhost.
		//
		// PublicURL defaults to https://localhost:8443 and the compose file
		// supplies http://localhost:8080, and nothing checked it. Left unset it
		// silently drives the CORS allowed origins, the WebAuthn relying-party
		// id, the OIDC redirect URI, the SAML ACS/metadata/SLO URLs, the SCIM
		// base URL and the WebSocket origin check. The server boots perfectly
		// and then single sign-on, passkeys and every terminal fail separately,
		// none of them saying why.
		//
		// Refusing at boot turns six confusing runtime failures into one
		// sentence at startup.
		if u, uerr := url.Parse(c.PublicURL); uerr != nil || u.Host == "" {
			return fmt.Errorf("PROV_PUBLIC_URL is not a valid absolute URL (%q)", c.PublicURL)
		} else if h := strings.ToLower(u.Hostname()); h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return fmt.Errorf("PROV_PUBLIC_URL is still %q in the %q environment. It is the "+
				"address browsers and identity providers are told to use, so single sign-on, "+
				"passkeys and terminal WebSockets will each fail on their own. Set it to the "+
				"URL this deployment is actually reached at", c.PublicURL, c.Environment)
		}

		// Session cookies without Secure, on a deployment that serves HTTPS.
		//
		// The Go default is true, but the compose file that `make up-single`
		// uses -- the documented single-server production path -- passes
		// ${PROV_COOKIE_SECURE:-false}, and `make env` seeds .env from an
		// example that sets it to false. So an operator who follows the boot
		// errors, sets PROV_ENV=production and gets a clean start still ends up
		// with session cookies that any network path can read, and no HSTS
		// either, since securityHeaders() keys off the same flag.
		//
		// Refused rather than warned when the public URL is https, because there
		// is no case where serving HTTPS and marking cookies insecure is what
		// somebody meant. Plain http is a different matter: a deployment behind
		// a private LAN address, which is a real way to run this, cannot set
		// Secure at all or nobody can log in. That gets a warning.
		if !c.CookieSecure {
			if strings.HasPrefix(strings.ToLower(c.PublicURL), "https://") {
				return fmt.Errorf("PROV_COOKIE_SECURE is false but PROV_PUBLIC_URL is https "+
					"(%s): session cookies would be sent without the Secure flag and no HSTS "+
					"header would be set. Set PROV_COOKIE_SECURE=true", c.PublicURL)
			}
			slog.Warn("PROV_COOKIE_SECURE is false: session cookies are sent without the " +
				"Secure flag and no HSTS header is set. That is only safe on a trusted " +
				"private network reached over plain http; anything internet-facing must " +
				"serve https and set PROV_COOKIE_SECURE=true.")
		}

		// Warn (don't fail) on an unencrypted Postgres connection. Acceptable when the
		// DB is co-located on the same Docker host (loopback/bridge), but on any
		// networked or managed Postgres this sends the DB password and every
		// at-rest-decrypted row in cleartext. Not fatal so single-host deploys still boot.
		if pgSSLDisabled(c.DatabaseURL) {
			slog.Warn("PROV_DATABASE_URL uses sslmode=disable — the Postgres connection is UNENCRYPTED. This is only safe when the database is on the same host; for any networked/managed Postgres set sslmode=verify-full with a CA.")
		}
		if len(c.RecordingEncryptionKey) != 0 && len(c.RecordingEncryptionKey) < 32 {
			return fmt.Errorf("PROV_RECORDING_KEY, when set, must be at least 32 bytes")
		}
		if len(c.RecordingEncryptionKey) == 0 {
			slog.Warn("PROV_RECORDING_KEY is unset — session recordings are stored UNENCRYPTED on disk. Set a 32+ byte key to encrypt them at rest.")
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
			ephemeral = append(ephemeral, "PROV_JWT_SECRET (ephemeral)")
		}
		if len(c.CSRFSecret) == 0 {
			c.CSRFSecret = randomSecret(32)
			ephemeral = append(ephemeral, "PROV_CSRF_SECRET (ephemeral)")
		}
		if len(c.CAKeyPassphrase) == 0 {
			// The CA key is encrypted at rest with this, so it must stay stable
			// across restarts — a random value would make a persisted dev CA
			// undecryptable. This is the one remaining fixed dev default.
			c.CAKeyPassphrase = []byte("dev-insecure-ca-passphrase-change")
			ephemeral = append(ephemeral, "PROV_CA_PASSPHRASE (fixed insecure default)")
		}
		if len(c.AuditHMACKey) == 0 {
			// Fixed (not random) so a persisted dev audit chain stays verifiable
			// across restarts, mirroring the CA passphrase rationale above.
			c.AuditHMACKey = []byte("dev-insecure-audit-hmac-key-change")
			ephemeral = append(ephemeral, "PROV_AUDIT_HMAC_KEY (fixed insecure default)")
		}
		if len(ephemeral) > 0 {
			slog.Warn("running in DEVELOPMENT mode with insecure secrets — set PROV_ENV=production and provide real secrets for any non-local deployment",
				"secrets", strings.Join(ephemeral, ", "))
		}
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("PROV_DATABASE_URL is required")
	}
	// The renewal window must sit inside the cert lifetime; otherwise every
	// EnsureHostCredential call sees a cert already "due for renewal" and re-mints
	// on every connection. Only enforced when a TTL is actually set: Load() always
	// applies non-zero defaults, so real configs are always checked; a zero TTL only
	// occurs in direct struct construction (tests) that isn't exercising cert TTLs.
	if c.UserCertTTL > 0 && c.CertRenewBefore >= c.UserCertTTL {
		return fmt.Errorf("PROV_CERT_RENEW_BEFORE (%s) must be less than PROV_USER_CERT_TTL (%s)",
			c.CertRenewBefore, c.UserCertTTL)
	}
	if err := c.validateOverlays(); err != nil {
		return err
	}
	if err := c.validateFederation(); err != nil {
		return err
	}
	return nil
}

// validateOverlays checks the two overlays' address plans. A malformed plan is
// fatal; overlapping plans are only fatal when the deployment can actually run both
// transports, because a single-overlay install legitimately has them equal (see the
// defaulting in Load).
func (c *Config) validateOverlays() error {
	// Skipped for zero-value configs built directly in tests, which set no subnets.
	if c.OVPNSubnet == "" && c.WGSubnet == "" {
		return nil
	}
	_, ovpnNet, err := net.ParseCIDR(strings.TrimSpace(c.OVPNSubnet))
	if err != nil {
		return fmt.Errorf("PROV_OVPN_SUBNET %q is not a valid CIDR: %w", c.OVPNSubnet, err)
	}
	if ip := net.ParseIP(strings.TrimSpace(c.OVPNJumpIP)); ip == nil || !ovpnNet.Contains(ip) {
		return fmt.Errorf("PROV_OVPN_JUMP_IP %q must be an address inside PROV_OVPN_SUBNET %s",
			c.OVPNJumpIP, c.OVPNSubnet)
	}
	_, wgNet, err := net.ParseCIDR(strings.TrimSpace(c.WGSubnet))
	if err != nil {
		return fmt.Errorf("PROV_WG_SUBNET %q is not a valid CIDR: %w", c.WGSubnet, err)
	}
	// Equal plans are allowed but not silent. "This deployment speaks one overlay" is
	// the shape an existing OpenVPN-only install keeps, and it works only if the
	// WireGuard server really is absent. In the stack this project ships it is not:
	// the jump host runs it regardless, so both overlays terminate there with the same
	// prefix, the kernel routes the shared subnet to wg0, and every host on the cert
	// overlay is unreachable while its tunnel looks perfectly healthy. QA lost an
	// afternoon to it on a FIPS deployment, where the cert overlay is not a choice.
	//
	// Partial overlap is never intentional and would hand out addresses from one pool
	// that route into the other.
	if c.OVPNSubnet == c.WGSubnet {
		log.Printf("WARN PROV_OVPN_SUBNET and PROV_WG_SUBNET are both %s. Both overlays "+
			"terminate on the jump host, so it will hold two connected routes for that "+
			"prefix and hosts on the OpenVPN overlay may be unreachable even with a "+
			"healthy tunnel. Give the cert overlay its own subnet (default 10.101.0.0/24) "+
			"unless this deployment genuinely runs no WireGuard server.", c.OVPNSubnet)
		return nil
	}
	if wgNet.Contains(ovpnNet.IP) || ovpnNet.Contains(wgNet.IP) {
		return fmt.Errorf(
			"PROV_OVPN_SUBNET %s overlaps PROV_WG_SUBNET %s — the two overlays terminate on the same "+
				"jump host and each puts its own address on its interface, so overlapping pools leave one "+
				"transport's hosts unreachable. Give the OpenVPN overlay its own subnet",
			c.OVPNSubnet, c.WGSubnet)
	}
	return nil
}

// validateFederation checks the multi-site federation settings. Standalone (the
// default) requires nothing and leaves every other check untouched.
func (c *Config) validateFederation() error {
	switch c.Mode {
	case "", "standalone":
		c.Mode = "standalone"
		return nil
	case "hub", "site":
		// ok
	default:
		return fmt.Errorf("PROV_MODE must be standalone, hub, or site (got %q)", c.Mode)
	}
	// Federation crosses a trust boundary between instances, so it must not run on
	// the insecure development defaults (ephemeral JWT, publicly-known CA passphrase).
	if c.Environment == "development" {
		return fmt.Errorf("PROV_MODE=%s requires PROV_ENV=production (or staging) with real secrets", c.Mode)
	}
	if c.FederationTransport == "" {
		c.FederationTransport = "wss"
	}
	if c.FederationTransport != "wss" && c.FederationTransport != "wireguard" {
		return fmt.Errorf("PROV_FEDERATION_TRANSPORT must be wss or wireguard (got %q)", c.FederationTransport)
	}
	if c.Mode == "site" {
		if c.HubURL == "" {
			return fmt.Errorf("PROV_MODE=site requires PROV_HUB_URL")
		}
		// A site refuses to enter managed mode without a pinned hub key: on the
		// very first join the fingerprint is learned and persisted, but a join
		// token must then be present to establish that trust.
		if c.HubKeyFingerprint == "" && c.HubJoinToken == "" {
			return fmt.Errorf("PROV_MODE=site requires PROV_HUB_JOIN_TOKEN (first join) or PROV_HUB_KEY_FINGERPRINT (subsequent boots)")
		}
	}
	return nil
}

// IsStandalone reports the default single-instance mode (no federation).
func (c *Config) IsStandalone() bool { return c.Mode == "" || c.Mode == "standalone" }

// IsHub reports whether this instance aggregates and manages remote sites.
func (c *Config) IsHub() bool { return c.Mode == "hub" }

// IsSite reports whether this instance dials out to and is managed by a hub.
func (c *Config) IsSite() bool { return c.Mode == "site" }

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

// pgSSLDisabled reports whether a Postgres connection string explicitly disables TLS
// (sslmode=disable). Absent an sslmode, libpq/pgx negotiate TLS if the server offers
// it, so only an explicit disable is flagged.
func pgSSLDisabled(dbURL string) bool {
	return strings.Contains(strings.ToLower(dbURL), "sslmode=disable")
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
			return nil, fmt.Errorf("PROV_VAULT_PASSPHRASE must differ from PROV_CA_PASSPHRASE")
		}
		return []byte(c.VaultPassphrase), nil
	}
	if c.IsProduction() {
		return nil, fmt.Errorf("PROV_VAULT_PASSPHRASE is required in production to use the credential vault")
	}
	return c.CAKeyPassphrase, nil
}

// KMS builds the KMS provider configuration from the resolved environment.
func (c *Config) KMS() kms.Config {
	return kms.Config{
		Provider:           c.KMSProvider,
		KeyID:              c.KMSKeyID,
		VaultAddr:          c.KMSVaultAddr,
		VaultToken:         c.KMSVaultToken,
		VaultCACertFile:    c.KMSVaultCACertFile,
		VaultTLSSkipVerify: c.KMSVaultTLSSkipVerify,
		AWSRegion:          c.KMSAWSRegion,
		AWSAccessKey:       c.KMSAWSAccessKey,
		AWSSecretKey:       c.KMSAWSSecretKey,
		AWSSessionToken:    c.KMSAWSSessionToken,
		AWSEndpoint:        c.KMSAWSEndpoint,
		AzureVaultURL:      c.KMSAzureVaultURL,
		AzureTenantID:      c.KMSAzureTenantID,
		AzureClientID:      c.KMSAzureClientID,
		AzureClientSecret:  c.KMSAzureClientSecret,
		GCPCredentialsJSON: c.KMSGCPCredentialsJSON,
		GCPCredentialsFile: c.KMSGCPCredentialsFile,
	}
}

// KMSEnabled reports whether an external KMS/HSM backend is configured.
func (c *Config) KMSEnabled() bool { return c.KMS().ProviderConfigured() }

// extSecretOverlay supplies the operator-configured connection from the settings
// table, when one has been saved. It is a hook rather than a direct store read
// because Config is constructed before the database exists, and because every caller
// of ExtSecret() -- the monitor, the terminal, SFTP, playbooks, winscripts, imaging --
// already has a *Config and none of them should have to learn about settings.
var extSecretOverlay func() extsecret.Config

// SetExtSecretOverlay installs the settings-backed source of the external
// secrets-manager connection. Called once, after the store exists.
func SetExtSecretOverlay(f func() extsecret.Config) { extSecretOverlay = f }

// ExtSecret builds the external secrets-manager configuration.
//
// The environment is the baseline and the saved settings are layered over it FIELD BY
// FIELD, with a non-empty saved value winning. Per-field rather than
// whole-object, because an operator who sets only the address in the UI has not
// thereby unset the token their .env supplies -- and a deployment that predates the
// settings screen has no row at all, which must keep working exactly as it did.
func (c *Config) ExtSecret() extsecret.Config {
	base := extsecret.Config{
		VaultAddr:          c.ExtSecretVaultAddr,
		VaultToken:         c.ExtSecretVaultToken,
		VaultCACertFile:    c.ExtSecretVaultCACertFile,
		VaultTLSSkipVerify: c.ExtSecretVaultTLSSkipVerify,
		AWSRegion:          c.ExtSecretAWSRegion,
		AWSAccessKey:       c.ExtSecretAWSAccessKey,
		AWSSecretKey:       c.ExtSecretAWSSecretKey,
		AWSSessionToken:    c.ExtSecretAWSSessionToken,
		AWSEndpoint:        c.ExtSecretAWSEndpoint,
	}
	if extSecretOverlay == nil {
		return base
	}
	return MergeExtSecret(base, extSecretOverlay())
}

// MergeExtSecret layers `over` on top of `base`, field by field. Exported so the
// precedence can be tested without a database.
//
// TLSSkipVerify is deliberately OR-ed rather than overwritten: it is a bool, so
// "false" is indistinguishable from "not set", and silently turning OFF a
// verification bypass that the environment asked for would change how a connection is
// authenticated without anyone saying so. Turning it on is explicit either way.
func MergeExtSecret(base, over extsecret.Config) extsecret.Config {
	pick := func(a, b string) string {
		if strings.TrimSpace(b) != "" {
			return b
		}
		return a
	}
	return extsecret.Config{
		VaultAddr:          pick(base.VaultAddr, over.VaultAddr),
		VaultToken:         pick(base.VaultToken, over.VaultToken),
		VaultCACertFile:    pick(base.VaultCACertFile, over.VaultCACertFile),
		VaultCACertPEM:     pick(base.VaultCACertPEM, over.VaultCACertPEM),
		VaultTLSSkipVerify: base.VaultTLSSkipVerify || over.VaultTLSSkipVerify,
		AWSRegion:          pick(base.AWSRegion, over.AWSRegion),
		AWSAccessKey:       pick(base.AWSAccessKey, over.AWSAccessKey),
		AWSSecretKey:       pick(base.AWSSecretKey, over.AWSSecretKey),
		AWSSessionToken:    pick(base.AWSSessionToken, over.AWSSessionToken),
		AWSEndpoint:        pick(base.AWSEndpoint, over.AWSEndpoint),
	}
}

// ExtSecretEnabled reports whether an external secrets manager is configured.
func (c *Config) ExtSecretEnabled() bool { return c.ExtSecret().Configured() }

// caPassphraseViaKMS reports whether the CA passphrase is provided as a KMS-wrapped
// blob rather than plaintext.
func (c *Config) caPassphraseViaKMS() bool {
	return c.KMSEnabled() && c.CAKeyPassphraseWrapped != ""
}

// ResolveSecrets unwraps any KMS-wrapped master passphrases into their plaintext
// fields via the configured external KMS. It must run once at startup — after Load,
// before the CA or credential vault is used — for both provd and provctl. With the
// default "local" provider (or no wrapped values) it is a no-op, so non-KMS
// deployments are unaffected. After unwrapping it re-checks the invariants Load could
// not (unwrapped length, CA/vault distinctness), failing closed on a bad key.
func (c *Config) ResolveSecrets(ctx context.Context) error {
	if !c.KMSEnabled() {
		return nil
	}
	if c.CAKeyPassphraseWrapped == "" && c.VaultPassphraseWrapped == "" {
		return nil // provider set but nothing wrapped (e.g. only used via provctl kms)
	}
	prov, err := kms.New(c.KMS())
	if err != nil {
		return err
	}
	if c.CAKeyPassphraseWrapped != "" {
		pt, err := prov.Unwrap(ctx, c.CAKeyPassphraseWrapped)
		if err != nil {
			return fmt.Errorf("unwrap CA passphrase via %s KMS: %w", prov.Name(), err)
		}
		c.CAKeyPassphrase = pt
	}
	if c.VaultPassphraseWrapped != "" {
		pt, err := prov.Unwrap(ctx, c.VaultPassphraseWrapped)
		if err != nil {
			return fmt.Errorf("unwrap vault passphrase via %s KMS: %w", prov.Name(), err)
		}
		c.VaultPassphrase = string(pt)
	}
	// Post-unwrap invariants (Load ran before the plaintext existed).
	if c.IsProduction() {
		if len(c.CAKeyPassphrase) < 16 {
			return fmt.Errorf("unwrapped PROV_CA_PASSPHRASE is shorter than 16 bytes")
		}
		if c.VaultPassphrase != "" && c.VaultPassphrase == string(c.CAKeyPassphrase) {
			return fmt.Errorf("PROV_VAULT_PASSPHRASE must differ from PROV_CA_PASSPHRASE")
		}
	}
	return nil
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

// legacyEnvPrefix is the environment prefix this product used before it was
// called Provenance. Settings were never renamed across the earlier rebrands
// precisely because renaming them breaks running deployments; this rename does
// change them, so the old prefix has to keep working for a while.
//
// docs/compatibility.md promises a deprecated setting keeps working for at least
// two minor releases and warns, naming its replacement. LookupEnv is the half of
// that promise the code keeps: every one of the ~187 settings reads through it.
const (
	envPrefix       = "PROV_"
	legacyEnvPrefix = "FLEET_"
)

// legacyEnvSeen records which old-prefix settings were actually read, so the boot
// warning can name them. A setting nobody sets is not worth a line in anyone's logs.
var (
	legacyEnvMu   sync.Mutex
	legacyEnvSeen = map[string]string{} // old name -> new name
)

// LookupEnv resolves a PROV_ setting, falling back to the FLEET_ name it used to
// have. The new name wins whenever it is set, so an operator who has migrated
// their .env is never second-guessed by a leftover variable.
//
// An empty value counts as unset, matching the original behaviour: compose writes
// `PROV_FOO: ${PROV_FOO:-}` for optional settings, so an unset variable arrives as
// an empty string rather than being absent.
func LookupEnv(key string) (string, bool) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v, true
	}
	legacy, ok := legacyName(key)
	if !ok {
		return "", false
	}
	v, ok := os.LookupEnv(legacy)
	if !ok || v == "" {
		return "", false
	}
	legacyEnvMu.Lock()
	legacyEnvSeen[legacy] = key
	legacyEnvMu.Unlock()
	return v, true
}

// legacyName maps a current setting name to the one it replaced. Only the prefix
// changed, so anything not carrying the current prefix has no legacy spelling.
func legacyName(key string) (string, bool) {
	suffix, ok := strings.CutPrefix(key, envPrefix)
	if !ok {
		return "", false
	}
	return legacyEnvPrefix + suffix, true
}

// LegacyEnvInUse returns the old-prefix settings that were read, mapped to the
// names that replaced them, so a caller can warn once with the whole list.
func LegacyEnvInUse() map[string]string {
	legacyEnvMu.Lock()
	defer legacyEnvMu.Unlock()
	out := make(map[string]string, len(legacyEnvSeen))
	for k, v := range legacyEnvSeen {
		out[k] = v
	}
	return out
}

func env(key, def string) string {
	if v, ok := LookupEnv(key); ok {
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
	if v := splitList(env("PROV_TRUSTED_PROXIES", "")); len(v) > 0 {
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
	if v, ok := LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, ok := LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
