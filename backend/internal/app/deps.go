// Package app defines the shared dependency container passed to every HTTP
// module. Modules depend only on this struct (and leaf packages like store /
// models), which keeps wiring mechanical and avoids import cycles.
package app

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/accesspolicy"
	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/livesessions"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/store"
)

// Deps is the application's shared service container.
type Deps struct {
	Store   *store.Store
	Cfg     *config.Config
	Log     *slog.Logger
	Version string // running fleetd build (for a federation site to report to its hub)
	Auth    *auth.Service
	Live    *livesessions.Registry
	Watch   *livesessions.Broker // fans out live terminal output to read-only watchers

	// Notify delivers outbound alerts (email/webhook). Handlers call it on
	// notable events (e.g. a new approval request).
	Notify *notify.Service

	// AccessPolicy enforces attribute-based access-control (ABAC) deny rules at
	// connect time, on top of RBAC. Interactive connect surfaces (terminal, RDP,
	// SFTP) and the ad-hoc command runner consult it after the host-access check.
	AccessPolicy *accesspolicy.Enforcer

	// SSH services are populated once the gateway/CA are constructed. Modules
	// that need them (terminal, sftp, enrollment, monitor) read these fields.
	CA      CAIssuer
	Gateway Dialer

	// Events fans out real-time updates (host status, session start/end) to
	// connected dashboards over the WebSocket hub.
	Events Broadcaster

	// DistributeKRL pushes the current certificate revocation list to all enrolled
	// hosts immediately (set by the server). Returns the number of hosts where the
	// KRL was verified installed, and the number where it was not — a host in the
	// second count still honors the certificates that were just revoked, so callers
	// must surface it rather than report distribution as complete.
	DistributeKRL func(ctx context.Context) (pushed, failed int, err error)

	// ForgetHostKeys drops cached SSH host-key pins for the given dial identities
	// (set by the server; nil in tests). Deleting the ssh_host_keys rows is not
	// enough on its own — the gateway caches each pin per process, so a running
	// backend keeps refusing the new key until this clears the cache too.
	ForgetHostKeys func(ids ...string)

	// CleanupHostOverlay retires a deleted host's overlay membership on the jump
	// host — a WireGuard peer or a certificate overlay's pinned address, whichever
	// the host was on (set by the server; nil in tests). Best-effort: deletion
	// succeeds even when the jump host is unreachable — enrollment retires stale
	// claims inline when the address is reused.
	CleanupHostOverlay func(ctx context.Context, host *models.Host) error

	// TeardownHost removes Fleet's footprint from a managed host — the NOPASSWD
	// sudoers grant, both shared accounts, the CA trust, the principal files and the
	// sshd drop-in (set by the server; nil in tests). Opt-in per delete: it is
	// destructive to the machine and, if Fleet was its only administrative access,
	// locks the operator out.
	//
	// Must be called BEFORE CleanupHostOverlay, which removes the route the teardown
	// travels over. Returns nil once the teardown has STARTED — the work runs
	// detached on the host, because it deletes the account the session is using.
	TeardownHost func(ctx context.Context, host *models.Host) error
}

// Broadcaster pushes a typed real-time event to connected clients. The concrete
// implementation is internal/ws.Hub.
type Broadcaster interface {
	// Broadcast fans an event out to every connected client (e.g. host status).
	Broadcast(eventType string, data any)
	// BroadcastSession fans a session-activity event out only to clients that may
	// see it: the session's own user, plus clients holding Session.Replay (who can
	// already list all sessions). This keeps one user's activity from leaking to
	// every other authenticated dashboard.
	BroadcastSession(eventType string, userID uuid.UUID, data any)
}

// CAIssuer issues and manages ephemeral SSH user certificates. The concrete
// implementation lives in internal/ca + internal/identity.
type CAIssuer interface {
	// IssueForSession mints an ephemeral keypair + signed user certificate bound
	// to a browser session, returning an opaque handle id for later lookup.
	IssueForSession(sessionID, userID, username string, principals []string) (handle string, err error)
}

// Dialer opens an SSH connection to a managed host through the jump host. The
// concrete implementation lives in internal/sshgw.
type Dialer interface {
	// DialHost establishes an SSH client connection to host:port via the jump
	// host using the session's ephemeral credentials referenced by handle.
	DialHost(handle, host string, port int, user string) (any, error)
	// HostCredentialSerial returns the serial of the per-host certificate bound
	// to a (session, host) pair, so it can be revoked when access is removed.
	HostCredentialSerial(sessionID, hostID uuid.UUID) (uint64, bool)
}
