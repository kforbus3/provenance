// Package app defines the shared dependency container passed to every HTTP
// module. Modules depend only on this struct (and leaf packages like store /
// models), which keeps wiring mechanical and avoids import cycles.
package app

import (
	"context"
	"log/slog"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/livesessions"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/store"
)

// Deps is the application's shared service container.
type Deps struct {
	Store *store.Store
	Cfg   *config.Config
	Log   *slog.Logger
	Auth  *auth.Service
	Live  *livesessions.Registry

	// Notify delivers outbound alerts (email/webhook). Handlers call it on
	// notable events (e.g. a new approval request).
	Notify *notify.Service

	// SSH services are populated once the gateway/CA are constructed. Modules
	// that need them (terminal, sftp, enrollment, monitor) read these fields.
	CA      CAIssuer
	Gateway Dialer

	// Events fans out real-time updates (host status, session start/end) to
	// connected dashboards over the WebSocket hub.
	Events Broadcaster

	// DistributeKRL pushes the current certificate revocation list to all enrolled
	// hosts immediately (set by the server). Returns the number of hosts updated.
	DistributeKRL func(ctx context.Context) (int, error)
}

// Broadcaster pushes a typed real-time event to all connected clients. The
// concrete implementation is internal/ws.Hub.
type Broadcaster interface {
	Broadcast(eventType string, data any)
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
}
