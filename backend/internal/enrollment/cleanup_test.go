package enrollment

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

// THE BUG THIS PINS DOWN: CleanupHostOverlay dialed the jump host with
// DialDirect(ctx, uuid.New().String(), ...) — a session id generated on the spot,
// which by construction has no credential in the identity vault. Every call failed
// the vault lookup before a packet was sent, so the jump-host half of the cleanup
// NEVER ran: a deleted host kept its peer on the hub and its tunnel kept handshaking.
// It is called from a goroutine that only logs a warning, so nothing surfaced.
//
// The distinguishing evidence is the error itself. On the broken path the dial fails
// inside the vault lookup ("no live credential for session"); on the fixed path it
// reaches the system-certificate issuer. This asserts the failure is the issuer's,
// which is only reachable once the session-credential path is gone.
func TestCleanupHostOverlayDoesNotUseASessionCredential(t *testing.T) {
	// A gateway with no issuer and no vault: whichever path CleanupHostOverlay takes,
	// it fails — the question is WHERE.
	gw := sshgw.New(&config.Config{JumpHost: "jump.invalid:22", JumpUser: "fleet"}, nil, nil, nil, nil)
	svc := &Service{cfg: &config.Config{JumpHost: "jump.invalid:22", JumpUser: "fleet"}, gw: gw}

	err := svc.CleanupHostOverlay(context.Background(), &models.Host{
		ID: uuid.New(), Hostname: "web-01", WGAddress: "10.100.0.7",
	})
	if err == nil {
		t.Fatal("expected a failure from a gateway with no issuer")
	}
	if strings.Contains(err.Error(), "no live credential for session") {
		t.Fatalf("CleanupHostOverlay is still dialing with a session credential it cannot have: %v", err)
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected the system-certificate path, got: %v", err)
	}
}

// A nil host is not an error — the delete handler reads the row before deleting it
// and may have found nothing.
func TestCleanupHostOverlayIgnoresANilHost(t *testing.T) {
	if err := (&Service{cfg: &config.Config{}}).CleanupHostOverlay(context.Background(), nil); err != nil {
		t.Errorf("nil host should be a no-op, got %v", err)
	}
}
