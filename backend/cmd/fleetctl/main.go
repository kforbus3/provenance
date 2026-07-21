// Command fleetctl is the offline administrative CLI for Fleet Terminal. It
// connects directly to the database (using the same FLEET_DATABASE_URL) and is
// the documented out-of-band recovery path — e.g. restoring access when every
// administrator is locked out, resetting MFA, or rotating the CA.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/ca"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/db"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `fleetctl — Fleet Terminal offline admin CLI

Usage:
  fleetctl create-admin <username> <password> [email]   Create a Super Administrator (recovery)
  fleetctl reset-mfa <username>                          Remove all of a user's MFA factors
  fleetctl enable-user <username>                        Re-enable and unlock a disabled account
  fleetctl rotate-ca                                     Generate a new active user CA
  fleetctl list-users                                    List accounts
  fleetctl wg-peers                                      Print overlay [Peer] stanzas for standby jump-host failover

Reads FLEET_DATABASE_URL (and FLEET_CA_PASSPHRASE for rotate-ca) from the environment.
`)
}

func run(cmd string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// The recovery CLI operates across all tenants; pass multiTenancy=false so its
	// connections always bypass row-level security regardless of the deployment flag.
	pool, err := db.Connect(ctx, cfg.DatabaseURL, 4, 1, false)
	if err != nil {
		return err
	}
	defer pool.Close()
	st := store.New(pool)

	switch cmd {
	case "create-admin":
		if len(args) < 2 {
			return fmt.Errorf("usage: fleetctl create-admin <username> <password> [email]")
		}
		email := ""
		if len(args) >= 3 {
			email = args[2]
		}
		if err := auth.DefaultPolicy.Validate(args[1]); err != nil {
			return err
		}
		hash, err := auth.HashPassword(args[1])
		if err != nil {
			return err
		}
		u, err := st.CreateUser(ctx, store.CreateUserParams{
			Username: args[0], Email: email, DisplayName: args[0],
			PasswordHash: hash, IsSuperAdmin: true,
		})
		if err != nil {
			return err
		}
		_ = st.AssignRoleByName(ctx, u.ID, "Super Administrator")
		_, _ = st.AppendAudit(ctx, models.AuditEvent{
			ActorName: "fleetctl", Action: "recovery.create_admin",
			TargetKind: "user", TargetID: u.ID.String(),
			Detail: map[string]any{"username": u.Username},
		})
		fmt.Printf("created super administrator %q (%s)\n", u.Username, u.ID)

	case "reset-mfa":
		if len(args) < 1 {
			return fmt.Errorf("usage: fleetctl reset-mfa <username>")
		}
		u, err := st.GetUserByUsername(ctx, args[0])
		if err != nil {
			return err
		}
		if err := st.ResetUserMFA(ctx, u.ID); err != nil {
			return err
		}
		_, _ = st.AppendAudit(ctx, models.AuditEvent{
			ActorName: "fleetctl", Action: "recovery.reset_mfa",
			TargetKind: "user", TargetID: u.ID.String(),
		})
		fmt.Printf("reset MFA for %q\n", u.Username)

	case "enable-user":
		if len(args) < 1 {
			return fmt.Errorf("usage: fleetctl enable-user <username>")
		}
		u, err := st.GetUserByUsername(ctx, args[0])
		if err != nil {
			return err
		}
		if err := st.SetDisabled(ctx, u.ID, false); err != nil {
			return err
		}
		if err := st.Unlock(ctx, u.ID); err != nil {
			return err
		}
		fmt.Printf("enabled and unlocked %q\n", u.Username)

	case "rotate-ca":
		caMgr := ca.New(st, cfg)
		if err := caMgr.EnsureUserCA(ctx); err != nil {
			return err
		}
		if err := caMgr.Rotate(ctx); err != nil {
			return err
		}
		fmt.Printf("rotated user CA; new active id %s\n", caMgr.ActiveID())

	case "list-users":
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		for _, u := range users {
			flags := ""
			if u.IsSuperAdmin {
				flags += " [super]"
			}
			if u.IsDisabled {
				flags += " [disabled]"
			}
			fmt.Printf("%-24s %s%s\n", u.Username, u.ID, flags)
		}

	case "wg-peers":
		// Emit the overlay peer list from Postgres as WireGuard [Peer] stanzas, so a
		// STANDBY jump host can rebuild the hub on failover (HA). Endpoint-free: peers
		// roam and dial in, so the hub never needs their Endpoint. Apply on the
		// standby with `wg addconf <iface> <(fleetctl wg-peers)` after restoring the
		// replicated hub private key. See docs/high-availability.md.
		peers, err := st.ListWGPeers(ctx)
		if err != nil {
			return err
		}
		for _, p := range peers {
			fmt.Printf("# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n\n", p.Hostname, p.PublicKey, p.Address)
		}
		fmt.Fprintf(os.Stderr, "emitted %d overlay peer(s)\n", len(peers))

	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}
