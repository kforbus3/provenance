// Command fleetctl is the offline administrative CLI for Fleet Terminal. It
// connects directly to the database (using the same FLEET_DATABASE_URL) and is
// the documented out-of-band recovery path — e.g. restoring access when every
// administrator is locked out, resetting MFA, or rotating the CA.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/ca"
	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/cryptoprofile"
	"github.com/fleet-terminal/backend/internal/db"
	"github.com/fleet-terminal/backend/internal/kms"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
	"github.com/fleet-terminal/backend/internal/overlaypki"
	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/store"
	"github.com/fleet-terminal/backend/internal/vault"
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
  fleetctl fips check                                    Report FIPS readiness (module, CA key type, password KDFs)
  fleetctl fips reseal-secrets                            Re-seal all at-rest secrets to the FIPS (PBKDF2) envelope
  fleetctl fips flag-stale-passwords                     Force non-FIPS local passwords to change (re-hash) on next login
  fleetctl kms status                                    Report the configured external KMS/HSM backend and its health
  fleetctl kms wrap [value]                              Wrap a passphrase with the external KMS (reads stdin if no value)
  fleetctl kms unwrap <token>                            Unwrap a KMS blob to verify it (prints the plaintext)

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

	// KMS operations are pure crypto calls to the external backend and need no
	// database, so dispatch them before connecting (the default DATABASE_URL only
	// resolves inside the compose network).
	if cmd == "kms" {
		return runKMS(ctx, cfg, args)
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

	case "fips":
		sub := ""
		if len(args) > 0 {
			sub = args[0]
		}
		switch sub {
		case "check":
			return fipsCheck(ctx, pool, cfg)
		case "reseal-secrets":
			return fipsReseal(st, cfg)
		case "flag-stale-passwords":
			n, err := st.FlagNonFIPSPasswords(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("flagged %d local account(s) with a non-FIPS password hash to change on next login\n", n)
			return nil
		default:
			return fmt.Errorf("usage: fleetctl fips check | reseal-secrets | flag-stale-passwords")
		}

	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// runKMS handles the external-KMS subcommands (status / wrap / unwrap). These operate
// only against the configured KMS backend and never touch the database. An operator
// uses `wrap` once to convert a plaintext passphrase into the KMS-wrapped blob stored
// in FLEET_CA_PASSPHRASE_WRAPPED / FLEET_VAULT_PASSPHRASE_WRAPPED.
func runKMS(ctx context.Context, cfg *config.Config, args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	if !cfg.KMSEnabled() && sub != "status" {
		return fmt.Errorf("no external KMS configured — set FLEET_KMS_PROVIDER (vault-transit|aws-kms) and the backend settings")
	}
	prov, err := kms.New(cfg.KMS())
	if err != nil {
		return err
	}

	switch sub {
	case "status":
		fmt.Println("Fleet Terminal — external KMS status")
		fmt.Println("====================================")
		fmt.Printf("  Provider              : %s\n", cfg.KMSProvider)
		fmt.Printf("  Key ID                : %s\n", orNone(cfg.KMSKeyID))
		fmt.Printf("  CA passphrase wrapped : %v\n", cfg.CAKeyPassphraseWrapped != "")
		fmt.Printf("  Vault passphrase wrap : %v\n", cfg.VaultPassphraseWrapped != "")
		if !cfg.KMSEnabled() {
			fmt.Println("  Health                : n/a (local provider — no external KMS)")
			return nil
		}
		if err := prov.Health(ctx); err != nil {
			fmt.Printf("  Health                : UNHEALTHY — %v\n", err)
			return err
		}
		fmt.Println("  Health                : OK")
		return nil

	case "wrap":
		var value []byte
		if len(args) >= 2 {
			value = []byte(args[1])
		} else {
			// Read the secret from stdin so it isn't captured in shell history/argv.
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if err != nil {
				return err
			}
			value = []byte(strings.TrimRight(string(b), "\r\n"))
		}
		if len(value) == 0 {
			return fmt.Errorf("nothing to wrap (pass a value or pipe it on stdin)")
		}
		token, err := prov.Wrap(ctx, value)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil

	case "unwrap":
		if len(args) < 2 {
			return fmt.Errorf("usage: fleetctl kms unwrap <token>")
		}
		pt, err := prov.Unwrap(ctx, args[1])
		if err != nil {
			return err
		}
		os.Stdout.Write(pt)
		fmt.Println()
		return nil

	default:
		return fmt.Errorf("usage: fleetctl kms status | wrap [value] | unwrap <token>")
	}
}

// fipsCheck prints a FIPS readiness report: the module/runtime status, config, the
// active CA key type, and password-hash algorithm counts, plus a ready/not-ready
// verdict for flipping FLEET_FIPS_MODE=true. Read-only.
func fipsCheck(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) error {
	ok := func(b bool) string {
		if b {
			return "OK"
		}
		return "NOT-FIPS"
	}

	fmt.Println("Fleet Terminal — FIPS readiness report")
	fmt.Println("======================================")
	fmt.Printf("  Config FLEET_FIPS_MODE : %v\n", cfg.FIPSMode)
	fmt.Printf("  Config FLEET_OVERLAY   : %s   [%s]\n", cfg.Overlay, ok(cfg.Overlay != "wireguard"))
	fmt.Printf("  Go FIPS module active  : %v   [%s]\n", cryptoprofile.ModuleActive(), ok(cryptoprofile.ModuleActive()))

	var caAlgo string
	_ = pool.QueryRow(ctx, `SELECT algo FROM ca_keys WHERE kind='user' AND active=true ORDER BY created_at DESC LIMIT 1`).Scan(&caAlgo)
	caOK := caAlgo != "" && !strings.Contains(caAlgo, "ed25519")
	fmt.Printf("  Active user CA key     : %s   [%s]\n", orNone(caAlgo), ok(caOK))

	rows, err := pool.Query(ctx, `SELECT split_part(password_hash,'$',2) AS alg, count(*) FROM user_credentials GROUP BY 1 ORDER BY 1`)
	if err == nil {
		fmt.Println("  Password hashes by algorithm:")
		anyArgon := false
		for rows.Next() {
			var alg string
			var n int
			if rows.Scan(&alg, &n) == nil {
				fipsAlg := alg == "pbkdf2-sha256"
				if !fipsAlg {
					anyArgon = true
				}
				fmt.Printf("      %-14s : %d   [%s]\n", orNone(alg), n, ok(fipsAlg))
			}
		}
		rows.Close()
		_ = anyArgon
	}

	// MFA factors: TOTP secrets re-seal with the other at-rest secrets, but a WebAuthn
	// passkey registered before FIPS may use an EdDSA (Ed25519) COSE key, which FIPS
	// forbids — that can't be told from the sealed blob here, so we surface the count
	// and advise re-registration rather than assert compliance.
	var totpN, webauthnN int
	_ = pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE kind='totp' AND confirmed),
		count(*) FILTER (WHERE kind='webauthn' AND confirmed) FROM mfa_methods`).Scan(&totpN, &webauthnN)
	fmt.Printf("  MFA factors            : %d TOTP, %d WebAuthn\n", totpN, webauthnN)
	if webauthnN > 0 {
		fmt.Println("      note: WebAuthn passkeys registered before FIPS may use EdDSA (not")
		fmt.Println("            FIPS-approved). Have those users re-register a passkey under FIPS")
		fmt.Println("            (new registrations are restricted to ES256/RS256).")
	}

	fmt.Println("--------------------------------------")
	ready := cryptoprofile.ModuleActive() && caOK && cfg.Overlay != "wireguard"
	if ready {
		fmt.Println("  VERDICT: core artifacts are FIPS-approved. Note: this report does not")
		fmt.Println("           scan every at-rest secret's KDF or the running overlay — see")
		fmt.Println("           docs/fips-mode-plan.md for the full M0–M6 migration.")
	} else {
		fmt.Println("  VERDICT: NOT ready to enable FIPS. Address the [NOT-FIPS] items above")
		fmt.Println("           (CA migration, OpenVPN overlay, GOFIPS140 binary). See")
		fmt.Println("           docs/fips-mode-plan.md.")
	}
	return nil
}

// fipsReseal re-seals every at-rest secret Fleet holds to the FIPS (PBKDF2 / v3)
// envelope, in place, without needing any secret re-entered. It targets the FIPS
// profile unconditionally — you run this DURING migration, before flipping
// FLEET_FIPS_MODE=true (M4). Every re-seal verifies the new envelope decrypts to the
// identical plaintext before overwriting, and values already on the target profile are
// left untouched, so it is safe and idempotent. Password hashes are NOT covered here:
// they upgrade on next login (verify-then-upgrade); MFA/WebAuthn re-enroll as needed.
func fipsReseal(st *store.Store, cfg *config.Config) error {
	// Re-KDF work (argon2 open + 600k-iter PBKDF2 seal) is slow per secret, so give the
	// sweep a generous budget independent of the CLI's default 30s.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// The whole point of the command is to prepare for FIPS, so target v3 regardless of
	// the current mode. v3 is readable by every build, so this is safe pre-flip.
	secretbox.SetFIPS(true)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	total := 0
	report := func(name string, n int, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("  %-22s %d re-sealed\n", name, n)
		total += n
		return nil
	}
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	fmt.Println("Re-sealing at-rest secrets to the FIPS (PBKDF2) envelope…")

	changed, err := ca.New(st, cfg).ResealActiveKey(ctx)
	if err := report("user CA key", b2i(changed), err); err != nil {
		return err
	}

	if _, gerr := st.GetActiveOverlayCA(ctx); gerr == nil {
		changed, err := overlaypki.New(st, cfg).ResealCA(ctx)
		if err := report("overlay CA key", b2i(changed), err); err != nil {
			return err
		}
	}

	nn, err := notify.New(st, cfg, log).ResealSecrets(ctx)
	if err := report("notification secrets", nn, err); err != nil {
		return err
	}

	an, err := auth.NewService(st, cfg, log).ResealSecrets(ctx)
	if err := report("LDAP/OIDC secrets", an, err); err != nil {
		return err
	}

	if key, verr := cfg.VaultKey(); verr == nil {
		vn, err := vault.ResealSecrets(ctx, st, key)
		if err := report("vault entries", vn, err); err != nil {
			return err
		}
	} else {
		fmt.Printf("  %-22s skipped (%v)\n", "vault entries", verr)
	}

	fmt.Printf("Done — %d secret(s) upgraded to PBKDF2. Run `fleetctl fips check` to confirm readiness.\n", total)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
