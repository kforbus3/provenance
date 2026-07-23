// Command fleet is the remote automation CLI for Fleet Terminal. It authenticates
// with a service-account API token and drives the REST API through the Go SDK,
// so anything you can do in the web UI's inventory/access surfaces you can script
// here — for CI/CD, cron jobs, and infrastructure automation.
//
// This is distinct from `fleetctl`, the on-host/break-glass tool that talks to the
// database directly for recovery. `fleet` is the day-to-day, token-authenticated
// client and never needs database access.
//
// Configuration (flags override environment):
//
//	FLEET_URL         base URL of the deployment (e.g. https://fleet.example.com)
//	FLEET_API_TOKEN   service-account API token (flt_...)
//
// Examples:
//
//	fleet hosts list
//	fleet hosts create --hostname db-02 --env prod --tags db,postgres
//	fleet groups create --name prod-db --tag-all prod,db          # dynamic group
//	fleet vuln scan --host <id>       &&  fleet vuln list --host <id>
//	fleet report vulnerabilities --from 2026-01-01 -o vulns.csv
//	fleet whoami
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"

	fleet "github.com/kforbus3/Fleet-Terminal/sdk"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		if fleet.IsUnauthorized(err) {
			fmt.Fprintln(os.Stderr, "hint: set FLEET_API_TOKEN to a valid service-account token with the required permission.")
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "version":
		return cmdVersion(ctx, args)
	case "whoami":
		return cmdWhoami(ctx, args)
	case "hosts":
		return cmdHosts(ctx, args)
	case "groups":
		return cmdGroups(ctx, args)
	case "users":
		return cmdUsers(ctx, args)
	case "roles":
		return cmdRoles(ctx, args)
	case "service-accounts", "sa":
		return cmdServiceAccounts(ctx, args)
	case "tokens":
		return cmdTokens(ctx, args)
	case "vuln":
		return cmdVuln(ctx, args)
	case "report":
		return cmdReport(ctx, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		return errUsage
	}
}

// client builds an SDK client from the environment.
func client() (*fleet.Client, error) {
	base := os.Getenv("FLEET_URL")
	if base == "" {
		return nil, errors.New("FLEET_URL is not set (e.g. https://fleet.example.com)")
	}
	return fleet.New(base,
		fleet.WithToken(os.Getenv("FLEET_API_TOKEN")),
		fleet.WithUserAgent("fleet-cli/"+version),
	)
}

func usage() {
	fmt.Fprint(os.Stderr, `fleet — remote automation CLI for Fleet Terminal

Usage:
  fleet <command> [subcommand] [flags]

Environment:
  FLEET_URL         base URL of the deployment (e.g. https://fleet.example.com)
  FLEET_API_TOKEN   service-account API token (flt_...)

Commands:
  version                         show the deployment version
  whoami                          show the identity and permissions of the token
  hosts list                      list hosts
  hosts get <id>                  show one host
  hosts create --hostname <h> ... register a host
  hosts delete <id>               remove a host
  hosts add-group <hostId> <groupId>
  hosts rm-group  <hostId> <groupId>
  groups list                     list groups
  groups create --name <n> [--tag-all a,b] [--tag-any a,b] [--env e]
  groups delete <id>              remove a group
  users list                      list users
  roles list                      list roles
  service-accounts list           list service accounts (alias: sa)
  service-accounts create --username <u> [--roles id,id] [--groups id,id]
  service-accounts delete <id>
  tokens list <serviceAccountId>
  tokens create <serviceAccountId> --name <n> [--expires-days N]
  tokens revoke <serviceAccountId> <tokenId>
  vuln scan --host <id> | --group <id>
  vuln list [--host <id>] | vuln latest
  vuln get <scanId>
  report <access|audit|certificates|scans|vulnerabilities> [--from D] [--to D] [-o file.csv]

Global flags:
  --json    output raw JSON instead of a table

Run "fleet <command> --help" for command-specific flags.
`)
}

// ---- output helpers --------------------------------------------------------

// hasJSON reports whether --json is present and returns the remaining args.
func hasJSON(args []string) (bool, []string) {
	out := args[:0:0]
	j := false
	for _, a := range args {
		if a == "--json" {
			j = true
			continue
		}
		out = append(out, a)
	}
	return j, out
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02")
}
