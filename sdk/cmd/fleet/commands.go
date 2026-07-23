package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	fleet "github.com/your-org/Fleet-Terminal/sdk"
)

// splitList parses a comma-separated flag value into a trimmed, non-empty slice.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// subFlags builds a FlagSet for a subcommand with a --json flag already wired.
func subFlags(name string, jsonOut *bool) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.BoolVar(jsonOut, "json", false, "output raw JSON")
	return fs
}

func cmdVersion(ctx context.Context, args []string) error {
	c, err := client()
	if err != nil {
		return err
	}
	v, err := c.Version(ctx)
	if err != nil {
		return err
	}
	j, _ := hasJSON(args)
	if j {
		return printJSON(v)
	}
	fmt.Printf("%s (%s) — %s\n", v.AppName, v.Environment, v.Version)
	return nil
}

func cmdWhoami(ctx context.Context, args []string) error {
	c, err := client()
	if err != nil {
		return err
	}
	id, err := c.Whoami(ctx)
	if err != nil {
		return err
	}
	j, _ := hasJSON(args)
	if j {
		return printJSON(id)
	}
	fmt.Printf("%s (%s)\n", id.User.Username, dash(id.User.DisplayName))
	fmt.Printf("super-admin: %t\n", id.IsSuperAdmin)
	fmt.Printf("permissions: %s\n", strings.Join(id.Permissions, ", "))
	return nil
}

func cmdHosts(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("hosts: expected a subcommand (list|get|create|delete|add-group|rm-group)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		j, rest := hasJSON(rest)
		_ = rest
		hosts, err := c.ListHosts(ctx, fleet.ListOptions{})
		if err != nil {
			return err
		}
		if j {
			return printJSON(hosts)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tHOSTNAME\tENV\tENROLLED\tTAGS")
		for _, h := range hosts {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\n", h.ID, h.Hostname, dash(h.Environment), h.Enrolled, strings.Join(h.Tags, ","))
		}
		return tw.Flush()
	case "get":
		if len(rest) == 0 {
			return errors.New("hosts get: <id> required")
		}
		h, err := c.GetHost(ctx, rest[0])
		if err != nil {
			return err
		}
		return printJSON(h)
	case "create":
		var in fleet.HostInput
		var tags string
		fs := flag.NewFlagSet("hosts create", flag.ContinueOnError)
		fs.StringVar(&in.Hostname, "hostname", "", "hostname (required)")
		fs.StringVar(&in.Description, "desc", "", "description")
		fs.StringVar(&in.Environment, "env", "", "environment")
		fs.StringVar(&in.Owner, "owner", "", "owner")
		fs.StringVar(&in.Address, "address", "", "network address")
		fs.StringVar(&in.SSHUser, "ssh-user", "", "SSH login user")
		fs.IntVar(&in.SSHPort, "ssh-port", 0, "SSH port")
		fs.StringVar(&tags, "tags", "", "comma-separated tags")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		if in.Hostname == "" {
			return errors.New("hosts create: --hostname is required")
		}
		in.Tags = splitList(tags)
		h, err := c.CreateHost(ctx, in)
		if err != nil {
			return err
		}
		fmt.Printf("created host %s (%s)\n", h.Hostname, h.ID)
		return nil
	case "delete":
		if len(rest) == 0 {
			return errors.New("hosts delete: <id> required")
		}
		if err := c.DeleteHost(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Println("deleted")
		return nil
	case "add-group":
		if len(rest) < 2 {
			return errors.New("hosts add-group: <hostId> <groupId> required")
		}
		if err := c.AddHostToGroup(ctx, rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Println("added")
		return nil
	case "rm-group":
		if len(rest) < 2 {
			return errors.New("hosts rm-group: <hostId> <groupId> required")
		}
		if err := c.RemoveHostFromGroup(ctx, rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Println("removed")
		return nil
	default:
		return fmt.Errorf("hosts: unknown subcommand %q", sub)
	}
}

func cmdGroups(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("groups: expected a subcommand (list|create|delete)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		j, _ := hasJSON(rest)
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		if j {
			return printJSON(groups)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tNAME\tTYPE\tDESCRIPTION")
		for _, g := range groups {
			typ := "static"
			if g.Rule != nil {
				typ = "dynamic"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", g.ID, g.Name, typ, dash(g.Description))
		}
		return tw.Flush()
	case "create":
		var in fleet.GroupInput
		var tagAll, tagAny, env, osContains, hostContains string
		fs := flag.NewFlagSet("groups create", flag.ContinueOnError)
		fs.StringVar(&in.Name, "name", "", "group name (required)")
		fs.StringVar(&in.Description, "desc", "", "description")
		fs.StringVar(&tagAll, "tag-all", "", "dynamic: host must carry ALL of these tags (comma-separated)")
		fs.StringVar(&tagAny, "tag-any", "", "dynamic: host must carry AT LEAST ONE of these tags")
		fs.StringVar(&env, "env", "", "dynamic: match environment")
		fs.StringVar(&osContains, "os-contains", "", "dynamic: OS name contains")
		fs.StringVar(&hostContains, "hostname-contains", "", "dynamic: hostname contains")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		if in.Name == "" {
			return errors.New("groups create: --name is required")
		}
		rule := &fleet.GroupRule{
			Environment: env, OSContains: osContains, HostnameContains: hostContains,
			TagsAll: splitList(tagAll), TagsAny: splitList(tagAny),
		}
		// Only attach a rule if any condition was set; otherwise the group is static.
		if rule.Environment != "" || rule.OSContains != "" || rule.HostnameContains != "" ||
			len(rule.TagsAll) > 0 || len(rule.TagsAny) > 0 {
			in.Rule = rule
		}
		g, err := c.CreateGroup(ctx, in)
		if err != nil {
			return err
		}
		typ := "static"
		if g.Rule != nil {
			typ = "dynamic"
		}
		fmt.Printf("created %s group %s (%s)\n", typ, g.Name, g.ID)
		return nil
	case "delete":
		if len(rest) == 0 {
			return errors.New("groups delete: <id> required")
		}
		if err := c.DeleteGroup(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Println("deleted")
		return nil
	default:
		return fmt.Errorf("groups: unknown subcommand %q", sub)
	}
}

func cmdUsers(ctx context.Context, args []string) error {
	c, err := client()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] != "list" {
		return errors.New("users: expected 'list'")
	}
	j, _ := hasJSON(args[1:])
	users, err := c.ListUsers(ctx)
	if err != nil {
		return err
	}
	if j {
		return printJSON(users)
	}
	tw := newTable()
	fmt.Fprintln(tw, "ID\tUSERNAME\tSOURCE\tDISABLED\tROLES")
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\n", u.ID, u.Username, dash(u.AuthSource), u.IsDisabled, strings.Join(u.Roles, ","))
	}
	return tw.Flush()
}

func cmdRoles(ctx context.Context, args []string) error {
	c, err := client()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] != "list" {
		return errors.New("roles: expected 'list'")
	}
	j, _ := hasJSON(args[1:])
	roles, err := c.ListRoles(ctx)
	if err != nil {
		return err
	}
	if j {
		return printJSON(roles)
	}
	tw := newTable()
	fmt.Fprintln(tw, "ID\tNAME\tBUILTIN\tPERMISSIONS")
	for _, r := range roles {
		fmt.Fprintf(tw, "%s\t%s\t%t\t%d\n", r.ID, r.Name, r.IsBuiltin, len(r.Permissions))
	}
	return tw.Flush()
}

func cmdServiceAccounts(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("service-accounts: expected a subcommand (list|create|delete)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		j, _ := hasJSON(rest)
		sas, err := c.ListServiceAccounts(ctx)
		if err != nil {
			return err
		}
		if j {
			return printJSON(sas)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tUSERNAME\tTOKENS\tROLES\tDISABLED")
		for _, s := range sas {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%t\n", s.ID, s.Username, s.TokenCount, strings.Join(s.Roles, ","), s.IsDisabled)
		}
		return tw.Flush()
	case "create":
		var in fleet.ServiceAccountInput
		var roles, groups string
		fs := flag.NewFlagSet("service-accounts create", flag.ContinueOnError)
		fs.StringVar(&in.Username, "username", "", "service-account username (required)")
		fs.StringVar(&in.DisplayName, "display-name", "", "display name")
		fs.StringVar(&roles, "roles", "", "comma-separated role IDs")
		fs.StringVar(&groups, "groups", "", "comma-separated group IDs")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		if in.Username == "" {
			return errors.New("service-accounts create: --username is required")
		}
		in.RoleIDs = splitList(roles)
		in.GroupIDs = splitList(groups)
		sa, err := c.CreateServiceAccount(ctx, in)
		if err != nil {
			return err
		}
		fmt.Printf("created service account %s (%s)\n", sa.Username, sa.ID)
		return nil
	case "delete":
		if len(rest) == 0 {
			return errors.New("service-accounts delete: <id> required")
		}
		if err := c.DeleteServiceAccount(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Println("deleted")
		return nil
	default:
		return fmt.Errorf("service-accounts: unknown subcommand %q", sub)
	}
}

func cmdTokens(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("tokens: expected a subcommand (list|create|revoke)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		if len(rest) == 0 {
			return errors.New("tokens list: <serviceAccountId> required")
		}
		j, r2 := hasJSON(rest)
		toks, err := c.ListTokens(ctx, r2[0])
		if err != nil {
			return err
		}
		if j {
			return printJSON(toks)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tNAME\tPREFIX\tCREATED\tEXPIRES\tREVOKED")
		for _, t := range toks {
			exp, rev := "-", "no"
			if t.ExpiresAt != nil {
				exp = fmtTime(*t.ExpiresAt)
			}
			if t.RevokedAt != nil {
				rev = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Prefix, fmtTime(t.CreatedAt), exp, rev)
		}
		return tw.Flush()
	case "create":
		if len(rest) == 0 {
			return errors.New("tokens create: <serviceAccountId> required")
		}
		said := rest[0]
		var in fleet.TokenInput
		fs := flag.NewFlagSet("tokens create", flag.ContinueOnError)
		fs.StringVar(&in.Name, "name", "", "token name (required)")
		fs.IntVar(&in.ExpiresInDays, "expires-days", 0, "expiry in days (0 = never)")
		if err := fs.Parse(rest[1:]); err != nil {
			return errUsage
		}
		if in.Name == "" {
			return errors.New("tokens create: --name is required")
		}
		tok, err := c.CreateToken(ctx, said, in)
		if err != nil {
			return err
		}
		// The secret is shown exactly once. Print it plainly so scripts can capture it.
		fmt.Fprintln(os.Stderr, "token created — store this secret now, it is not shown again:")
		fmt.Println(tok.Secret)
		return nil
	case "revoke":
		if len(rest) < 2 {
			return errors.New("tokens revoke: <serviceAccountId> <tokenId> required")
		}
		if err := c.RevokeToken(ctx, rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Println("revoked")
		return nil
	default:
		return fmt.Errorf("tokens: unknown subcommand %q", sub)
	}
}

func cmdVuln(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("vuln: expected a subcommand (scan|list|latest|get)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "scan":
		var host, group string
		fs := flag.NewFlagSet("vuln scan", flag.ContinueOnError)
		fs.StringVar(&host, "host", "", "host ID to scan")
		fs.StringVar(&group, "group", "", "group ID (scan every host in the group)")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		var ids []string
		switch {
		case host != "":
			ids, err = c.ScanHost(ctx, host)
		case group != "":
			ids, err = c.ScanGroup(ctx, group)
		default:
			return errors.New("vuln scan: --host or --group is required")
		}
		if err != nil {
			return err
		}
		fmt.Printf("started %d scan(s): %s\n", len(ids), strings.Join(ids, " "))
		return nil
	case "list", "latest":
		var host string
		jsonOut := false
		fs := subFlags("vuln "+sub, &jsonOut)
		fs.StringVar(&host, "host", "", "filter by host ID (list only)")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		var scans []fleet.VulnScan
		if sub == "latest" {
			scans, err = c.LatestVulnScans(ctx)
		} else {
			scans, err = c.ListVulnScans(ctx, host)
		}
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(scans)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tHOST\tSTATUS\tCRIT\tHIGH\tMED\tMAXCVSS\tFINISHED")
		for _, s := range scans {
			fin := "-"
			if s.FinishedAt != nil {
				fin = fmtTime(*s.FinishedAt)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%.1f\t%s\n",
				s.ID, dash(s.Hostname), s.Status, s.Critical, s.High, s.Medium, s.MaxCVSS, fin)
		}
		return tw.Flush()
	case "get":
		if len(rest) == 0 {
			return errors.New("vuln get: <scanId> required")
		}
		d, err := c.GetVulnScan(ctx, rest[0])
		if err != nil {
			return err
		}
		return printJSON(d)
	default:
		return fmt.Errorf("vuln: unknown subcommand %q", sub)
	}
}

func cmdReport(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("report: expected a kind (access|audit|certificates|scans|vulnerabilities)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	kind := fleet.ReportKind(args[0])
	var from, to, out string
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.StringVar(&from, "from", "", "start date (YYYY-MM-DD)")
	fs.StringVar(&to, "to", "", "end date (YYYY-MM-DD)")
	fs.StringVar(&out, "o", "", "output file (default: stdout)")
	if err := fs.Parse(args[1:]); err != nil {
		return errUsage
	}
	data, err := c.Report(ctx, kind, from, to)
	if err != nil {
		return err
	}
	if out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(data), out)
	return nil
}
