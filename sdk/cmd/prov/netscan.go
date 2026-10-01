package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	prov "github.com/kforbus3/provenance/sdk"
)

// cmdNetScan: network scans (what hosts expose) and the ranges scanned for
// unmanaged devices.
func cmdNetScan(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("netscan: expected a subcommand (scan|latest|host|get|ranges|range-add|range-delete|range-scan)")
	}
	c, err := client()
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "scan":
		var host, group string
		fs := flag.NewFlagSet("netscan scan", flag.ContinueOnError)
		fs.StringVar(&host, "host", "", "host ID to scan")
		fs.StringVar(&group, "group", "", "group ID (scan every host in the group)")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		var hosts []string
		switch {
		case host != "":
			hosts = []string{host}
		case group == "":
			return errors.New("netscan scan: --host or --group is required")
		}
		started, skipped, err := c.NetScanHosts(ctx, hosts, group)
		if err != nil {
			return err
		}
		for _, s := range started {
			fmt.Printf("started %s: %d path(s)\n", s.Hostname, len(s.ScanIDs))
		}
		for _, s := range skipped {
			fmt.Printf("skipped %s: %s\n", s.Hostname, s.Reason)
		}
		return nil
	case "latest", "host":
		jsonOut := false
		fs := subFlags("netscan "+sub, &jsonOut)
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		var scans []prov.NetScan
		if sub == "host" {
			if fs.NArg() == 0 {
				return errors.New("netscan host: <hostId> required")
			}
			scans, err = c.HostNetScans(ctx, fs.Arg(0))
		} else {
			scans, err = c.LatestNetScans(ctx)
		}
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(scans)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tHOST\tADDRESS\tPATH\tSTATUS\tOPEN\tCRIT\tHIGH\tMED\tUNEXPECTED")
		for _, s := range scans {
			status := s.Status
			if status == "unreachable" {
				status = "unreachable (not assessed)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n", s.ID, dash(s.Hostname), s.Target,
				s.Path, status, s.OpenPorts, s.Critical, s.High, s.Medium, s.Unexpected)
		}
		return tw.Flush()
	case "get":
		if len(rest) == 0 {
			return errors.New("netscan get: <scanId> required")
		}
		d, err := c.GetNetScan(ctx, rest[0])
		if err != nil {
			return err
		}
		return printJSON(d)
	case "ranges":
		jsonOut := false
		fs := subFlags("netscan ranges", &jsonOut)
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		rs, err := c.ListNetScanRanges(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(rs)
		}
		tw := newTable()
		fmt.Fprintln(tw, "ID\tNAME\tCIDR\tENABLED\tLAST SCAN\tLIVE")
		for _, r := range rs {
			last := "-"
			if r.LastScan != nil {
				last = fmtTime(*r.LastScan)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%d\n", r.ID, r.Name, r.CIDR, r.Enabled, last, r.LastLive)
		}
		return tw.Flush()
	case "range-add":
		var name, cidr, note string
		disabled := false
		fs := flag.NewFlagSet("netscan range-add", flag.ContinueOnError)
		fs.StringVar(&name, "name", "", "range name")
		fs.StringVar(&cidr, "cidr", "", "network, e.g. 10.0.2.0/24 (at most 1024 addresses)")
		fs.StringVar(&note, "note", "", "free-text note")
		fs.BoolVar(&disabled, "disabled", false, "create it excluded from scheduled range scans")
		if err := fs.Parse(rest); err != nil {
			return errUsage
		}
		if name == "" || cidr == "" {
			return errors.New("netscan range-add: --name and --cidr are required")
		}
		enabled := !disabled
		r, err := c.CreateNetScanRange(ctx, prov.NetScanRangeInput{Name: name, CIDR: cidr, Note: note, Enabled: &enabled})
		if err != nil {
			return err
		}
		fmt.Printf("created %s (%s) %s\n", r.Name, r.CIDR, r.ID)
		return nil
	case "range-delete":
		if len(rest) == 0 {
			return errors.New("netscan range-delete: <rangeId> required")
		}
		return c.DeleteNetScanRange(ctx, rest[0])
	case "range-scan":
		if len(rest) == 0 {
			return errors.New("netscan range-scan: <rangeId> required")
		}
		run, err := c.ScanNetScanRange(ctx, rest[0])
		if err != nil {
			return err
		}
		fmt.Printf("started range scan, run %s\n", run)
		return nil
	default:
		return fmt.Errorf("netscan: unknown subcommand %q", sub)
	}
}
