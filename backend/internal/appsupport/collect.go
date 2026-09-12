// Package appsupport collects a support bundle about PROVENANCE ITSELF, as
// opposed to internal/support, which collects one about a managed host.
//
// The distinction matters when the thing misbehaving is the application: an
// operator should not have to know which container to exec into, which log to
// tail, or which table to query, to send somebody enough to work from. One
// button, one file, offline-readable.
//
// Two rules govern what goes in, because a bundle is made to be SENT:
//
//   - configuration is reported from an explicit list of non-secret fields, never
//     by dumping the environment. Deny by default: a new setting is absent from a
//     bundle until somebody decides it is safe to include.
//   - free text that has to be included is scrubbed for credential shapes and has
//     its IP addresses consistently pseudonymised. Scrubbing is the second line,
//     not the first — a value that does not look like a secret survives it.
package appsupport

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Source is what the collector needs from the rest of the application. An
// interface so a bundle can be produced in a test without a database, a Docker
// socket or a running updater — the parts most likely to be broken when somebody
// wants a bundle.
type Source interface {
	Version() string
	Instances(ctx context.Context) ([]InstanceInfo, error)
	Jobs() []JobInfo
	Migrations(ctx context.Context) ([]string, error)
	Settings() []Setting
	Health(ctx context.Context) []Check
	FleetSummary(ctx context.Context) (FleetSummary, error)
	// Hostnames is the fleet's own names, used only when masking is asked for.
	// Only names this instance manages are masked: matching hostname-shaped words
	// generally would catch every domain in every log, and most belong to others.
	Hostnames(ctx context.Context) ([]string, error)
	UpgradeStatus(ctx context.Context) (any, error)
	Diagnostics(ctx context.Context) (Diagnostics, error)
}

type InstanceInfo struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	Version  string    `json:"version"`
	LastSeen time.Time `json:"lastSeen"`
	Leader   bool      `json:"leader"`
}

type JobInfo struct {
	Name    string    `json:"name"`
	LastRun time.Time `json:"lastRun"`
	Error   string    `json:"error,omitempty"`
}

// Setting is one configuration value, already decided to be safe to include.
type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type FleetSummary struct {
	Hosts       int            `json:"hosts"`
	ByStatus    map[string]int `json:"byStatus"`
	Containers  int            `json:"containers"`
	Stacks      int            `json:"stacks"`
	OpenRollout int            `json:"rolloutsRunning"`
}

type Diagnostics struct {
	Containers string            `json:"containers"`
	Logs       map[string]string `json:"logs"`
	Errors     map[string]string `json:"errors,omitempty"`
}

// Collector builds bundles.
type Collector struct {
	src Source
}

func New(src Source) *Collector { return &Collector{src: src} }

// Manifest describes the bundle itself, so somebody opening it months later can
// tell what they are holding and what was done to it.
type Manifest struct {
	Kind          string    `json:"kind"`
	Format        int       `json:"formatVersion"`
	Generated     time.Time `json:"generatedAt"`
	By            string    `json:"generatedBy,omitempty"`
	Version       string    `json:"provenanceVersion"`
	Anonymised    int       `json:"addressesAnonymised"`
	Masked        bool      `json:"hostnamesMasked"`
	Ambiguous     []string  `json:"ambiguousHostnames,omitempty"`
	Notes         []string  `json:"notes"`
	CollectErrors []string  `json:"collectionErrors,omitempty"`
}

// Collect writes a gzipped tar to w.
//
// Never fatal on a part. A bundle is wanted precisely when something is broken,
// so a collector that refuses to produce anything because one source is
// unreachable fails at the only moment it matters. Each failure is recorded in
// the manifest and the rest of the bundle is written.
// Options are the choices an operator makes when producing a bundle.
type Options struct {
	// Anonymise masks the fleet's hostnames and replaces IP addresses.
	//
	// Off by default, deliberately. A bundle usually goes to somebody who already
	// knows the estate, and the real names make it far easier to read; masking is
	// for the case where it is going further afield. Credential scrubbing is not
	// part of this choice and always happens — a password has no audience.
	Anonymise bool
}

func (c *Collector) Collect(ctx context.Context, w io.Writer, by string, opt Options) error {
	anon := NewAnonymiser()
	var ambiguous []string
	if opt.Anonymise {
		anon.Enable()
		names, err := c.src.Hostnames(ctx)
		if err == nil {
			anon.MaskHostnames(names)
			ambiguous = anon.AmbiguousHostnames()
		}
	}
	var problems []string
	note := func(what string, err error) {
		if err != nil {
			problems = append(problems, what+": "+err.Error())
		}
	}

	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	add := func(name string, body string) {
		body = anon.Text(Scrub(body))
		hdr := &tar.Header{
			Name: "provenance-support/" + name,
			Mode: 0o600,
			Size: int64(len(body)),
			// A fixed time, not now(): a bundle's value is its content, and
			// per-file timestamps invite people to read meaning into them.
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			note(name, err)
			return
		}
		if _, err := io.WriteString(tw, body); err != nil {
			note(name, err)
		}
	}
	addJSON := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			note(name, err)
			return
		}
		add(name, string(b))
	}

	// --- what the application is ---
	if inst, err := c.src.Instances(ctx); err != nil {
		note("instances", err)
	} else {
		addJSON("instances.json", inst)
	}
	if mig, err := c.src.Migrations(ctx); err != nil {
		note("migrations", err)
	} else {
		add("migrations.txt", strings.Join(mig, "\n")+"\n")
	}
	addJSON("settings.json", c.src.Settings())

	// --- what it is doing ---
	addJSON("jobs.json", c.src.Jobs())
	addJSON("health.json", c.src.Health(ctx))
	if up, err := c.src.UpgradeStatus(ctx); err != nil {
		note("upgrade status", err)
	} else {
		addJSON("upgrade-status.json", up)
	}
	if fs, err := c.src.FleetSummary(ctx); err != nil {
		note("fleet summary", err)
	} else {
		addJSON("fleet-summary.json", fs)
	}

	// --- what the containers are doing ---
	if d, err := c.src.Diagnostics(ctx); err != nil {
		note("container diagnostics", err)
	} else {
		add("containers.txt", d.Containers)
		names := make([]string, 0, len(d.Logs))
		for n := range d.Logs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			add("logs/"+safeName(n)+".log", d.Logs[n])
		}
		if len(d.Errors) > 0 {
			addJSON("logs/_errors.json", d.Errors)
		}
	}

	// The manifest is written LAST, so it can report what went wrong collecting
	// everything else and how many addresses were replaced.
	m := Manifest{
		Kind:          "provenance-support-bundle",
		Format:        1,
		Generated:     time.Now().UTC(),
		By:            by,
		Version:       c.src.Version(),
		Notes:         notes(opt.Anonymise, ambiguous),
		Anonymised:    anon.Count(),
		Masked:        opt.Anonymise,
		Ambiguous:     ambiguous,
		CollectErrors: problems,
	}
	addJSON("manifest.json", m)
	return nil
}

// safeName keeps a container name from escaping the archive directory.
func safeName(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" {
		return "unnamed"
	}
	return s
}

// FetchDiagnostics asks the updater for what only it can see.
func FetchDiagnostics(ctx context.Context, client *http.Client, baseURL, token string, lines int) (Diagnostics, error) {
	var d Diagnostics
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/diagnostics?lines=%d", strings.TrimRight(baseURL, "/"), lines), nil)
	if err != nil {
		return d, err
	}
	if token != "" {
		req.Header.Set("X-Updater-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return d, fmt.Errorf("the updater is not reachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("the updater answered %d", resp.StatusCode)
	}
	return d, json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&d)
}

// notes says plainly what was and was not done, because a bundle outlives the
// conversation in which it was produced.
func notes(anonymised bool, ambiguous []string) []string {
	out := []string{
		"Credential-shaped text has been removed. Configuration is reported from a fixed list of non-secret fields rather than from the environment. This happens regardless of the anonymisation setting.",
	}
	if !anonymised {
		return append(out,
			"Hostnames and IP addresses are AS THEY ARE. This bundle describes a real network; treat it accordingly.",
			"It can be produced with hostnames masked and addresses replaced instead — the option is offered when generating one.")
	}
	out = append(out,
		"Hostnames have been masked, and IP addresses replaced with placeholders from the ranges reserved for documentation (RFC 5737, RFC 3849).",
		"The same hostname and the same address map to the same placeholder throughout this bundle, so relationships between machines are still readable.",
		"The mapping is specific to this bundle: two bundles from the same instance use different placeholders and cannot be lined up against each other.",
		"Loopback and unspecified addresses are left as they are, being diagnostic and identifying nobody.")
	if len(ambiguous) > 0 {
		out = append(out, "These hostnames are also ordinary words, so they have been replaced wherever they appear — including where they did not refer to the host: "+
			strings.Join(ambiguous, ", ")+".")
	}
	return out
}
