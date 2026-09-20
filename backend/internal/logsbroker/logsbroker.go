// Package logsbroker searches the Aldgate log collector on a caller's behalf.
//
// Provenance already knows every host and records who did what; Aldgate holds
// what those hosts said. Brokering the search rather than pointing a browser at
// OpenSearch buys the same three things the Kubernetes broker buys:
//
//   - The collector's credential stays server-side. It is never in a browser,
//     never in a bookmark, and cannot be replayed from somebody's history.
//   - Every query is recorded against the person who ran it. "Who went looking
//     at the auth logs" is a question a log system should be able to answer
//     about itself.
//   - What a person may see is decided by their Provenance role, in one place,
//     rather than by a second set of users inside OpenSearch.
//
// It is deliberately a narrow surface: a search, the hosts that are sending, and
// the fields worth filtering on. Anything richer belongs in Dashboards, which is
// embedded alongside this rather than reimplemented.
package logsbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client talks to one OpenSearch.
type Client struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
}

// New returns a client, or nil when no collector is configured.
//
// Nil rather than an error: a deployment with no log collector is an ordinary
// deployment, and the Logs page tells the operator how to point at one instead
// of reporting a fault.
// searchPath covers BOTH streams, and that is the whole point of the page: a
// syslog line from a switch and an SNMP trap from the same switch are the same
// event seen twice, and a search that returns one without the other quietly
// tells you your network was fine. Aldgate normalises traps into the same
// fields, so one query spans both. A wildcard that matches no index is ignored
// rather than a 404, so a collector with no traps yet still searches cleanly.
// severityError is the syslog severity code for "error". Codes are ordered by
// urgency ASCENDING (0=emerg .. 7=debug), so "error or worse" is <= 3.
const severityError = 3

const searchPath = "/syslog-*,snmp-*/_search?ignore_unavailable=true"

func New(baseURL, user, password string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	return &Client{
		BaseURL:  strings.TrimSuffix(baseURL, "/"),
		User:     user,
		Password: password,
		// Bounded. A search that hangs must not hold a request open until the
		// gateway gives up, because the operator then has no idea whether the
		// query was slow or the collector is down.
		HTTP: &http.Client{Timeout: 25 * time.Second},
	}
}

// Query is a search as the UI expresses it.
type Query struct {
	Text      string // free text over the message
	Host      string // exact host
	Program   string // exact program/unit
	MinSev    int    // severity_code <= this; 0 disables
	Since     string // an OpenSearch date-math string such as now-1h
	Until     string
	Limit     int
	Ascending bool
	// Hosts restricts the search to these sender names. Empty means unrestricted,
	// which only a provider-level super administrator may ask for -- see the handler.
	//
	// This exists because a log line is host data, and the rest of the product treats
	// host data as something a person either may or may not see. Without it, Logs.View
	// meant every line from every machine: under multi-tenancy one customer's
	// administrator could read another customer's authentication logs, hostnames and
	// commands, which was demonstrated in QA before this was added.
	Hosts []string
}

// Entry is one log line, flattened for display.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Received  string `json:"receivedAt,omitempty"`
	Host      string `json:"host"`
	Program   string `json:"program"`
	Severity  string `json:"severity"`
	SevCode   int    `json:"severityCode"`
	Facility  string `json:"facility,omitempty"`
	Message   string `json:"message"`
	Source    string `json:"sourceAddress,omitempty"`
}

// Result is a page of entries plus what the whole match looks like.
type Result struct {
	Total   int      `json:"total"`
	Entries []Entry  `json:"entries"`
	ByHost  []Bucket `json:"byHost"`
	BySev   []Bucket `json:"bySeverity"`
	Took    int      `json:"tookMs"`
}

// Bucket is one aggregation row.
type Bucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Search runs the query and returns a page of results with two aggregations.
//
// The aggregations are not decoration: a log search is useless without knowing
// which hosts and severities the match is spread across, because that is how an
// operator narrows from "something is wrong" to "it is this machine".
func (c *Client) Search(ctx context.Context, q Query) (*Result, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	if q.Since == "" {
		q.Since = "now-1h"
	}
	if q.Until == "" {
		q.Until = "now"
	}

	filters := []any{
		map[string]any{"range": map[string]any{
			"timestamp": map[string]any{"gte": q.Since, "lte": q.Until},
		}},
	}
	if h := strings.TrimSpace(q.Host); h != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"host": strings.ToLower(h)}})
	}
	if len(q.Hosts) > 0 {
		filters = append(filters, map[string]any{"terms": map[string]any{"host": lowerAll(q.Hosts)}})
	}
	if p := strings.TrimSpace(q.Program); p != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"program": p}})
	}
	if q.MinSev > 0 {
		filters = append(filters, map[string]any{"range": map[string]any{
			"severity_code": map[string]any{"lte": q.MinSev},
		}})
	}
	if t := strings.TrimSpace(q.Text); t != "" {
		// match, not match_phrase: an operator typing two words means "both of
		// these", not "this exact phrase", and a phrase search silently returns
		// nothing for the ordinary case.
		filters = append(filters, map[string]any{"match": map[string]any{
			"message": map[string]any{"query": t, "operator": "and"},
		}})
	}

	order := "desc"
	if q.Ascending {
		order = "asc"
	}
	body := map[string]any{
		"size":  q.Limit,
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
		"sort":  []any{map[string]any{"timestamp": map[string]any{"order": order}}},
		"aggs": map[string]any{
			"by_host":     map[string]any{"terms": map[string]any{"field": "host", "size": 25}},
			"by_severity": map[string]any{"terms": map[string]any{"field": "severity", "size": 10}},
		},
		// An exact count past a few thousand costs more than it is worth for a
		// human reading a page of results; this keeps "10000+" honest and fast.
		"track_total_hits": 10000,
	}

	raw, err := c.post(ctx, searchPath, body)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Took int `json:"took"`
		Hits struct {
			Total struct{ Value int } `json:"total"`
			Hits  []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations struct {
			ByHost struct {
				Buckets []struct {
					Key      string
					DocCount int `json:"doc_count"`
				}
			} `json:"by_host"`
			BySeverity struct {
				Buckets []struct {
					Key      string
					DocCount int `json:"doc_count"`
				}
			} `json:"by_severity"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("could not read the collector's reply: %w", err)
	}

	// Every slice starts empty, not nil. A nil slice marshals to JSON `null`,
	// and the page then calls .map on null and unmounts the whole tree -- a
	// BLANK PAGE, with no error message anywhere, for the ordinary case of a
	// filter that matched nothing. Guarding only Entries (which is what this did)
	// moves the crash to the aggregations rather than removing it.
	out := &Result{
		Total:   resp.Hits.Total.Value,
		Took:    resp.Took,
		Entries: []Entry{},
		ByHost:  []Bucket{},
		BySev:   []Bucket{},
	}
	for _, h := range resp.Hits.Hits {
		out.Entries = append(out.Entries, entryFrom(h.Source))
	}
	for _, b := range resp.Aggregations.ByHost.Buckets {
		out.ByHost = append(out.ByHost, Bucket{Key: b.Key, Count: b.DocCount})
	}
	for _, b := range resp.Aggregations.BySeverity.Buckets {
		out.BySev = append(out.BySev, Bucket{Key: b.Key, Count: b.DocCount})
	}
	return out, nil
}

// Hosts returns the hosts that have sent anything in the window, most first.
//
// Used by the UI to offer a host filter, and worth having for its own sake: a
// host that has stopped sending is the failure this whole system is most likely
// to suffer and least likely to announce.
func (c *Client) Hosts(ctx context.Context, since string, allow []string) ([]Bucket, error) {
	if since == "" {
		since = "now-24h"
	}
	filters := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since}}}}
	if len(allow) > 0 {
		// The dropdown is a list of other people's machine names when it is not
		// restricted, which is a smaller leak than the log lines themselves and the
		// same leak in kind.
		filters = append(filters, map[string]any{"terms": map[string]any{"host": lowerAll(allow)}})
	}
	body := map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
		"aggs": map[string]any{
			"by_host": map[string]any{"terms": map[string]any{"field": "host", "size": 200}},
		},
	}
	raw, err := c.post(ctx, searchPath, body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Aggregations struct {
			ByHost struct {
				Buckets []struct {
					Key      string
					DocCount int `json:"doc_count"`
				}
			} `json:"by_host"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	out := []Bucket{}
	for _, b := range resp.Aggregations.ByHost.Buckets {
		out = append(out, Bucket{Key: b.Key, Count: b.DocCount})
	}
	return out, nil
}

// entryFrom flattens one document, tolerating anything missing.
//
// Tolerant on purpose: Vector is told never to drop a message it could not
// parse, so a document with half these fields is a message that arrived and
// should still be visible. Refusing to render it would hide exactly the
// malformed traffic worth looking at.
func entryFrom(src map[string]any) Entry {
	str := func(k string) string {
		if v, ok := src[k]; ok && v != nil {
			if s, ok := v.(string); ok {
				return s
			}
			return fmt.Sprint(v)
		}
		return ""
	}
	e := Entry{
		Timestamp: str("timestamp"),
		Received:  str("received_at"),
		Host:      str("host"),
		Program:   str("program"),
		Severity:  str("severity"),
		Facility:  str("facility"),
		Message:   str("message"),
		Source:    str("source_address"),
	}
	if v, ok := src["severity_code"]; ok {
		switch n := v.(type) {
		case float64:
			e.SevCode = int(n)
		case string:
			e.SevCode, _ = strconv.Atoi(n)
		}
	}
	return e
}

func (c *Client) post(ctx context.Context, path string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Said plainly: the usual cause is the collector being down or the URL
		// pointing somewhere else, and "connection refused" buried in a Go error
		// string does not tell an operator which.
		return nil, fmt.Errorf("could not reach the log collector at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("the log collector rejected Provenance's credentials (HTTP %d) — check PROV_ALDGATE_USER and PROV_ALDGATE_PASSWORD", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		// A 404 means no index exists yet, which is what a brand new collector
		// looks like. Not an error worth showing as one.
		return nil, errNoData
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the log collector answered HTTP %d: %s", resp.StatusCode, trim(string(raw)))
	}
	return raw, nil
}

// errNoData is "the collector is up and has nothing yet".
var errNoData = fmt.Errorf("no logs have been collected yet")

// IsNoData reports the empty-collector case so a handler can answer with an
// empty result instead of an error.
func IsNoData(err error) bool { return err == errNoData }

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// HostErrorRate is one host's count of error-or-worse log lines in two windows:
// Recent (the last recentMinutes) and Baseline (everything before that, inside the
// baseline window). The two are disjoint, so a caller can compare rates directly.
type HostErrorRate struct {
	Host     string
	Recent   int
	Baseline int
	// The windows the counts came from, so a caller can turn counts into rates
	// without having to remember what it asked for.
	RecentMinutes   int
	BaselineMinutes int
}

// ErrorRates counts error-or-worse lines per host over a recent window and the
// baseline period preceding it, in ONE query.
//
// One query on purpose: this feeds the dashboard and the daily digest, which run
// on every page load and every schedule tick, and a per-host round trip would turn
// a fleet of 50 hosts into 50 searches against a collector that is also busy
// indexing. The recent window is a filter sub-aggregation of the baseline bucket,
// so OpenSearch counts both in one pass.
//
// Documents with no severity_code are not counted. Vector is told never to drop a
// message it could not parse, and an unparsed line has no severity to compare --
// counting it as an error would make every malformed-syslog device look like it was
// on fire.
func (c *Client) ErrorRates(ctx context.Context, recentMinutes, baselineHours int) ([]HostErrorRate, error) {
	if recentMinutes <= 0 {
		recentMinutes = 60
	}
	if baselineHours <= 0 {
		baselineHours = 24 * 7
	}
	// The baseline must be longer than the recent window, or "compared with its
	// baseline" compares a window with itself.
	if baselineHours*60 <= recentMinutes {
		baselineHours = (recentMinutes / 60) + 1
	}
	recent := fmt.Sprintf("now-%dm", recentMinutes)
	body := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"range": map[string]any{
				"timestamp": map[string]any{"gte": fmt.Sprintf("now-%dh", baselineHours)},
			}},
			map[string]any{"range": map[string]any{
				"severity_code": map[string]any{"lte": severityError},
			}},
		}}},
		"aggs": map[string]any{
			"by_host": map[string]any{
				"terms": map[string]any{"field": "host", "size": 200},
				"aggs": map[string]any{
					"recent": map[string]any{"filter": map[string]any{
						"range": map[string]any{"timestamp": map[string]any{"gte": recent}},
					}},
				},
			},
		},
	}
	raw, err := c.post(ctx, searchPath, body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Aggregations struct {
			ByHost struct {
				Buckets []struct {
					Key      string
					DocCount int `json:"doc_count"`
					Recent   struct {
						DocCount int `json:"doc_count"`
					} `json:"recent"`
				}
			} `json:"by_host"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("could not read the collector's reply: %w", err)
	}
	out := []HostErrorRate{}
	for _, b := range resp.Aggregations.ByHost.Buckets {
		out = append(out, HostErrorRate{
			Host:            b.Key,
			Recent:          b.Recent.DocCount,
			Baseline:        b.DocCount - b.Recent.DocCount,
			RecentMinutes:   recentMinutes,
			BaselineMinutes: baselineHours*60 - recentMinutes,
		})
	}
	return out, nil
}

// lowerAll normalises sender names for a keyword term filter, which is case
// sensitive: "Web01" and "web01" are different terms, and a host recorded with a
// capital letter would silently match nothing.
func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
