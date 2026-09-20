package logsbroker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// No collector configured is an ordinary deployment, not a fault.
func TestNoCollectorIsNil(t *testing.T) {
	if New("", "u", "p") != nil {
		t.Error("an empty URL produced a client; the Logs page must be able to say " +
			"'not configured' rather than report a connection error")
	}
	if New("  ", "u", "p") != nil {
		t.Error("whitespace produced a client")
	}
}

// A document with fields missing must still render. Vector is told never to drop
// a message it could not parse, so a half-parsed document is real traffic --
// and refusing to show it would hide exactly the malformed input worth seeing.
func TestAPartialDocumentStillRenders(t *testing.T) {
	e := entryFrom(map[string]any{"message": "something happened"})
	if e.Message != "something happened" {
		t.Errorf("message lost: %+v", e)
	}
	if e.Host != "" || e.Severity != "" {
		t.Errorf("absent fields invented: %+v", e)
	}
	// severity_code arrives as a JSON number, and sometimes as a string.
	if got := entryFrom(map[string]any{"severity_code": float64(3)}).SevCode; got != 3 {
		t.Errorf("numeric severity_code = %d, want 3", got)
	}
	if got := entryFrom(map[string]any{"severity_code": "4"}).SevCode; got != 4 {
		t.Errorf("string severity_code = %d, want 4", got)
	}
}

// The query the UI sends must become the filters an operator expects, and free
// text must be AND across words rather than a phrase -- typing two words means
// "both of these", and a phrase search silently returns nothing for that.
func TestSearchBuildsTheExpectedQuery(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"took":3,"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "admin", "pw")
	if _, err := c.Search(context.Background(), Query{
		Text: "connection refused", Host: "WEB01", Program: "sshd", MinSev: 4, Since: "now-6h",
	}); err != nil {
		t.Fatalf("search: %v", err)
	}
	blob, _ := json.Marshal(got)
	s := string(blob)
	for _, want := range []string{
		`"operator":"and"`, // both words, not a phrase
		`"host":"web01"`,   // lower-cased, because the field is a keyword
		`"program":"sshd"`,
		`"severity_code":{"lte":4}`, // "warning or worse" as a range
		`"gte":"now-6h"`,
		`"by_host"`, `"by_severity"`, // the aggregations the UI needs to narrow
	} {
		if !strings.Contains(s, want) {
			t.Errorf("query is missing %s:\n%s", want, s)
		}
	}
}

// Both streams, or the page lies by omission: a switch's SNMP traps live in
// snmp-*, and a search that only covers syslog-* reports a quiet network while
// the trap saying a link went down sits one index away. Asserted on the request
// path rather than the constant, so narrowing the search anywhere -- here or in
// Hosts -- fails the test.
func TestSearchCoversSyslogAndSnmp(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		_, _ = w.Write([]byte(`{"took":1,"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "admin", "pw")
	if _, err := c.Search(context.Background(), Query{Host: "coreswitch"}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if _, err := c.Hosts(context.Background(), "now-1h", nil); err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("want 2 requests, got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		for _, want := range []string{"syslog-*", "snmp-*", "ignore_unavailable=true"} {
			if !strings.Contains(p, want) {
				t.Errorf("request path %q is missing %q — traps or a fresh collector would be invisible", p, want)
			}
		}
	}
}

// An empty collector answers 404. That is a new collector, not an error, and
// the UI must show an empty result rather than a failure.
func TestAnEmptyCollectorIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := New(srv.URL, "", "").Search(context.Background(), Query{})
	if !IsNoData(err) {
		t.Errorf("a 404 from an empty collector is reported as %v, want the no-data case", err)
	}
}

// A rejected credential must say which setting is wrong, not "401".
func TestBadCredentialsNameTheSetting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := New(srv.URL, "admin", "wrong").Search(context.Background(), Query{})
	if err == nil || !strings.Contains(err.Error(), "PROV_ALDGATE_PASSWORD") {
		t.Errorf("error does not name the setting to fix: %v", err)
	}
}

// An unreachable collector must name the URL it tried.
func TestAnUnreachableCollectorNamesTheURL(t *testing.T) {
	_, err := New("http://127.0.0.1:1/", "", "").Search(context.Background(), Query{})
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error does not say where it tried to connect: %v", err)
	}
}

// Limits are clamped: a UI bug or a hand-edited URL must not ask the collector
// for an unbounded page.
func TestTheLimitIsClamped(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "", "")
	for _, in := range []int{0, -5, 99999} {
		got = nil
		if _, err := c.Search(context.Background(), Query{Limit: in}); err != nil {
			t.Fatal(err)
		}
		if size, ok := got["size"].(float64); !ok || size > 500 || size <= 0 {
			t.Errorf("limit %d became size %v, want it clamped into 1..500", in, got["size"])
		}
	}
}

// An empty result must marshal with EMPTY ARRAYS, never null.
//
// This is the bug keith hit: filtering by a host with nothing in the window
// returned {"byHost":null,"bySeverity":null}, the page called .map on null, and
// React unmounted the tree -- a blank page, no error, for the most ordinary
// case there is. Entries was guarded and the aggregations were not, which only
// moved the crash.
func TestAnEmptyResultMarshalsAsArraysNotNull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// What OpenSearch returns for a filter that matched nothing.
		_, _ = w.Write([]byte(`{"took":19,"hits":{"total":{"value":0},"hits":[]},
			"aggregations":{"by_host":{"buckets":[]},"by_severity":{"buckets":[]}}}`))
	}))
	defer srv.Close()

	res, err := New(srv.URL, "", "").Search(context.Background(), Query{Host: "docker"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(blob)
	for _, nope := range []string{`"entries":null`, `"byHost":null`, `"bySeverity":null`} {
		if strings.Contains(got, nope) {
			t.Errorf("response contains %s, which blanks the page:\n%s", nope, got)
		}
	}
	for _, want := range []string{`"entries":[]`, `"byHost":[]`, `"bySeverity":[]`} {
		if !strings.Contains(got, want) {
			t.Errorf("response is missing %s:\n%s", want, got)
		}
	}
}

// Same guarantee when OpenSearch omits the aggregations entirely.
func TestMissingAggregationsStillMarshalAsArrays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"took":3,"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()
	res, _ := New(srv.URL, "", "").Search(context.Background(), Query{})
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), "null") {
		t.Errorf("a response with no aggregations produced null: %s", blob)
	}
}

// ErrorRates must come back with the two windows DISJOINT. OpenSearch's sub-
// aggregation counts the recent window inside the baseline bucket, so the baseline
// count has to have the recent one subtracted out; leaving it in makes every spike
// look smaller than it is, and a big enough spike then never fires at all.
func TestErrorRatesSplitsTheWindows(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"aggregations":{"by_host":{"buckets":[
			{"key":"hypervisor","doc_count":150,"recent":{"doc_count":120}},
			{"key":"nas","doc_count":4,"recent":{"doc_count":0}}
		]}}}`))
	}))
	defer srv.Close()

	rates, err := New(srv.URL, "admin", "pw").ErrorRates(context.Background(), 60, 24)
	if err != nil {
		t.Fatalf("error rates: %v", err)
	}
	if len(rates) != 2 {
		t.Fatalf("got %d hosts, want 2", len(rates))
	}
	if rates[0].Host != "hypervisor" || rates[0].Recent != 120 || rates[0].Baseline != 30 {
		t.Errorf("hypervisor = %+v, want recent 120 and baseline 30 (150 total minus the recent 120)", rates[0])
	}
	if rates[1].Baseline != 4 || rates[1].Recent != 0 {
		t.Errorf("nas = %+v, want recent 0 baseline 4", rates[1])
	}
	// The windows must be reported in minutes, and the baseline must exclude the
	// recent window there too, or a caller computing a rate divides by the wrong span.
	if rates[0].RecentMinutes != 60 || rates[0].BaselineMinutes != 24*60-60 {
		t.Errorf("windows = %dm recent / %dm baseline, want 60 / %d", rates[0].RecentMinutes, rates[0].BaselineMinutes, 24*60-60)
	}

	blob, _ := json.Marshal(got)
	s := string(blob)
	for _, want := range []string{
		`"severity_code":{"lte":3}`, // error or worse, not warnings
		`"gte":"now-24h"`,           // the baseline window bounds the whole query
		`"gte":"now-60m"`,           // ...and the recent one is a sub-filter
		`"by_host"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("query missing %s:\n%s", want, s)
		}
	}
}

// A baseline window no longer than the recent one would compare a window with
// itself, and every host would read as exactly 1x its baseline forever.
func TestErrorRatesRefusesADegenerateBaseline(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"aggregations":{"by_host":{"buckets":[]}}}`))
	}))
	defer srv.Close()

	rates, err := New(srv.URL, "admin", "pw").ErrorRates(context.Background(), 120, 1)
	if err != nil {
		t.Fatalf("error rates: %v", err)
	}
	if len(rates) != 0 {
		t.Fatalf("expected no hosts, got %+v", rates)
	}
	if blob, _ := json.Marshal(got); !strings.Contains(string(blob), `"gte":"now-3h"`) {
		t.Errorf("a 2h recent window inside a 1h baseline was not widened:\n%s", blob)
	}
}
