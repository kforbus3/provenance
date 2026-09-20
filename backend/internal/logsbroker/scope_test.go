package logsbroker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// A log line is host data, and Logs.View used to mean every line from every machine the
// collector had ever heard from. QA proved what that costs: a customer tenant with zero
// hosts searched the collector and got the provider tenant's log lines back, hostnames
// and messages included.
func TestSearchRestrictsToTheGivenSenders(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"took":1,"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "u", "p")
	if _, err := c.Search(context.Background(), Query{Hosts: []string{"WEB01", "db1", "web01", "  "}}); err != nil {
		t.Fatalf("search: %v", err)
	}
	blob, _ := json.Marshal(got)
	s := string(blob)
	if !strings.Contains(s, `"terms":{"host":["web01","db1"]}`) {
		t.Errorf("the sender allowlist is not applied (or not normalised/deduped):\n%s", s)
	}
}

// An unrestricted search is still possible -- a provider-level super administrator needs
// it, because a collector also holds lines from senders that are not enrolled hosts.
func TestSearchWithoutAnAllowlistIsUnfiltered(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"took":1,"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "u", "p").Search(context.Background(), Query{}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if blob, _ := json.Marshal(got); strings.Contains(string(blob), `"terms":{"host"`) {
		t.Errorf("an unrestricted search sent a host allowlist:\n%s", blob)
	}
}

// The host dropdown is a list of machine names. Unrestricted, it is a list of other
// people's machine names -- the same leak in kind as the lines themselves.
func TestHostsListRestrictsToTheGivenSenders(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"aggregations":{"by_host":{"buckets":[]}}}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "u", "p").Hosts(context.Background(), "now-24h", []string{"web01"}); err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if blob, _ := json.Marshal(got); !strings.Contains(string(blob), `"terms":{"host":["web01"]}`) {
		t.Errorf("the host list is not restricted:\n%s", blob)
	}
}

// Every name a host's lines might arrive under. The collector shortens some senders, so
// a host enrolled as "hypervisor.example.com" whose lines arrive as "hypervisor" must match, or
// scoping silently hides a host's own logs from the person who owns it.
func TestSenderNamesCoverTheWaysAHostIsNamed(t *testing.T) {
	h := models.Host{ID: uuid.New(), Hostname: "hypervisor.example.com", Address: "10.10.0.10"}
	got := senderNames(h)
	for _, want := range []string{"hypervisor.example.com", "hypervisor", "10.10.0.10"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("senderNames missing %q: %v", want, got)
		}
	}
}
