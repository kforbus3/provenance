package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer returns a Client pointed at a test server using the given handler.
func newTestServer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, WithToken("flt_test"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewNormalizesBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://fleet.example.com":         "https://fleet.example.com",
		"https://fleet.example.com/":        "https://fleet.example.com",
		"https://fleet.example.com/api/v1":  "https://fleet.example.com",
		"https://fleet.example.com/api/v1/": "https://fleet.example.com",
		"fleet.example.com":                 "https://fleet.example.com", // scheme defaulted
	}
	for in, want := range cases {
		c, err := New(in)
		if err != nil {
			t.Fatalf("New(%q): %v", in, err)
		}
		if c.baseURL != want {
			t.Errorf("New(%q).baseURL = %q, want %q", in, c.baseURL, want)
		}
	}
	if _, err := New(""); err == nil {
		t.Error("New(\"\") should error")
	}
}

func TestListHostsSendsAuthAndParses(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer flt_test" {
			t.Errorf("Authorization = %q, want Bearer flt_test", got)
		}
		if r.URL.Path != "/api/v1/hosts" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "50" {
			t.Errorf("limit = %q, want 50", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hosts": []map[string]any{{"id": "h1", "hostname": "web-01", "tags": []string{"prod"}}},
			"count": 1,
		})
	})
	hosts, err := c.ListHosts(context.Background(), ListOptions{Limit: 50})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Hostname != "web-01" || hosts[0].ID != "h1" {
		t.Fatalf("unexpected hosts: %+v", hosts)
	}
}

func TestCreateHostPostsBody(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var in HostInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if in.Hostname != "db-02" {
			t.Errorf("hostname = %q", in.Hostname)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": "new", "hostname": in.Hostname})
	})
	h, err := c.CreateHost(context.Background(), HostInput{Hostname: "db-02"})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if h.ID != "new" {
		t.Fatalf("id = %q", h.ID)
	}
}

func TestCreateTokenReturnsSecret(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/service-accounts/sa1/tokens") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": "t1", "name": "ci", "secret": "flt_secretvalue"})
	})
	tok, err := c.CreateToken(context.Background(), "sa1", TokenInput{Name: "ci"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Secret != "flt_secretvalue" {
		t.Fatalf("secret = %q", tok.Secret)
	}
}

func TestScanHostReturnsIDs(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["hostId"] != "h9" {
			t.Errorf("hostId = %q", body["hostId"])
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"scanIds": []string{"s1"}})
	})
	ids, err := c.ScanHost(context.Background(), "h9")
	if err != nil {
		t.Fatalf("ScanHost: %v", err)
	}
	if len(ids) != 1 || ids[0] != "s1" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestReportReturnsCSV(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/reports/access.csv" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("from") != "2026-01-01" {
			t.Errorf("from = %q", r.URL.Query().Get("from"))
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Write([]byte("user,host,when\nalice,web-01,2026-01-02\n"))
	})
	data, err := c.Report(context.Background(), ReportAccess, "2026-01-01", "")
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !strings.HasPrefix(string(data), "user,host,when") {
		t.Fatalf("csv = %q", string(data))
	}
}

func TestAPIErrorParsedAndClassified(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "host not found"})
	})
	_, err := c.GetHost(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound = false for %v", err)
	}
	var ae *APIError
	if !strings.Contains(err.Error(), "host not found") {
		t.Errorf("error message not surfaced: %v", err)
	}
	if ok := As(err, &ae); !ok || ae.StatusCode != 404 {
		t.Errorf("APIError not extractable: %v", err)
	}
}

// As is a tiny local alias so the test does not import errors just for this.
func As(err error, target **APIError) bool {
	for err != nil {
		if ae, ok := err.(*APIError); ok {
			*target = ae
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
