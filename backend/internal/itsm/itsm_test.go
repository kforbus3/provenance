package itsm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceNowCreateTicket(t *testing.T) {
	var gotAuth, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"number":"INC0012345","sys_id":"abc123"}}`))
	}))
	defer srv.Close()

	c := New(Config{Provider: ProviderServiceNow, BaseURL: srv.URL, User: "svc", Token: "pw", Project: "incident"})
	ref, url, err := c.CreateTicket(context.Background(), "summary here", "desc here")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref != "INC0012345" {
		t.Errorf("ref = %q", ref)
	}
	if !strings.Contains(url, "sys_id=abc123") {
		t.Errorf("url = %q", url)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("missing basic auth: %q", gotAuth)
	}
	if gotPath != "/api/now/table/incident" {
		t.Errorf("path = %q", gotPath)
	}
	var body map[string]string
	_ = json.Unmarshal([]byte(gotBody), &body)
	if body["short_description"] != "summary here" {
		t.Errorf("short_description = %q", body["short_description"])
	}
}

func TestJiraCreateTicket(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"key":"OPS-42","id":"10001"}`))
	}))
	defer srv.Close()

	c := New(Config{Provider: ProviderJira, BaseURL: srv.URL, User: "a@b.com", Token: "tok", Project: "OPS"})
	ref, url, err := c.CreateTicket(context.Background(), "s", "d")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref != "OPS-42" || !strings.HasSuffix(url, "/browse/OPS-42") {
		t.Errorf("ref=%q url=%q", ref, url)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestCreateTicketErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad creds"}`))
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderServiceNow, BaseURL: srv.URL, User: "x", Token: "y"})
	if _, _, err := c.CreateTicket(context.Background(), "s", "d"); err == nil {
		t.Error("expected error on 401")
	}
}

func TestServiceNowComment(t *testing.T) {
	var gotLookup, gotPatchPath, gotPatchBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotLookup = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"result":[{"sys_id":"sid42"}]}`))
			return
		}
		// PATCH
		gotPatchPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotPatchBody = string(b)
		_, _ = w.Write([]byte(`{"result":{}}`))
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderServiceNow, BaseURL: srv.URL, User: "u", Token: "t", Project: "incident"})
	if err := c.Comment(context.Background(), "INC0099001", "decided"); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if !strings.Contains(gotLookup, "number=INC0099001") {
		t.Errorf("lookup query = %q", gotLookup)
	}
	if gotPatchPath != "/api/now/table/incident/sid42" {
		t.Errorf("patch path = %q", gotPatchPath)
	}
	if !strings.Contains(gotPatchBody, "work_notes") {
		t.Errorf("patch body = %q", gotPatchBody)
	}
}

func TestJiraComment(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := New(Config{Provider: ProviderJira, BaseURL: srv.URL, User: "a@b.com", Token: "t"})
	if err := c.Comment(context.Background(), "OPS-42", "decided"); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if gotPath != "/rest/api/2/issue/OPS-42/comment" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestConfiguredAndSupported(t *testing.T) {
	if (Config{}).Configured() {
		t.Error("empty config should not be Configured")
	}
	full := Config{Provider: ProviderJira, BaseURL: "https://x", User: "u", Token: "t", Enabled: true}
	if !full.Configured() {
		t.Error("full+enabled config should be Configured")
	}
	if (Config{Provider: ProviderJira, BaseURL: "https://x", User: "u", Token: "t"}).Configured() {
		t.Error("disabled config should not be Configured")
	}
	if !Supported(ProviderServiceNow) || !Supported(ProviderJira) || Supported("bmc") {
		t.Error("Supported wrong")
	}
}
