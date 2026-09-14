package extsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// OpenBao is a fork of Vault 1.14 and serves the same KV v2 routes, so it shares the
// client — but it is a distinct provider NAME, because that name is persisted on
// every external-backed credential and shown in the UI. An operator who selected
// OpenBao must see OpenBao, and a credential must resolve back through the provider
// it was created against.
func TestOpenBaoIsASupportedProviderInItsOwnName(t *testing.T) {
	if !Supported(ProviderOpenBao) {
		t.Fatalf("%q is not reported as supported", ProviderOpenBao)
	}
	p, err := New(ProviderOpenBao, Config{VaultAddr: "https://bao.internal:8200", VaultToken: "t"})
	if err != nil {
		t.Fatalf("New(%q): %v", ProviderOpenBao, err)
	}
	if got := p.Name(); got != ProviderOpenBao {
		t.Errorf("Name() = %q, want %q — a credential stored as openbao would not resolve back", got, ProviderOpenBao)
	}
	// And Vault must not have been changed into OpenBao by sharing the client.
	v, err := New(ProviderVaultKV, Config{VaultAddr: "https://vault.internal:8200", VaultToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Name(); got != ProviderVaultKV {
		t.Errorf("Name() = %q, want %q", got, ProviderVaultKV)
	}
}

// The unknown-provider error is what an operator sees after a typo, so it must list
// every name that would have worked.
func TestUnknownProviderErrorListsOpenBao(t *testing.T) {
	_, err := New("hashicorp", Config{})
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	for _, want := range []string{ProviderVaultKV, ProviderOpenBao, ProviderAWSSecrets} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not offer %q", err, want)
		}
	}
}

// Both KV providers must actually speak KV v2 against a server: same read path, same
// token header, same reference parsing.
func TestBothKVProvidersReadKVv2(t *testing.T) {
	for _, provider := range []string{ProviderVaultKV, ProviderOpenBao} {
		t.Run(provider, func(t *testing.T) {
			var gotPath, gotToken string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotToken = r.URL.Path, r.Header.Get("X-Vault-Token")
				_, _ = w.Write([]byte(`{"data":{"data":{"password":"s3cret"}}}`))
			}))
			defer srv.Close()

			p, err := New(provider, Config{VaultAddr: srv.URL, VaultToken: "tok"})
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.Fetch(context.Background(), "secret/db/prod#password")
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if got != "s3cret" {
				t.Errorf("Fetch = %q, want %q", got, "s3cret")
			}
			if gotPath != "/v1/secret/data/db/prod" {
				t.Errorf("read path = %q, want the KV v2 shape /v1/{mount}/data/{path}", gotPath)
			}
			if gotToken != "tok" {
				t.Errorf("token header = %q, want it sent", gotToken)
			}
		})
	}
}

// An error from OpenBao must say OpenBao. Reporting "vault-kv" to someone who never
// configured Vault sends them looking at the wrong server.
func TestErrorsNameTheProviderTheOperatorChose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`permission denied`))
	}))
	defer srv.Close()

	p, err := New(ProviderOpenBao, Config{VaultAddr: srv.URL, VaultToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Fetch(context.Background(), "secret/db/prod#password")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), ProviderOpenBao) {
		t.Errorf("error %q does not name openbao", err)
	}
	if strings.Contains(err.Error(), ProviderVaultKV) {
		t.Errorf("error %q names vault-kv for an OpenBao connection", err)
	}
}

// A missing address or token is a configuration mistake, and the message has to name
// where to fix it — the UI now, or the environment variable for an older deployment.
func TestMissingConnectionNamesWhereToConfigureIt(t *testing.T) {
	if _, err := New(ProviderOpenBao, Config{VaultToken: "t"}); err == nil ||
		!strings.Contains(err.Error(), "address") || !strings.Contains(err.Error(), ProviderOpenBao) {
		t.Errorf("missing address: %v", err)
	}
	if _, err := New(ProviderOpenBao, Config{VaultAddr: "https://bao:8200"}); err == nil ||
		!strings.Contains(err.Error(), "token") {
		t.Errorf("missing token: %v", err)
	}
}

// The CA bundle is configurable from the UI, where a path to a file on the server is
// useless. Inline PEM must win over a leftover path, or a stale server-side file
// silently overrides what the operator just typed.
func TestInlineCAWinsOverAFilePath(t *testing.T) {
	_, err := New(ProviderOpenBao, Config{
		VaultAddr: "https://bao:8200", VaultToken: "t",
		VaultCACertPEM:  "not a certificate",
		VaultCACertFile: "/does/not/exist",
	})
	if err == nil {
		t.Fatal("expected the inline PEM to be parsed (and rejected), not the missing file")
	}
	if strings.Contains(err.Error(), "/does/not/exist") {
		t.Errorf("read the file path instead of the inline PEM: %v", err)
	}
	if !strings.Contains(err.Error(), "no certificates parsed") {
		t.Errorf("error %q does not say the PEM was unparseable", err)
	}
}

// Configured() gates whether the feature is offered at all, and a KV address is a KV
// address whichever server serves it.
func TestConfiguredIsTrueForAnOpenBaoAddress(t *testing.T) {
	if !(Config{VaultAddr: "https://bao.internal:8200"}).Configured() {
		t.Error("an OpenBao address does not count as configured")
	}
}
