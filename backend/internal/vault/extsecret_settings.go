package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/config"
	"github.com/kforbus3/provenance/backend/internal/extsecret"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/secretbox"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The external secrets-manager connection was environment-only, which meant changing
// it was a redeploy and seeing it was reading someone's .env. It is now editable in
// Settings, stored like the OIDC and LDAP connections: one settings row, with the
// credentials sealed at rest and never returned to the browser.
//
// The environment remains the baseline and saved values are layered over it field by
// field (config.MergeExtSecret), so a deployment that predates this screen keeps
// working untouched and an operator who fills in only the address has not thereby
// unset the token their .env supplies.
const extSecretSettingKey = "extsecret"

// extSecretConfig is the persisted shape. The three *Enc fields hold sealed
// ciphertext; the matching plaintext fields are write-only and never marshalled back
// out (see redacted).
type extSecretConfig struct {
	// Vault / OpenBao. One connection serves both: OpenBao is a fork of Vault 1.14
	// and speaks the same KV v2 API, so which one a credential uses is chosen per
	// credential, not here.
	VaultAddr       string `json:"vaultAddr,omitempty"`
	VaultToken      string `json:"vaultToken,omitempty"` // write-only
	VaultTokenEnc   string `json:"vaultTokenEnc,omitempty"`
	VaultCACertPEM  string `json:"vaultCaCertPem,omitempty"`
	VaultSkipVerify bool   `json:"vaultSkipVerify,omitempty"`
	AWSRegion       string `json:"awsRegion,omitempty"`
	AWSAccessKey    string `json:"awsAccessKey,omitempty"`
	AWSSecretKey    string `json:"awsSecretKey,omitempty"` // write-only
	AWSSecretKeyEnc string `json:"awsSecretKeyEnc,omitempty"`
	AWSSessionToken string `json:"awsSessionToken,omitempty"` // write-only
	AWSSessionEnc   string `json:"awsSessionEnc,omitempty"`
	AWSEndpoint     string `json:"awsEndpoint,omitempty"`
}

// loadExtSecretConfig reads the settings row. A missing or unreadable row is the
// zero value, which merges as "nothing configured here" and leaves the environment
// in charge — never as "the operator cleared it".
func loadExtSecretConfig(ctx context.Context, st *store.Store) extSecretConfig {
	var c extSecretConfig
	if raw, err := st.GetSetting(ctx, extSecretSettingKey); err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// toExtSecret unseals the stored credentials into a usable connection config.
//
// A credential that cannot be unsealed is dropped rather than passed on as an empty
// string: an empty token would merge as "not set" and silently fall through to the
// environment's, connecting as somebody else. Failing to resolve is the honest
// outcome, and the caller reports the manager as unreachable.
func (c extSecretConfig) toExtSecret(passphrase []byte) extsecret.Config {
	open := func(enc string) string {
		if strings.TrimSpace(enc) == "" {
			return ""
		}
		b, err := secretbox.Open(passphrase, enc)
		if err != nil {
			return ""
		}
		return string(b)
	}
	return extsecret.Config{
		VaultAddr:          strings.TrimSpace(c.VaultAddr),
		VaultToken:         open(c.VaultTokenEnc),
		VaultCACertPEM:     c.VaultCACertPEM,
		VaultTLSSkipVerify: c.VaultSkipVerify,
		AWSRegion:          strings.TrimSpace(c.AWSRegion),
		AWSAccessKey:       strings.TrimSpace(c.AWSAccessKey),
		AWSSecretKey:       open(c.AWSSecretKeyEnc),
		AWSSessionToken:    open(c.AWSSessionEnc),
		AWSEndpoint:        strings.TrimSpace(c.AWSEndpoint),
	}
}

// redacted strips everything secret, and reports which credentials are set so the UI
// can show "configured" without ever holding the value.
func (c extSecretConfig) redacted() map[string]any {
	return map[string]any{
		"vaultAddr":       c.VaultAddr,
		"vaultCaCertPem":  c.VaultCACertPEM,
		"vaultSkipVerify": c.VaultSkipVerify,
		"vaultTokenSet":   strings.TrimSpace(c.VaultTokenEnc) != "",
		"awsRegion":       c.AWSRegion,
		"awsAccessKey":    c.AWSAccessKey,
		"awsEndpoint":     c.AWSEndpoint,
		"awsSecretKeySet": strings.TrimSpace(c.AWSSecretKeyEnc) != "",
		"awsSessionSet":   strings.TrimSpace(c.AWSSessionEnc) != "",
	}
}

// InstallExtSecretOverlay wires the saved connection into config.ExtSecret(), so
// every consumer — the monitor, terminal, SFTP, playbooks, imaging — resolves
// credentials through it without knowing settings exist.
func InstallExtSecretOverlay(st *store.Store, cfg *config.Config) {
	config.SetExtSecretOverlay(func() extsecret.Config {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return loadExtSecretConfig(ctx, st).toExtSecret([]byte(cfg.CAKeyPassphrase))
	})
}

// extSecretGet returns the connection with every credential redacted.
func (h *handler) extSecretGet(w http.ResponseWriter, r *http.Request) {
	c := loadExtSecretConfig(r.Context(), h.d.Store)
	out := c.redacted()
	// What the environment supplies, so the screen can say a connection is already
	// configured there rather than looking empty and inviting a duplicate.
	env := h.d.Cfg.ExtSecret()
	out["providers"] = []string{extsecret.ProviderVaultKV, extsecret.ProviderOpenBao, extsecret.ProviderAWSSecrets}
	out["effectiveConfigured"] = env.Configured()
	httpx.WriteJSON(w, http.StatusOK, out)
}

// extSecretPut saves the connection, sealing any newly-supplied credential and
// preserving the stored one when the field is left blank.
func (h *handler) extSecretPut(w http.ResponseWriter, r *http.Request) {
	var in extSecretConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cur := loadExtSecretConfig(r.Context(), h.d.Store)
	pass := []byte(h.d.Cfg.CAKeyPassphrase)

	// A blank credential means "leave it alone", not "clear it" — the screen never
	// receives the current value, so it cannot send it back. Clearing is done by
	// clearing the address, which is visible and therefore deliberate.
	seal := func(plain, curEnc string) (string, error) {
		if strings.TrimSpace(plain) == "" {
			return curEnc, nil
		}
		return secretbox.Seal(pass, []byte(plain))
	}
	var err error
	if in.VaultTokenEnc, err = seal(in.VaultToken, cur.VaultTokenEnc); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not seal the token")
		return
	}
	if in.AWSSecretKeyEnc, err = seal(in.AWSSecretKey, cur.AWSSecretKeyEnc); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not seal the secret key")
		return
	}
	if in.AWSSessionEnc, err = seal(in.AWSSessionToken, cur.AWSSessionEnc); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not seal the session token")
		return
	}
	in.VaultToken, in.AWSSecretKey, in.AWSSessionToken = "", "", ""

	if err := h.d.Store.SetSetting(r.Context(), extSecretSettingKey, in); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if p := auth.MustPrincipal(r); p != nil {
		actor := p.UserID
		_, _ = h.d.Store.AppendAudit(r.Context(), models.AuditEvent{
			ActorID: &actor, ActorName: p.Username, Action: "system.extsecret_config", TargetKind: "system",
			// The address is recorded; no credential ever is.
			Detail: map[string]any{"vaultAddr": in.VaultAddr, "awsRegion": in.AWSRegion},
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// extSecretTest proves the connection actually works, against the configuration as it
// is RESOLVED — environment plus saved settings — rather than against whatever was
// just typed. A screen that reports success for a config the resolver would not
// assemble is worse than no test at all.
func (h *handler) extSecretTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
		Ref      string `json:"ref"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	provider := strings.TrimSpace(body.Provider)
	if provider == "" {
		provider = extsecret.ProviderVaultKV
	}
	if !extsecret.Supported(provider) {
		httpx.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unsupported provider %q", provider))
		return
	}
	p, err := extsecret.New(provider, h.d.Cfg.ExtSecret())
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	out := map[string]any{"ok": true, "provider": p.Name()}
	// An optional reference turns "the server answers" into "this deployment can
	// actually read a secret", which is the question an operator is really asking.
	if ref := strings.TrimSpace(body.Ref); ref != "" {
		if _, err := p.Fetch(ctx, ref); err != nil {
			out["ok"] = false
			out["error"] = err.Error()
		} else {
			out["fetched"] = ref
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
