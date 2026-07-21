package system

import (
	"net/http"
	"strings"

	"github.com/fleet-terminal/backend/internal/cryptoprofile"
	"github.com/fleet-terminal/backend/internal/httpx"
)

// fipsReadiness is the web-UI view of `fleetctl fips check`: whether each
// FIPS-critical artifact is on an approved algorithm, plus an overall verdict.
type fipsReadiness struct {
	ModuleActive bool           `json:"moduleActive"` // Go FIPS 140-3 module active in this process
	ConfigFIPS   bool           `json:"configFips"`   // FLEET_FIPS_MODE
	Overlay      string         `json:"overlay"`      // wireguard | openvpn
	OverlayOK    bool           `json:"overlayOk"`    // overlay is a FIPS transport (not WireGuard)
	CAKeyAlgo    string         `json:"caKeyAlgo"`    // active user CA key algorithm
	CAKeyOK      bool           `json:"caKeyOk"`      // CA key is FIPS-approved (not Ed25519)
	Passwords    []fipsAlgCount `json:"passwords"`    // password-hash algorithms in use
	TOTP         int            `json:"totp"`         // confirmed TOTP factors
	WebAuthn     int            `json:"webauthn"`     // confirmed WebAuthn factors (may be pre-FIPS EdDSA)
	Ready        bool           `json:"ready"`        // core artifacts all FIPS-approved
}

type fipsAlgCount struct {
	Algorithm string `json:"algorithm"`
	Count     int    `json:"count"`
	FIPS      bool   `json:"fips"`
}

// fips returns the FIPS readiness report — the same data as `fleetctl fips check`,
// for the Settings → FIPS dashboard. Read-only; admin-gated.
func (h *handler) fips(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := fipsReadiness{
		ModuleActive: cryptoprofile.ModuleActive(),
		ConfigFIPS:   h.d.Cfg.FIPSMode,
		Overlay:      h.d.Cfg.Overlay,
		OverlayOK:    h.d.Cfg.Overlay != "wireguard",
		Passwords:    []fipsAlgCount{},
	}
	pool := h.d.Store.Pool()

	_ = pool.QueryRow(ctx,
		`SELECT algo FROM ca_keys WHERE kind='user' AND active=true ORDER BY created_at DESC LIMIT 1`).
		Scan(&out.CAKeyAlgo)
	out.CAKeyOK = out.CAKeyAlgo != "" && !strings.Contains(out.CAKeyAlgo, "ed25519")

	if rows, err := pool.Query(ctx,
		`SELECT split_part(password_hash,'$',2), count(*) FROM user_credentials GROUP BY 1 ORDER BY 1`); err == nil {
		for rows.Next() {
			var a string
			var n int
			if rows.Scan(&a, &n) == nil {
				out.Passwords = append(out.Passwords, fipsAlgCount{Algorithm: a, Count: n, FIPS: a == "pbkdf2-sha256"})
			}
		}
		rows.Close()
	}
	_ = pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE kind='totp' AND confirmed),
		count(*) FILTER (WHERE kind='webauthn' AND confirmed) FROM mfa_methods`).Scan(&out.TOTP, &out.WebAuthn)

	out.Ready = out.ModuleActive && out.CAKeyOK && out.OverlayOK
	httpx.WriteJSON(w, http.StatusOK, out)
}
