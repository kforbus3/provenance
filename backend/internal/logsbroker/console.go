package logsbroker

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// consoleBasePath is where nginx serves the embedded Dashboards. It matches the
// location block in nginx.conf, the cookie's Path below, and the collector's own
// ALDGATE_BASEPATH; all four have to agree or the console 404s.
const consoleBasePath = "/aldgate"

// consoleLanding is where "Open log console" actually goes: the dashboard Aldgate
// ships with, over the last 24 hours, rather than Dashboards' home screen.
//
// A console that opens on a home screen asking you to choose an index pattern is a
// tool you have to assemble before it answers anything. This lands on log volume,
// severity mix, the noisiest hosts and what is failing -- and the saved searches
// are one click from there.
const consoleLanding = consoleBasePath + "/app/dashboards#/view/aldgate-overview"

// consoleScope limits a console token to the logs routes and nothing else, so a
// stolen console cookie cannot reach the rest of the API as its owner.
const consoleScope = "/api/v1/logs"

// consoleCookie carries the console token. HttpOnly, and scoped to the console's
// own path: no script reads it, and it is not sent to any other part of the API.
const consoleCookie = "prov_logs_console"

// consoleTokenTTL is a working session at the console, not a credential to keep.
const consoleTokenTTL = 12 * time.Hour

// consoleTokenName identifies these in the token list, and is built from the
// shared marker prefix so signing out revokes them by prefix.
func consoleTokenName(username string) string {
	return models.LogConsoleTokenNamePrefix + username
}

// consoleToken opens the log console for the caller.
//
// Before this, /aldgate/ was a bare proxy to Dashboards: it presented its own
// username-and-password form, a Provenance role had nothing to do with what you
// could do once past it, and the only credential that worked was the collector's
// admin account — which is every privilege there is. Whoever opened the console
// was whoever knew that password, and the collector had no idea who they were.
//
// Now Provenance decides. This mints a short-lived, per-user token scoped to the
// logs routes and returns it in an HttpOnly cookie on the console's own path.
// Every request the browser then makes to /aldgate/ carries that cookie, nginx
// checks it through consoleAuthz below, and consoleAuthz hands nginx the
// collector credential for the TIER the person's permissions earn — so the
// browser is never sent a collector password at all, and the person never sees
// one.
func (h *handler) consoleToken(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	if p == nil || p.UserID == uuid.Nil {
		httpx.WriteError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	// Same rule as the Kubernetes console: a scoped token must not mint another,
	// or a leaked one renews itself forever and its expiry means nothing.
	if p.TokenScope != "" {
		httpx.WriteError(w, http.StatusForbidden,
			"a scoped token cannot issue another one — sign in to open the console")
		return
	}
	if h.c == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable,
			"no log collector is configured — set PROV_ALDGATE_URL")
		return
	}
	tier, _ := h.tierFor(p)
	if tier == "" {
		// Nothing to hand nginx, so opening the console would only land the person
		// on Dashboards' own login form with no credential that works. Say why
		// instead of letting that happen.
		httpx.WriteError(w, http.StatusServiceUnavailable,
			"the console's credentials are not configured — run `make bootstrap` on the "+
				"collector and set PROV_ALDGATE_CONSOLE_VIEWER_PASSWORD / "+
				"PROV_ALDGATE_CONSOLE_ADMIN_PASSWORD from its .env")
		return
	}

	// Supersede rather than accumulate: without this, every console open that
	// found a lapsed cookie would leave another live credential behind and fill
	// the operator's token list with entries they never chose to create.
	name := consoleTokenName(p.Username)
	superseded, err := h.d.Store.RevokeAPITokensByNamePrefix(r.Context(), p.UserID, name)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not retire the previous console token")
		return
	}
	token, hash, prefix, err := auth.NewAPIToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not mint a token")
		return
	}
	expires := time.Now().Add(consoleTokenTTL)
	if _, err := h.d.Store.CreateScopedAPIToken(r.Context(), p.UserID, name, hash, prefix,
		p.UserID, &expires, consoleScope); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record the token")
		return
	}

	//nolint:gosec // Secure follows cfg.CookieSecure, as every other auth cookie here does.
	http.SetCookie(w, &http.Cookie{
		Name: consoleCookie, Value: token, Path: consoleBasePath,
		HttpOnly: true, Secure: h.d.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
		Expires: expires,
	})
	h.audit(r, "logs.console.open", map[string]any{
		"tier": tier, "prefix": prefix,
		"expires": expires.Format(time.RFC3339), "superseded": superseded,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"consoleBase": consoleBasePath,
		// Where to actually open. Sent by the server rather than built in the SPA
		// so the dashboard id lives in one place -- it is Aldgate's, and the two
		// would drift the first time it changed.
		"consoleURL": consoleLanding,
		"tier":       tier,
		"expiresAt":  expires.Format(time.RFC3339),
	})
}

// consoleAuthz is nginx's auth_request target for /aldgate/. It answers two
// questions at once: may this request reach the console at all, and as WHOM
// should the collector see it.
//
// The tier is decided HERE, per request, rather than baked into the token when it
// was minted. A token lives twelve hours; a role change must not. Someone moved
// from Administrator to Operator drops to the read-only tier on their very next
// request, without anyone having to find and revoke a cookie.
//
// The credential goes back in a response header, which nginx copies into the
// proxied request and never sends to the browser. That is the whole point: the
// person gets a console they did not have to log into, and still never holds a
// credential for the collector.
func (h *handler) consoleAuthz(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	if p == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	h.writeConsoleAuthz(w, p)
}

// writeConsoleAuthz is the answer itself, split from the request so it can be
// tested against a principal directly: attaching one to a context is deliberately
// not possible from outside the auth package.
func (h *handler) writeConsoleAuthz(w http.ResponseWriter, p *auth.Principal) {
	tier, basic := h.tierFor(p)
	if tier == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "the console's credentials are not configured")
		return
	}
	// The credential goes in a HEADER and never in the body: nginx copies the
	// header into the proxied request, and a body is on its way to the browser.
	w.Header().Set("X-Aldgate-Authorization", basic)
	// Named so an operator reading nginx's log can tell which tier answered.
	w.Header().Set("X-Aldgate-Tier", tier)
	w.WriteHeader(http.StatusNoContent)
}

// tierFor maps Provenance permissions onto a collector account.
//
// Two tiers, and the mapping is the whole feature: Logs.Administer opens the
// console that can delete an index or rewrite a retention policy, Logs.View opens
// the one that can only read. Anyone reaching either of these handlers already
// holds Logs.View -- the routes are gated on it -- so the fallback is the reader,
// never "no access".
//
// Returns ("", "") when the matching credential is not configured, which is a
// deployment that has not run the collector's bootstrap. Falling back to the
// admin account there would hand every reader the keys, so it fails instead.
func (h *handler) tierFor(p *auth.Principal) (tier, basic string) {
	cfg := h.d.Cfg
	if p.Has(permLogsAdminister) && cfg.AldgateConsoleAdminPassword != "" {
		return "administer", basicAuth(cfg.AldgateConsoleAdminUser, cfg.AldgateConsoleAdminPassword)
	}
	if cfg.AldgateConsoleViewerPassword != "" {
		return "view", basicAuth(cfg.AldgateConsoleViewerUser, cfg.AldgateConsoleViewerPassword)
	}
	// An administrator on a deployment where only the admin credential is set
	// still gets in; a reader does not get promoted into it.
	if p.Has(permLogsAdminister) && cfg.AldgateConsoleAdminPassword != "" {
		return "administer", basicAuth(cfg.AldgateConsoleAdminUser, cfg.AldgateConsoleAdminPassword)
	}
	return "", ""
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// cookieAsBearer lets the console's cookie authenticate the request.
//
// The console is a page the browser loads, not a call the SPA makes, so it
// carries cookies and no Authorization header — and Provenance's session cookies
// are scoped to /api/v1/auth, so they never arrive here either. Rather than teach
// the authenticator about a second credential form, the cookie is presented as
// the bearer token it already is. Everything downstream is then unchanged: the
// api_tokens lookup, the scope check that keeps this token inside /api/v1/logs,
// and the permission middleware.
//
// An existing Authorization header always wins, so this can never downgrade a
// properly authenticated call.
func cookieAsBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie(consoleCookie); err == nil && c.Value != "" {
				r.Header.Set("Authorization", "Bearer "+c.Value)
			}
		}
		next.ServeHTTP(w, r)
	})
}
