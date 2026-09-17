package k8sbroker

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/auth"
	"github.com/kforbus3/provenance/backend/internal/httpx"
	"github.com/kforbus3/provenance/backend/internal/models"
)

// consoleTokenTTL is a browser session, not a file on a laptop.
//
// Much shorter than kubeconfigTTL because this token never lands on disk under
// the operator's control: it goes into an HttpOnly cookie that Headlamp's
// backend sets, and the SPA can mint another one the moment that cookie lapses.
// Nothing is gained by making it long-lived and a stolen cookie is worth less
// for every hour taken off it.
const consoleTokenTTL = 12 * time.Hour

// consoleTokenName is how a console token identifies itself in the token list.
//
// Built from the shared marker prefix so that signing out -- which revokes by
// prefix, in a package that cannot import this one -- finds these and nothing
// else. In particular it must never match a kubeconfig token, which is the
// operator's to keep.
func consoleTokenName(username string) string { return models.ConsoleTokenNamePrefix + username }

// consoleToken mints the credential the embedded Headlamp console runs as.
//
// This exists so an operator does not have to paste a token into Headlamp's own
// auth screen. The SPA posts what this returns to Headlamp's
// /clusters/{name}/set-token, Headlamp stores it in an HttpOnly cookie, and the
// console is authenticated — in the iframe and in a new tab alike, because a
// cookie belongs to the origin rather than to the frame.
//
// It is deliberately a SEPARATE, PER-USER token rather than one shared console
// credential. Every call Headlamp makes is brokered through /api/v1/k8s and
// audited, and the actor on those records is whoever this token belongs to. A
// shared token would collapse the whole team into one actor, which would give up
// the only thing embedding a console buys over linking out to one.
//
// Who may hold one is therefore exactly who holds Kubernetes.Access — the route
// is gated on that permission, so Provenance's roles control console access with
// no second access-control system to keep in sync.
func (h *handler) consoleToken(w http.ResponseWriter, r *http.Request) {
	p := auth.MustPrincipal(r)
	if p == nil || p.UserID == uuid.Nil {
		httpx.WriteError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	// Same rule as the kubeconfig: a scoped token cannot mint another, or a
	// leaked one renews itself forever and its expiry means nothing.
	if p.TokenScope != "" {
		httpx.WriteError(w, http.StatusForbidden,
			"a scoped token cannot issue another one — sign in to open the console")
		return
	}

	// Supersede rather than accumulate. Without this, every console open that
	// found a lapsed cookie would leave another live credential behind, and an
	// operator's token list would fill with entries they never chose to create
	// and will never think to revoke.
	//
	// This is safe across tabs because the cookie is per-origin, not per-tab: a
	// second tab minting a token replaces the cookie both tabs send. Across
	// DEVICES it does cut the other one off, which is the intended trade — one
	// live console credential per operator, and the other device mints again.
	name := consoleTokenName(p.Username)
	superseded, err := h.d.Store.RevokeAPITokensByNamePrefix(r.Context(), p.UserID,
		models.ConsoleTokenNamePrefix)
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
		p.UserID, &expires, kubeconfigScope); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record the token")
		return
	}

	h.audit(r, "k8s.console.token", uuid.Nil, map[string]any{
		"scope": kubeconfigScope, "prefix": prefix,
		"expires": expires.Format(time.RFC3339), "superseded": superseded,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": expires.Format(time.RFC3339),
		// The SPA needs the console's base path to post the token to Headlamp,
		// and hardcoding it in two places is how the two drift apart.
		"consoleBase": strings.TrimSuffix(consoleBasePath, "/"),
	})
}

// consoleBasePath is where nginx serves the embedded Headlamp. It matches the
// -base-url Headlamp is started with and the location block in nginx.conf; all
// three have to agree or the console 404s.
const consoleBasePath = "/headlamp/"
