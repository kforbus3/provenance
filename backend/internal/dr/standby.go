package dr

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/httpx"
)

// standbyHandler serves the read-only DR standby console. It never writes to the
// database (a replica cannot) — the only mutation is pg_promote(), a promotion
// request. Auth is a static break-glass token, not a session, because a standby DB
// cannot create the session row a normal login writes.
type standbyHandler struct {
	d     *app.Deps
	token string
}

// mode reports that this instance is a standby, plus live replication lag, so the
// operator can confirm the replica is caught up before promoting. Unauthenticated
// (status only, no secrets, no writes).
func (h *standbyHandler) mode(w http.ResponseWriter, r *http.Request) {
	repl, err := h.d.Store.DBReplication(r.Context())
	// Promotion needs BOTH a break-glass token and a database role allowed to call
	// pg_promote(). Reporting only the token was a promise the console could not keep:
	// a multi-tenant deployment connects as a non-superuser by requirement, and
	// pg_promote is superuser-only unless EXECUTE is granted.
	canPromote := h.d.Store.CanPromoteDB(r.Context())
	resp := map[string]any{
		"standby":          true,
		"promotionEnabled": h.token != "" && canPromote,
	}
	if h.token != "" && !canPromote {
		resp["promotionBlocked"] = "this instance's database role may not call pg_promote(). " +
			"Grant it — GRANT EXECUTE ON FUNCTION pg_promote(boolean, integer) TO <role>; — " +
			"or promote with provctl / your database tooling instead."
	}
	if err == nil {
		resp["inRecovery"] = repl.InRecovery
		resp["replayLagSeconds"] = repl.ReplayLagSeconds
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// promoteAndRestart verifies the break-glass token, promotes this instance's
// PostgreSQL from standby to primary, and then triggers a graceful process restart.
// On restart the database is no longer in recovery, so the instance boots in full
// normal mode (migrations run, background writers start, normal login works).
func (h *standbyHandler) promoteAndRestart(w http.ResponseWriter, r *http.Request) {
	if h.token == "" {
		httpx.WriteError(w, http.StatusForbidden,
			"console promotion is disabled (set PROV_DR_STANDBY_TOKEN, or promote via provctl / your DB tooling)")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	presented := body.Token
	if presented == "" {
		presented = r.Header.Get("X-DR-Token")
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(h.token)) != 1 {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid DR token")
		return
	}

	ok, err := h.d.Store.PromoteDB(r.Context())
	if err != nil {
		msg := "pg_promote failed: " + err.Error()
		if !h.d.Store.CanPromoteDB(r.Context()) {
			// Say what to do about it. "permission denied for function pg_promote" during
			// a site failure is not the moment to go looking for the grant syntax.
			msg += " — this instance's database role may not call pg_promote(). Grant it " +
				"(GRANT EXECUTE ON FUNCTION pg_promote(boolean, integer) TO <role>;) or " +
				"promote with provctl / your database tooling."
		}
		httpx.WriteError(w, http.StatusBadGateway, msg)
		return
	}
	h.d.Log.Warn("DR standby: database promoted via console; restarting into normal mode")

	// Respond first, then restart, so the client sees success. The handler returns
	// (flushing the response) well before the delayed SIGTERM fires; the container's
	// restart policy brings the process back up against the now-primary database.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      ok,
		"message": "database promoted — this instance is restarting into normal mode; reload in a few seconds",
	})
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
}
