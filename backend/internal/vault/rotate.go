package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/secretbox"
)

// rotate rotates a password credential on the host that uses it: connect with the
// current password, set a new random one, verify, and store it as a new version.
// The vault is kept consistent with the host — if the host change fails, the stored
// value is reverted. On-demand only (a user's live session authenticates the jump
// hop); the operator never sees any password.
// setRotationPolicy configures (or clears, with intervalDays=0) automatic scheduled
// rotation for a password credential. The background rotation loop then rotates it on
// its host every intervalDays.
func (h *handler) setRotationPolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		IntervalDays int `json:"intervalDays"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.IntervalDays < 0 || body.IntervalDays > 3650 {
		httpx.WriteError(w, http.StatusBadRequest, "intervalDays must be between 0 and 3650")
		return
	}
	sec, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	if body.IntervalDays > 0 && sec.Type != "password" {
		httpx.WriteError(w, http.StatusBadRequest, "only password credentials can be rotated automatically")
		return
	}
	if err := h.d.Store.SetVaultRotationPolicy(r.Context(), id, body.IntervalDays); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not set the rotation policy")
		return
	}
	h.audit(r, "credential.rotation_policy", id, map[string]any{"intervalDays": body.IntervalDays})
	updated, _ := h.d.Store.GetVaultSecret(r.Context(), id)
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (h *handler) rotate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r, "id")
	if !ok {
		return
	}
	secret, err := h.d.Store.GetVaultSecret(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "credential not found")
		return
	}
	if secret.Type != "password" {
		httpx.WriteError(w, http.StatusBadRequest, "only password credentials can be rotated automatically")
		return
	}
	hosts, err := h.d.Store.HostsUsingCredential(r.Context(), id)
	if err != nil || len(hosts) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "attach this credential to a host before rotating it")
		return
	}
	host := &hosts[0]

	key, ok := h.vaultKey(w)
	if !ok {
		return
	}
	sealed, err := h.d.Store.GetVaultSecretSealed(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not load the credential")
		return
	}
	oldPw, err := secretbox.Open(key, sealed)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not decrypt the credential")
		return
	}
	newPw := randomPassword()
	loginUser := secret.Username
	if loginUser == "" {
		loginUser = host.SSHUser
	}
	p := auth.MustPrincipal(r)

	// Store the new value first (vault current = new), then change on the host with
	// the OLD password. If the host change fails, revert so the vault matches the host.
	sealedNew, err := secretbox.Seal(key, []byte(newPw))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not seal the new credential")
		return
	}
	if _, err := h.d.Store.AddVaultSecretVersion(r.Context(), id, sealedNew, p.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not store the new credential")
		return
	}

	verified, cerr := h.rotatePasswordOnHost(r.Context(), p.SessionID, host, loginUser, string(oldPw), newPw)
	if cerr != nil {
		// The host was not changed — put the old value back as the current version.
		if sealedOld, serr := secretbox.Seal(key, oldPw); serr == nil {
			_, _ = h.d.Store.AddVaultSecretVersion(r.Context(), id, sealedOld, p.UserID)
		}
		h.audit(r, "credential.rotate_failed", id, map[string]any{"host": host.Hostname, "error": cerr.Error()})
		httpx.WriteError(w, http.StatusBadGateway, "rotation failed on host (credential reverted): "+cerr.Error())
		return
	}

	h.audit(r, "credential.rotate", id, map[string]any{"host": host.Hostname, "verified": verified})
	resp := map[string]any{"rotated": true, "host": host.Hostname, "verified": verified}
	if !verified {
		resp["warning"] = "the password was changed on the host but could not be verified; the host and vault both hold the new value"
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// rotatePasswordOnHost connects with the old password, sets the new one via
// chpasswd, and verifies with the new password. Returns (verified, err): a non-nil
// err means the host was NOT changed (caller should revert the stored value); err
// nil with verified=false means the change succeeded but re-login couldn't confirm.
func (h *handler) rotatePasswordOnHost(ctx context.Context, sessionID uuid.UUID, host *models.Host, user, oldPw, newPw string) (bool, error) {
	var lastErr error
	for _, addr := range dedupeAddrs(host.WGAddress, host.Address, host.Hostname) {
		conn, derr := h.gw.DialAuthViaJump(ctx, sessionID.String(), addr, host.SSHPort, user, ssh.Password(oldPw))
		if derr != nil {
			lastErr = derr
			continue
		}
		sess, serr := conn.Client.NewSession()
		if serr != nil {
			conn.Close()
			lastErr = serr
			continue
		}
		// Feed "user:newpassword" on stdin so the secret never appears in argv/ps.
		sess.Stdin = strings.NewReader(user + ":" + newPw + "\n")
		out, cerr := sess.CombinedOutput("sudo chpasswd")
		_ = sess.Close()
		conn.Close()
		if cerr != nil {
			return false, fmt.Errorf("chpasswd: %v: %s", cerr, strings.TrimSpace(string(out)))
		}
		// Verify by re-authenticating with the new password.
		if vconn, verr := h.gw.DialAuthViaJump(ctx, sessionID.String(), addr, host.SSHPort, user, ssh.Password(newPw)); verr == nil {
			vconn.Close()
			return true, nil
		}
		return false, nil // changed, but could not verify
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable address for host")
	}
	return false, lastErr
}

// randomPassword returns a strong password with only URL-safe base64 characters,
// so it is safe to pass on chpasswd's stdin (no ':' or newline).
func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func dedupeAddrs(in ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
