package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kforbus3/provenance/backend/internal/app"
	"github.com/kforbus3/provenance/backend/internal/cryptoprofile"
	"github.com/kforbus3/provenance/backend/internal/identity"
	princ "github.com/kforbus3/provenance/backend/internal/principals"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// caLifecycle drives a CA rotation: a new key is trusted first, signs second, and the
// old one is retired last -- each step taken only when the one before it has been
// confirmed by the hosts that must honour it.
//
// Before this, Rotate CA made the new key the signer the moment it existed, pushed
// trust to the hosts once, and never retired anything. New logins then failed for up
// to five minutes (the jump host learns the CA by polling), a host that missed the one
// push lost the fleet's automation within a day, and a rotation for a suspected
// compromise left the compromised key trusted on every host for ever: nothing called
// RetireCAKey.
type caLifecycle struct{ s *Server }

func (l caLifecycle) want(ctx context.Context) (string, error) {
	keys, err := l.s.Store.ListActiveCAPublicKeys(ctx, "user")
	if err != nil {
		return "", err
	}
	return store.CATrustHash(keys), nil
}

// Status reports the rotation without changing anything.
func (l caLifecycle) Status(ctx context.Context) (*app.CARotationStatus, error) {
	if err := l.s.CA.Refresh(ctx); err != nil {
		return nil, err
	}
	want, err := l.want(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := l.s.Store.HostsCATrust(ctx, want)
	if err != nil {
		return nil, err
	}
	st := &app.CARotationStatus{SigningID: l.s.CA.ActiveID(), PendingID: l.s.CA.PendingID(), Hosts: hosts}
	for _, h := range hosts {
		if !h.InSync {
			st.OutOfSync++
		}
	}
	return st, nil
}

// jumpTrusts proves the jump host accepts the pending key by logging in with a
// certificate it signed. The jump host learns the CA by polling the backend, so "we
// published it" is not "it trusts it" -- and every connection to every host goes
// through it.
func (l caLifecycle) jumpTrusts(ctx context.Context) (bool, error) {
	priv, err := cryptoprofile.For(l.s.Cfg.FIPSMode).GenerateSigningKey()
	if err != nil {
		return false, err
	}
	keySigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return false, err
	}
	serial, err := l.s.Store.NextCertSerial(ctx)
	if err != nil {
		return false, err
	}
	cert, err := l.s.CA.SignWithPending(keySigner.PublicKey(),
		fmt.Sprintf("system/ca-rotation-check/%d", serial), []string{princ.Global}, serial, 2*time.Minute)
	if err != nil {
		return false, err
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		return false, err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client, err := l.s.Gateway.DialJumpWithSigner(cctx, certSigner)
	if err != nil {
		return false, nil // refused: it does not trust the key yet
	}
	_ = client.Close()
	return true, nil
}

// Advance pushes trust to every host that does not confirm the current key set, then
// promotes a pending key if the jump host and every host trust it. With force, the
// hosts that do not are named and left behind; the jump host is never skipped,
// because without it nothing is reachable at all.
func (l caLifecycle) Advance(ctx context.Context, force bool) (*app.CARotationStatus, error) {
	if err := l.s.CA.Refresh(ctx); err != nil {
		return nil, err
	}
	if _, _, err := l.s.pushCATrust(ctx, true); err != nil {
		return nil, err
	}
	st, err := l.Status(ctx)
	if err != nil {
		return nil, err
	}
	if st.PendingID == "" {
		return st, nil
	}
	jump, err := l.jumpTrusts(ctx)
	if err != nil {
		return nil, err
	}
	st.JumpTrustsPending = &jump
	if ok, why := promotionAllowed(jump, st.OutOfSync, force); !ok {
		st.Note = why
		return st, nil
	}
	if err := l.s.CA.Promote(ctx); err != nil {
		return nil, err
	}
	// New system certificates come from the new key from now on. The old key stays
	// trusted, so the cached ones would still work; dropping them now means nothing
	// depends on the old key by the time it is retired.
	identity.FlushSystemCache()
	st.Promoted = true
	st.SigningID, st.PendingID, st.JumpTrustsPending = l.s.CA.ActiveID(), "", nil
	if st.OutOfSync > 0 {
		st.Note = fmt.Sprintf("Promoted with %d host(s) not confirming the new key: they will refuse new "+
			"logins until they take it. Provenance keeps retrying them.", st.OutOfSync)
	} else {
		st.Note = "The new key is signing. Retire the previous key once you no longer need its certificates."
	}
	return st, nil
}

// Retire stops trusting a key that no longer signs. For a previous signing key it
// requires every host and the jump host to trust the current one first; a pending
// key can always be retired, which abandons the rotation.
func (l caLifecycle) Retire(ctx context.Context, id uuid.UUID) (*app.CARotationStatus, error) {
	if err := l.s.CA.Refresh(ctx); err != nil {
		return nil, err
	}
	if id.String() == l.s.CA.ActiveID() {
		return nil, fmt.Errorf("%w: this key is signing; rotate and promote a new one before retiring it", app.ErrCAKeyInUse)
	}
	if id.String() != l.s.CA.PendingID() {
		st, err := l.Status(ctx)
		if err != nil {
			return nil, err
		}
		if st.PendingID != "" {
			return nil, fmt.Errorf("%w: a rotation is still in progress; finish or abandon it first", app.ErrCAKeyInUse)
		}
		if st.OutOfSync > 0 {
			return nil, fmt.Errorf("%w: %d host(s) do not confirm the signing key yet; retiring the old one "+
				"would leave them trusting a key nothing signs with", app.ErrCAKeyInUse, st.OutOfSync)
		}
	}
	if err := l.s.Store.RetireCAKey(ctx, id); err != nil {
		return nil, fmt.Errorf("retire CA key: %w", err)
	}
	if err := l.s.CA.Refresh(ctx); err != nil {
		return nil, err
	}
	// Certificates the retired key signed stop working as the new trust file lands.
	// Cached system certificates may be among them; mint fresh ones.
	identity.FlushSystemCache()
	if _, _, err := l.s.pushCATrust(ctx, false); err != nil {
		return nil, err
	}
	st, err := l.Status(ctx)
	if err != nil {
		return nil, err
	}
	st.Note = "Retired. Hosts that confirmed the new trust file no longer accept certificates the key signed; " +
		"the jump host drops it within minutes. Anyone signed in before the rotation should sign in again."
	return st, nil
}

// caRotationLoop finishes rotations nobody is watching: it retries hosts that missed a
// trust push, and promotes a pending key once everything trusts it. It also catches a
// rotation started by provctl in another process.
func (s *Server) caRotationLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	l := caLifecycle{s: s}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !s.isLeader() {
			continue
		}
		st, err := l.Advance(ctx, false)
		s.Jobs.Record("ca-rotation", err)
		if err != nil {
			s.Log.Warn("CA rotation reconcile", "err", err)
			continue
		}
		if st.Promoted {
			s.Log.Info("CA rotation: new key promoted", "signing", st.SigningID)
		}
	}
}

// promotionAllowed is the gate a pending key must pass to start signing: the jump
// host must trust it -- always, because every connection goes through it -- and every
// enrolled SSH host must confirm it unless the operator forces past the ones that do
// not. Until then the previous key signs, so waiting never costs access.
func promotionAllowed(jumpTrusts bool, outOfSync int, force bool) (bool, string) {
	if !jumpTrusts {
		return false, "The new key is trusted by the hosts that have confirmed it but not yet by the jump host, " +
			"which fetches the CA every few minutes. The previous key keeps signing until it does."
	}
	if outOfSync > 0 && !force {
		return false, fmt.Sprintf("%d host(s) do not confirm the new key yet. The previous key keeps signing, "+
			"so nothing loses access; Provenance retries them and promotes the new key once they have it.", outOfSync)
	}
	return true, ""
}
