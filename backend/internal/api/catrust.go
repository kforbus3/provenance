package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// distributeCATrust writes the current user-CA public keys to every enrolled host.
//
// Rotating the CA is half an operation. A host learns the CA through
// TrustedUserCAKeys, written once at enrollment, so after a rotation every host still
// trusts only the key on its way out — and because already-issued certificates keep
// working until they expire, nothing looks wrong until they do, fleet-wide and at once.
// The documented remedy was "re-enroll every host", which is a lot of machine for a file
// copy, and easy to leave undone.
//
// Observed on a QA host: after `provctl rotate-ca`, enrollment failed with
// "no supported methods remain" until the new key was put in /etc/ssh/prov_ca.pub by
// hand, and then succeeded immediately.
//
// ALL active keys are written, not only the newest. During a rotation both are active:
// certificates issued before it are still valid, and a host that trusted only the new
// key would reject them. The old key stops being written when it is retired.
func (s *Server) distributeCATrust(ctx context.Context) (int, int, error) {
	caKeys, err := s.Store.ListActiveCAPublicKeys(ctx, "user")
	if err != nil {
		return 0, 0, fmt.Errorf("read the active CA keys: %w", err)
	}
	// Refuse to write nothing. A host whose TrustedUserCAKeys is empty trusts no
	// certificate at all and cannot be logged into — by anyone, including whoever
	// would fix it. That has happened here before, from a cleanup that removed the
	// last line of the file, and it is not a state to reach by accident.
	var keys []string
	for _, k := range caKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return 0, 0, fmt.Errorf("refusing to distribute an empty CA trust file: no active " +
			"user CA keys. Every host that received it would accept no certificate at all")
	}
	payload := strings.Join(keys, "\n") + "\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))

	// Written aside and moved into place: sshd reads this file on every
	// authentication, so a half-written one is a window in which nobody can log in.
	// Then VERIFIED by reading it back — the point of the exercise is that the host
	// trusts the current key, and "tee did not error" is not that.
	fingerprint := keys[len(keys)-1]
	if f := strings.Fields(fingerprint); len(f) >= 2 {
		fingerprint = f[1]
	}
	cmd := "set -e; " +
		"echo " + b64 + " | base64 -d | sudo tee /etc/ssh/prov_ca.pub.new >/dev/null; " +
		"sudo chmod 644 /etc/ssh/prov_ca.pub.new; " +
		"sudo mv /etc/ssh/prov_ca.pub.new /etc/ssh/prov_ca.pub; " +
		"grep -q '" + fingerprint + "' /etc/ssh/prov_ca.pub && echo OK"

	hosts, _ := s.Store.AllHosts(ctx)
	const concurrency = 8
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var pushed, failed int64
	miss := func(h models.Host, reason string, err error, out string) {
		atomic.AddInt64(&failed, 1)
		s.Log.Warn("CA trust push failed; this host does not trust the current CA and will "+
			"reject certificates issued by it",
			"host", h.Hostname, "hostID", h.ID, "reason", reason, "err", err, "output", out)
	}
	for i := range hosts {
		h := hosts[i]
		if !h.Enrolled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			signer, err := s.Issuer.SystemSigner(ctx, s.Issuer.SystemHostPrincipals(h.ID), 24*time.Hour)
			if err != nil {
				miss(h, "issue credential", err, "")
				return
			}
			var lastErr error
			for _, addr := range dedupe([]string{h.WGAddress, h.Address, h.Hostname}) {
				conn, derr := s.Gateway.DialWithSigner(ctx, signer, addr, h.SSHPort, h.SSHUser)
				if derr != nil {
					lastErr = derr
					continue
				}
				sess, e := conn.Client.NewSession()
				if e != nil {
					conn.Close()
					miss(h, "open session", e, "")
					return
				}
				out, rerr := sess.CombinedOutput(cmd)
				sess.Close()
				conn.Close()
				if rerr == nil && strings.Contains(string(out), "OK") {
					atomic.AddInt64(&pushed, 1)
				} else {
					miss(h, "install CA trust", rerr, strings.TrimSpace(string(out)))
				}
				return
			}
			miss(h, "unreachable", lastErr, "")
		}()
	}
	wg.Wait()
	if failed > 0 {
		// Error, not Info: every host in this count will reject certificates signed by
		// the current CA once the ones it already holds expire.
		s.Log.Error("CA trust distribution incomplete", "pushed", pushed, "failed", failed,
			"activeKeys", len(keys))
	} else {
		s.Log.Info("distributed CA trust", "hosts", pushed, "activeKeys", len(keys))
	}
	return int(pushed), int(failed), nil
}
