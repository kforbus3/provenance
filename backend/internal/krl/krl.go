// Package krl builds OpenSSH Key Revocation Lists (binary KRL) from the active
// CA public keys and a set of revoked certificate serials. Hosts configured with
// `RevokedKeys` reject any presented certificate whose serial is in the KRL.
package krl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Build produces a binary KRL revoking the given serials relative to the
// provided CA public keys (authorized_keys lines). An empty serial list yields a
// valid empty KRL (revokes nothing) — safe to install.
func Build(caAuthorizedKeys []string, serials []uint64) ([]byte, error) {
	if len(caAuthorizedKeys) == 0 {
		return nil, fmt.Errorf("no CA public keys")
	}
	dir, err := os.MkdirTemp("", "prov-krl")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	caPath := filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(caPath, []byte(strings.Join(caAuthorizedKeys, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}
	var spec strings.Builder
	for _, s := range serials {
		fmt.Fprintf(&spec, "serial: %d\n", s)
	}
	specPath := filepath.Join(dir, "spec")
	if err := os.WriteFile(specPath, []byte(spec.String()), 0o600); err != nil {
		return nil, err
	}
	outPath := filepath.Join(dir, "krl")
	cmd := exec.Command("ssh-keygen", "-k", "-f", outPath, "-s", caPath, specPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen -k: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return os.ReadFile(outPath)
}

// Available reports whether ssh-keygen is present (KRL generation requires it).
func Available() bool {
	_, err := exec.LookPath("ssh-keygen")
	return err == nil
}
