package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/fleet-terminal/backend/internal/release"
)

// applyConfigAdditions merges a manifest's additive config into the deployment's .env
// at path, generating secrets where requested. It is strictly additive: a key that is
// already present (even empty) is left untouched, so operator-set values and manually
// provisioned secrets are never overwritten. Returns the keys actually added.
//
// This runs BEFORE any container is recreated, so the recreated backend/frontend (and,
// last, the updater itself) come up already seeing the new variables.
func applyConfigAdditions(path string, additions []release.ConfigAddition) ([]string, error) {
	if len(additions) == 0 {
		return nil, nil
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read env file %s: %w", path, err)
	}
	merged, added, err := mergeConfigAdditions(string(cur), additions)
	if err != nil {
		return nil, err
	}
	if len(added) == 0 {
		return nil, nil // nothing missing; don't rewrite the file
	}
	// Preserve the file mode (it holds secrets — typically 0600).
	mode := os.FileMode(0o600)
	if fi, statErr := os.Stat(path); statErr == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(merged), mode); err != nil {
		return nil, fmt.Errorf("write env file %s: %w", path, err)
	}
	return added, nil
}

// mergeConfigAdditions appends any additions whose key is absent from envContent,
// returning the new content and the keys added. Pure (no I/O) so it is unit-testable;
// randomness for generated secrets is the only impurity.
func mergeConfigAdditions(envContent string, additions []release.ConfigAddition) (string, []string, error) {
	existing := map[string]bool{}
	for _, line := range strings.Split(envContent, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.IndexByte(t, '='); i > 0 {
			existing[strings.TrimSpace(t[:i])] = true
		}
	}
	var b strings.Builder
	b.WriteString(envContent)
	if len(envContent) > 0 && !strings.HasSuffix(envContent, "\n") {
		b.WriteByte('\n')
	}
	var added []string
	for _, a := range additions {
		if err := a.Validate(); err != nil {
			return "", nil, err
		}
		if existing[a.Key] {
			continue
		}
		val := a.Default
		if a.Generate == "secret" {
			s, err := randomHex(32)
			if err != nil {
				return "", nil, err
			}
			val = s
		}
		if a.Comment != "" {
			fmt.Fprintf(&b, "# %s\n", a.Comment)
		}
		fmt.Fprintf(&b, "%s=%s\n", a.Key, val)
		existing[a.Key] = true
		added = append(added, a.Key)
	}
	return b.String(), added, nil
}

// randomHex returns n cryptographically-random bytes as a hex string (2n chars).
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
