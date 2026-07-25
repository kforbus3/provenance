package release

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ChannelSchema is the current release-channel index schema version.
const ChannelSchema = 1

// ChannelIndex is the signed document a Fleet instance fetches from its configured
// release channel (FLEET_UPDATE_CHANNEL_URL) to discover available upgrades. It is
// signed by the same release key as the bundles; a downloaded bundle is still
// verified independently on apply, so the index signature only needs to authenticate
// the release LIST (which versions exist and where) — defeating downgrade/redirect.
type ChannelIndex struct {
	SchemaVersion int              `json:"schemaVersion"`
	Latest        string           `json:"latest"`
	Releases      []ChannelRelease `json:"releases"`
}

// ChannelRelease is one published release advertised by the channel.
type ChannelRelease struct {
	Version                string `json:"version"`
	MinFromVersion         string `json:"minFromVersion"`
	BundleURL              string `json:"bundleUrl"`
	BundleSize             int64  `json:"bundleSize,omitempty"`
	MigrationCompatibility string `json:"migrationCompatibility"`
	Notes                  string `json:"notes,omitempty"`
	PublishedAt            string `json:"publishedAt,omitempty"`
}

const maxChannelBytes = 1 << 20 // channel indexes are small

// FetchChannel downloads the channel index and its detached signature
// (channelURL + ".sig"), verifies the signature against the trusted release keys, and
// returns the parsed index. The index is authenticated before it is trusted.
func FetchChannel(ctx context.Context, client *http.Client, channelURL string, trusted []ed25519.PublicKey) (*ChannelIndex, error) {
	idx, err := httpGet(ctx, client, channelURL, maxChannelBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch channel index: %w", err)
	}
	sigRaw, err := httpGet(ctx, client, channelURL+".sig", 4096)
	if err != nil {
		return nil, fmt.Errorf("fetch channel signature: %w", err)
	}
	sig := decodeSig(sigRaw)
	if err := Verify(idx, sig, trusted); err != nil {
		return nil, fmt.Errorf("channel signature: %w", err)
	}
	var index ChannelIndex
	if err := json.Unmarshal(idx, &index); err != nil {
		return nil, fmt.Errorf("parse channel index: %w", err)
	}
	if index.SchemaVersion != ChannelSchema {
		return nil, fmt.Errorf("unsupported channel schema %d (want %d)", index.SchemaVersion, ChannelSchema)
	}
	return &index, nil
}

// PickUpdate returns the newest release in the index that is a valid upgrade for
// currentVersion (strictly newer, and currentVersion at or above its minFromVersion),
// or nil if the instance is already current. A dev/non-semver current build treats any
// listed release as newer.
func (idx *ChannelIndex) PickUpdate(currentVersion string) *ChannelRelease {
	cur, curOK := parseVersion(currentVersion)
	var best *ChannelRelease
	var bestV semver
	for i := range idx.Releases {
		r := &idx.Releases[i]
		rv, ok := parseVersion(r.Version)
		if !ok {
			continue
		}
		if curOK {
			if compare(rv, cur) <= 0 { // not newer than what we run
				continue
			}
			if minV, mok := parseVersion(r.MinFromVersion); mok && compare(cur, minV) < 0 {
				continue // can't jump directly from our version
			}
		}
		if best == nil || compare(rv, bestV) > 0 {
			best, bestV = r, rv
		}
	}
	return best
}

func httpGet(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// decodeSig accepts either a raw 64-byte Ed25519 signature or its base64 text form.
func decodeSig(raw []byte) []byte {
	if len(raw) == ed25519.SignatureSize {
		return raw
	}
	if b, err := decodeB64(strings.TrimSpace(string(raw))); err == nil {
		return b
	}
	return raw
}
